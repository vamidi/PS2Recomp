#include "iop.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <tuple>

namespace ps2x::iop::lle
{
    namespace
    {
        constexpr uint32_t kTrapBase = 0x1000u;       // return traps, one word each
        constexpr uint32_t kCtypeBase = 0x1100u;      // sysclib's character class table
        constexpr uint32_t kInterruptStack = 0x8000u; // top of the interrupt context stack
        constexpr uint32_t kHeapBase = 0x10000u;
        constexpr uint32_t kSpuDmaLines[2] = {36u, 40u}; // INUM_DMA_4, INUM_DMA_7
        constexpr uint32_t kSpuLine = 9u;

        uint32_t syscallWord(uint32_t code) { return 0x0000000Cu | (code << 6); }

        // Debug-only load tracing (TOL_TRACE_IOP_READS): what the currently running thread reads, sampled.
        // A thread that never blocks but keeps the CPU busy is either polling a hardware register or a RAM
        // flag; the sampled address (and the pc that reads it) says which.
        struct ReadTrace
        {
            const CpuContext *context = nullptr;
            int thread = -1;
            uint64_t reads = 0u;
        };
        ReadTrace gReadTrace;
        // The return traps live in the low page, which a module loaded at base 0 clears with its .bss. Keep the
        // words cached so they can be rewritten before anything runs (measured: the RPC trap read 0x00000000).
        uint32_t gReturnTrapWord = 0u;
        uint32_t gRpcTrapWord = 0u;

        // Starvation guard state (see pickThread): the thread currently monopolising the interpreter, and how
        // long it has run without blocking.
        int gHogThread = -1;
        int gLastPick = -1;
        uint32_t gPickStreak = 0u;

        void traceRead(void *context, uint32_t address, unsigned bytes, uint32_t value)
        {
            auto &trace = *static_cast<ReadTrace *>(context);
            const uint64_t count = ++trace.reads;
            static const int sWanted = [] {
                const char *text = std::getenv("TOL_TRACE_IOP_READS");
                const int value = (text != nullptr) ? std::atoi(text) : 25;
                return value > 0 ? value : 25;
            }();
            if (trace.thread != sWanted)
                return;
            if ((count % 64u) != 0u)
                return;
            static uint32_t sLines = 0u;
            if (sLines >= 120u)
                return;
            ++sLines;
            std::fprintf(stderr, "[read] tid=%d pc=0x%08X addr=0x%08X phys=0x%08X %ub -> 0x%X (reads=%llu)\n",
                         trace.thread, trace.context != nullptr ? trace.context->pc : 0u, address,
                         address & 0x1FFFFFFFu, bytes, value, static_cast<unsigned long long>(count));
        }

        // Counterpart for stores: who updates the mixer's block descriptors (0xF34xx) and source pointers
        // (0x43xxx)? If nothing writes them, the producer that should is missing.
        void traceWrite(void *context, uint32_t address, unsigned bytes, uint32_t value)
        {
            (void)context;
            const uint32_t physical = address & 0x1FFFFFFFu;
            const bool wanted = (physical >= 0x000F3400u && physical < 0x000F3700u) ||
                                (physical >= 0x00043000u && physical < 0x00043400u);
            if (!wanted)
                return;
            static uint32_t sLines = 0u;
            if (++sLines > 120u)
                return;
            std::fprintf(stderr, "[write] tid=%d pc=0x%08X addr=0x%08X %ub = 0x%X\n", gReadTrace.thread,
                         gReadTrace.context != nullptr ? gReadTrace.context->pc : 0u, address, bytes, value);
        }
    }

    Iop::Iop(EeLink &ee) : m_ee(ee), m_bus(*this), m_cpu(m_bus), m_spu2(*this)
    {
        installKernel();
        if (std::getenv("TOL_TRACE_IOP_READS") != nullptr)
        {
            m_bus.readHook = &traceRead;
            m_bus.readHookContext = &gReadTrace;
        }
        if (std::getenv("TOL_TRACE_IOP_WRITES") != nullptr)
        {
            m_bus.writeHook = &traceWrite;
            m_bus.writeHookContext = &gReadTrace;
        }
        uint8_t *ram = m_bus.ram();
        // Threads and handlers return here; the trap tells the kernel they are done.
        m_returnTrap = kTrapBase;
        const uint32_t returnWord = syscallWord(handlerFor("", 1));
        std::memcpy(ram + kTrapBase, &returnWord, 4);        gReturnTrapWord = returnWord;
        m_rpcTrap = kTrapBase + 8u;
        const uint32_t rpcWord = syscallWord(handlerFor("", 2));
        std::memcpy(ram + m_rpcTrap, &rpcWord, 4);        gRpcTrapWord = rpcWord;
        // The ctype table sysclib hands out: bit 2 digit, 1 lower, 0 upper, 3 space, 6 hex.
        m_ctypeTable = kCtypeBase;
        for (uint32_t ch = 0; ch < 256u; ++ch)
        {
            uint8_t flags = 0;
            if (ch >= '0' && ch <= '9') flags |= 0x04u;
            if (ch >= 'a' && ch <= 'z') flags |= 0x02u;
            if (ch >= 'A' && ch <= 'Z') flags |= 0x01u;
            if (ch == ' ' || (ch >= 9u && ch <= 13u)) flags |= 0x08u;
            if ((ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) flags |= 0x40u;
            ram[kCtypeBase + 1u + ch] = flags;
        }
        m_allocations[0] = kHeapBase; // everything below the heap is the kernel's
    }

    Iop::~Iop() = default;

    std::string Iop::readString(uint32_t address, size_t limit)
    {
        std::string text;
        for (size_t index = 0; index < limit; ++index)
        {
            const uint8_t ch = m_bus.read8(address + static_cast<uint32_t>(index));
            if (ch == 0u)
                break;
            text.push_back(static_cast<char>(ch));
        }
        return text;
    }

    uint32_t Iop::arg(CpuContext &c, unsigned index)
    {
        return index < 4u ? c.gpr[4 + index] : m_bus.read32(c.gpr[29] + 16u + (index - 4u) * 4u);
    }

    uint32_t Iop::allocate(uint32_t size)
    {
        size = (size + 255u) & ~255u;
        uint32_t cursor = kHeapBase;
        for (const auto &[address, length] : m_allocations)
        {
            if (address >= cursor && address - cursor >= size)
                break;
            cursor = std::max(cursor, (address + length + 255u) & ~255u);
        }
        if (cursor + size > Bus::kRamBytes)
            return 0;
        m_allocations[cursor] = size;
        return cursor;
    }

    void Iop::release(uint32_t address)
    {
        if (address >= kHeapBase)
            m_allocations.erase(address);
    }

    void Iop::writeMemory(uint32_t address, const void *data, uint32_t size)
    {
        address &= Bus::kRamBytes - 1u;
        size = std::min(size, Bus::kRamBytes - address);
        std::memcpy(m_bus.ram() + address, data, size);
    }

    void Iop::readMemory(uint32_t address, void *data, uint32_t size)
    {
        address &= Bus::kRamBytes - 1u;
        size = std::min(size, Bus::kRamBytes - address);
        std::memcpy(data, m_bus.ram() + address, size);
    }

    // ------------------------------------------------------------------ hardware

    uint32_t Iop::ioRead(uint32_t physical, unsigned bytes)
    {
        if (physical >= 0x1F900000u && physical < 0x1F900800u)
        {
            uint32_t value = m_spu2.read(physical & 0x7FFu);
            if (bytes == 4u)
                value |= static_cast<uint32_t>(m_spu2.read((physical + 2u) & 0x7FFu)) << 16;
            return value;
        }
        int channel = 0;
        if (uint32_t *reg = dmaRegister(physical, channel))
            return *reg >> ((physical & 3u) * 8u);
        return 0;
    }

    uint32_t *Iop::dmaRegister(uint32_t physical, int &channel)
    {
        for (channel = 0; channel < 2; ++channel)
        {
            const uint32_t base = channel == 0 ? 0x1F8010C0u : 0x1F801500u;
            if (physical >= base && physical < base + 12u)
            {
                DmaChannel &dma = m_dma[channel];
                const uint32_t offset = physical - base;
                return offset < 4u ? &dma.madr : offset < 8u ? &dma.bcr : &dma.chcr;
            }
        }
        return nullptr;
    }

    void Iop::ioWrite(uint32_t physical, uint32_t value, unsigned bytes)
    {
        if (physical >= 0x1F900000u && physical < 0x1F900800u)
        {
            const uint32_t offset = physical & 0x7FFu;
            if (std::getenv("TOL_TRACE_SPU2") != nullptr)
            {
                // 0x1A8/0x1AA TSA (transfer address), 0x1AC DATA, 0x1B0 ADMAS (AutoDMA mode).
                if (offset == 0x1A8u || offset == 0x1AAu || offset == 0x1B0u || offset == 0x1B2u)
                {
                    std::fprintf(stderr, "[spu2] write off=0x%03X val=0x%04X (pc=0x%08X)\n", offset,
                                 value & 0xFFFFu, current() != nullptr ? current()->context.pc : 0u);
                }
                else if (offset == 0x1ACu)
                {
                    static uint32_t sData = 0u;
                    if ((++sData % 512u) == 0u)
                        std::fprintf(stderr, "[spu2] data write x%u val=0x%04X\n", sData, value & 0xFFFFu);
                }
            }
            m_spu2.write(offset, static_cast<uint16_t>(value));
            if (bytes == 4u)
                m_spu2.write((physical + 2u) & 0x7FFu, static_cast<uint16_t>(value >> 16));
            return;
        }
        // libsd writes the block count and size as separate halfwords.
        int channel = 0;
        if (uint32_t *reg = dmaRegister(physical, channel))
        {
            const uint32_t shift = (physical & 3u) * 8u;
            const uint32_t mask = (bytes >= 4u ? 0xFFFFFFFFu : (1u << (bytes * 8u)) - 1u) << shift;
            *reg = (*reg & ~mask) | ((value << shift) & mask);
            DmaChannel &dma = m_dma[channel];
            dma.madr &= 0x00FFFFFFu;
            if (reg == &dma.chcr && (mask & value << shift & 0x01000000u) != 0u)
                dmaTransfer(channel);
        }
    }

    void Iop::dmaTransfer(int channel)
    {
        DmaChannel &dma = m_dma[channel];
        const uint32_t blockWords = dma.bcr & 0xFFFFu;
        const uint32_t blocks = std::max<uint32_t>(dma.bcr >> 16, 1u);
        const uint32_t bytes = blockWords * blocks * 4u;
        m_spu2.dmaStarted(channel);
        if ((dma.chcr & 1u) != 0u && m_spu2.autoDmaEnabled(channel))
        {
            // AutoDMA: the SPU2 pulls 1 KiB at a time as it plays.
            dma.remaining = bytes;
            return;
        }
        const uint32_t address = dma.madr & (Bus::kRamBytes - 1u);
        const uint32_t length = std::min(bytes, Bus::kRamBytes - address);
        auto *words = reinterpret_cast<uint16_t *>(m_bus.ram() + address);
        if ((dma.chcr & 1u) != 0u)
            m_spu2.dmaWrite(channel, words, length / 2u);
        else
            m_spu2.dmaRead(channel, words, length / 2u);
        dma.madr = (dma.madr + length) & 0x00FFFFFFu;
        dma.chcr &= ~0x01000000u;
        raiseInterrupt(kSpuDmaLines[channel]);
    }

    bool Iop::fetchAutoDma(int core, uint16_t *block)
    {
        DmaChannel &dma = m_dma[core];
        if ((dma.chcr & 0x01000000u) == 0u || dma.remaining < 1024u)
            return false;
        readMemory(dma.madr, block, 1024u);
        dma.madr = (dma.madr + 1024u) & 0x00FFFFFFu;
        dma.remaining -= 1024u;
        if (dma.remaining < 1024u)
        {
            dma.chcr &= ~0x01000000u;
            raiseInterrupt(kSpuDmaLines[core]);
        }
        return true;
    }

    void Iop::raiseSpuInterrupt() { raiseInterrupt(kSpuLine); }

    void Iop::raiseInterrupt(uint32_t line)
    {
        if (std::find(m_pendingInterrupts.begin(), m_pendingInterrupts.end(), line) == m_pendingInterrupts.end())
            m_pendingInterrupts.push_back(line);
    }

    // ------------------------------------------------------------------ execution

    void Iop::call(uint32_t function, std::initializer_list<uint32_t> arguments, uint32_t *result, uint32_t gp)
    {
        CpuContext context{};
        context.pc = function;
        unsigned index = 4;
        for (const uint32_t value : arguments)
            context.gpr[index++] = value;
        context.gpr[28] = gp;
        context.gpr[29] = kInterruptStack - 16u;
        context.gpr[31] = m_returnTrap;
        const bool nested = m_inInterrupt;
        m_inInterrupt = true;
        // Handlers run between samples, off the clock like RPC work.
        uint64_t spent = 0;
        const uint64_t limit = 4'000'000u;
        for (;;)
        {
            const StopReason reason = m_cpu.run(context, spent, limit);
            if (reason != StopReason::Syscall)
            {
                m_ee.log("[iop] handler at " + std::to_string(function) + " did not return");
                break;
            }
            const uint32_t code = m_cpu.syscallCode();
            if (code < m_handlers.size() && m_handlers[code] == &Iop::functionReturn)
                break;
            context.pc = context.gpr[31];
            if (code < m_handlers.size())
            {
                m_lastHandler = code;
                (this->*m_handlers[code])(context);
            }
        }
        m_inInterrupt = nested;
        if (result)
            *result = context.gpr[2];
    }

    void Iop::serviceInterrupts()
    {
        if (m_intrSuspend > 0)
            return;
        while (!m_pendingInterrupts.empty())
        {
            const uint32_t line = m_pendingInterrupts.front();
            m_pendingInterrupts.erase(m_pendingInterrupts.begin());
            const auto found = m_interrupts.find(line);
            if (found == m_interrupts.end() || !found->second.enabled || found->second.handler == 0u)
                continue;
            uint32_t result = 0;
            call(found->second.handler, {found->second.argument}, &result, found->second.gp);
            // A handler returning zero leaves its line disabled.
            if (result == 0u)
                found->second.enabled = false;
            reschedule();
        }
    }

    void Iop::serviceEvents()
    {
        // Threads sleeping in DelayThread.
        for (auto &[id, thread] : m_threads)
            if (thread.wait == Wait::Delay && thread.wakeCycle <= m_cycle)
                makeReady(thread, 0u);

        // Alarms: the handler returns the next interval, or zero to stop.
        for (auto it = m_alarms.begin(); it != m_alarms.end();)
        {
            if (it->second.cycle > m_cycle)
            {
                ++it;
                continue;
            }
            const Alarm alarm = it->second;
            it = m_alarms.erase(it);
            uint32_t next = 0;
            call(alarm.handler, {alarm.argument}, &next, alarm.gp);
            if (next != 0u)
                m_alarms.emplace(alarm.handler, Alarm{m_cycle + next, alarm.handler, alarm.argument, alarm.gp});
            reschedule();
        }

        // Hardware timers: the handler returns the next compare value, or zero to stop.
        for (auto &timer : m_timers)
        {
            if (!timer.running || timer.handler == 0u || timer.next > m_cycle)
                continue;
            uint32_t compare = 0;
            call(timer.handler, {timer.argument}, &compare, timer.gp);
            if (compare == 0u)
                timer.running = false;
            else
            {
                timer.compare = compare;
                timer.next = m_cycle + static_cast<uint64_t>(compare) * timer.prescale;
            }
            reschedule();
        }
    }

    Iop::Thread *Iop::pickThread()
    {
        // Starvation guard. This port has no timer preemption, so a module thread that never blocks keeps the
        // interpreter forever: measured, the IxAudio mixer (prio 39) never yields and KORG's RPC server thread
        // (prio 99) never executes, which stalls sound init and therefore the whole boot. After a thread has
        // run a long uninterrupted stretch, prefer any other ready thread over it until it blocks again.
        Thread *best = nullptr;
        Thread *runnerUp = nullptr;
        for (auto &[id, thread] : m_threads)
        {
            if (thread.dormant || thread.wait != Wait::None)
                continue;
            if (!best || thread.priority < best->priority ||
                (thread.priority == best->priority && thread.readySequence < best->readySequence))
            {
                runnerUp = best;
                best = &thread;
            }
            else if (!runnerUp || thread.priority < runnerUp->priority ||
                     (thread.priority == runnerUp->priority && thread.readySequence < runnerUp->readySequence))
            {
                runnerUp = &thread;
            }
        }
        if (gHogThread != -1)
        {
            const auto hog = m_threads.find(gHogThread);
            if (hog == m_threads.end() || hog->second.dormant || hog->second.wait != Wait::None)
            {
                gHogThread = -1;
                gPickStreak = 0u;
                gLastPick = -1;
            }
        }
        if (best != nullptr && gHogThread == best->id && runnerUp != nullptr)
            return runnerUp;
        return best;
    }

    void Iop::makeReady(Thread &thread, uint32_t result)
    {
        thread.wait = Wait::None;
        thread.context.gpr[2] = result;
        thread.readySequence = ++m_readySequence;
        reschedule();
    }

    void Iop::block(Wait wait, int32_t id)
    {
        Thread *thread = current();
        if (!thread || m_inInterrupt)
        {
            m_ee.log("[iop] blocking call outside a thread");
            return;
        }
        thread->wait = wait;
        thread->waitId = id;
        reschedule();
    }

    bool Iop::runThreads(uint64_t budget, bool advanceClock)
    {
        // A module loaded at base 0 clears the low page with its .bss, which erased the return traps: at fault
        // time the RPC trap word read 0x00000000, so a handler returning to it executed zeros instead of the
        // syscall. Keep both trap words valid before anything runs.
        {
            uint8_t *ram = m_bus.ram();
            std::memcpy(ram + m_returnTrap, &gReturnTrapWord, 4);
            std::memcpy(ram + m_rpcTrap, &gRpcTrapWord, 4);
        }
        // Only the sample clock moves time. Work done off it, answering an
        // RPC the moment it arrives, would otherwise run the timers fast.
        uint64_t offClock = 0;
        uint64_t &clock = advanceClock ? m_cycle : offClock;
        bool ran = false;
        const uint64_t end = clock + budget;
        while (clock < end)
        {
            serviceInterrupts();
            Thread *thread = m_intrSuspend > 0 && current() && current()->wait == Wait::None ? current() : pickThread();
            if (!thread)
                break;
            m_current = thread->id;
            m_reschedule = false;
            ran = true;
            gReadTrace.context = &thread->context;
            gReadTrace.thread = thread->id;
            // Starvation accounting: a thread that keeps being picked without ever blocking is a hog.
            if (thread->id == gLastPick)
            {
                if (++gPickStreak > 8u)
                    gHogThread = thread->id;
            }
            else
            {
                gLastPick = thread->id;
                gPickStreak = 0u;
            }
            if (std::getenv("TOL_TRACE_IOP_RPC") != nullptr)
            {
                static uint32_t sPicks = 0u;
                if ((++sPicks % 2048u) == 0u && sPicks <= 2048u * 30u)
                {
                    std::fprintf(stderr, "[sifrpc] pick thread=%d prio=%d pc=0x%08X ready=%u\n",
                                 static_cast<int>(thread->id), static_cast<int>(thread->priority),
                                 thread->context.pc, thread->readySequence);
                }
            }
            while (!m_reschedule && clock < end)
            {
                const StopReason reason = m_cpu.run(thread->context, clock, end);
                if (reason == StopReason::Budget)
                    break;
                if (reason == StopReason::Fault)
                {
                    const uint32_t faultPc = m_cpu.faultPc();
                    const uint32_t faultWord = m_bus.read32(faultPc);
                    char address[16];
                    char word[16];
                    std::snprintf(address, sizeof(address), "%08X", faultPc);
                    std::snprintf(word, sizeof(word), "%08X", faultWord);
                    m_ee.log("[iop] thread " + std::to_string(thread->id) + " stopped on an unsupported instruction" +
                             " pc=0x" + address + " word=0x" + word);
                    const auto active = m_active.find(thread->id);
                    if (active != m_active.end())
                    {
                        // Where did the return actually go? ra at fault vs the trap we set, and the word the
                        // trap address holds: if ra != trap the return address was corrupted inside the
                        // handler; if ra == trap the resume path is what lands at the bad pc.
                        char raText[16];
                        char spText[16];
                        char trapText[16];
                        char trapWord[16];
                        std::snprintf(raText, sizeof(raText), "%08X", thread->context.gpr[31]);
                        std::snprintf(spText, sizeof(spText), "%08X", thread->context.gpr[29]);
                        std::snprintf(trapText, sizeof(trapText), "%08X", m_rpcTrap);
                        std::snprintf(trapWord, sizeof(trapWord), "%08X", m_bus.read32(m_rpcTrap));
                        m_ee.log(std::string("[iop] rpc fault tid=") + std::to_string(thread->id) + " ra=0x" + raText +
                                 " sp=0x" + spText + " trap=0x" + trapText + " trapWord=0x" + trapWord);
                        // The handler returned somewhere other than its RPC return trap (measured: pc 0x117C,
                        // in the kernel's own ctype area). The work is done and the reply is in the server
                        // buffer, so deliver that and put the thread back in its RPC loop rather than losing
                        // the server thread - a lost server thread makes every later call hang.
                        const auto server = m_servers.find(active->second->sid);
                        finishRequest(*thread, server != m_servers.end() ? server->second.buffer : 0u);
                        break;
                    }
                    thread->dormant = true;
                    reschedule();
                    break;
                }
                const uint32_t code = m_cpu.syscallCode();
                thread->context.pc = thread->context.gpr[31];
                if (std::getenv("TOL_TRACE_IOP_PC") != nullptr)
                {
                    static uint32_t sTraced = 0u;
                    if (sTraced < 4000u)
                    {
                        ++sTraced;
                        char pc[16];
                        std::snprintf(pc, sizeof(pc), "%08X", thread->context.pc);
                        m_ee.log("[iop] thread " + std::to_string(thread->id) + " syscall #" +
                                 std::to_string(code) + " at 0x" + pc);
                    }
                }
                if (code < m_handlers.size())
                {
                    m_lastHandler = code;
                    (this->*m_handlers[code])(thread->context);
                }
                if (thread->dormant || thread->wait != Wait::None)
                {
                    if (std::getenv("TOL_TRACE_IOP_PC") != nullptr)
                    {
                        static std::set<std::tuple<int32_t, int, int32_t>> sSeenWaits;
                        const auto key = std::make_tuple(thread->id, static_cast<int>(thread->wait),
                                                         thread->waitId);
                        if (sSeenWaits.insert(key).second)
                        {
                            char pc[16];
                            std::snprintf(pc, sizeof(pc), "%08X", thread->context.pc);
                            m_ee.log("[iop] thread " + std::to_string(thread->id) + " waits kind=" +
                                     std::to_string(static_cast<int>(thread->wait)) + " id=" +
                                     std::to_string(thread->waitId) + " pc=0x" + pc +
                                     (thread->dormant ? " (dormant)" : ""));
                        }
                    }
                    break;
                }
            }
            deliverRequests();
        }
        m_current = 0;
        return ran;
    }

    void Iop::settle()
    {
        deliverRequests();
        // Enough for any command handler; threads spinning on hardware stop here.
        runThreads(2'000'000u, false);
    }

    void Iop::step(int16_t &left, int16_t &right)
    {
        const uint64_t target = (m_cycle / kCyclesPerSample + 1u) * kCyclesPerSample;
        serviceEvents();
        deliverRequests();
        runThreads(target > m_cycle ? target - m_cycle : 0u);
        m_cycle = std::max(m_cycle, target);
        m_spu2.tick(left, right);
        serviceInterrupts();
    }

    // ------------------------------------------------------------------ RPC

    bool Iop::hasServer(uint32_t sid) const { return m_servers.count(sid) != 0u; }

    bool Iop::server(uint32_t sid, uint32_t &record, uint32_t &buffer) const
    {
        const auto found = m_servers.find(sid);
        if (found == m_servers.end())
            return false;
        record = found->second.record;
        buffer = found->second.buffer;
        return true;
    }

    void Iop::submit(std::shared_ptr<Request> request) { m_requests.push_back(std::move(request)); }

    void Iop::deliverRequests()
    {
        for (auto it = m_requests.begin(); it != m_requests.end();)
        {
            const auto server = m_servers.find((*it)->sid);
            if (server == m_servers.end())
            {
                if (std::getenv("TOL_TRACE_IOP_RPC") != nullptr)
                {
                    std::fprintf(stderr, "[sifrpc] request sid=0x%08X fn=0x%08X -> NO SERVER\n", (*it)->sid,
                                 (*it)->function);
                }
                (*it)->done = true; // nobody serves it; the EE side falls back
                it = m_requests.erase(it);
                continue;
            }
            const auto owner = m_threads.find(server->second.thread);
            const bool active = owner != m_threads.end() && m_active.count(owner->first) != 0u;
            const bool deliverable =
                owner != m_threads.end() && owner->second.wait == Wait::Rpc && !active;
            if ((*it)->sid == 0x90000300u)
            {
                // KORG's dispatcher (0xB5B0) reads a jump table at 0xDCCC with `lui at,1; lw v0,-0x2334(at)`,
                // i.e. at the LINK address, while the module is loaded at base+0. Compare what the dispatcher
                // would read with the relocated copy and with the expected handler (base + 0xA070).
                static uint32_t sDispatch = 0u;
                if (sDispatch < 8u)
                {
                    ++sDispatch;
                    const uint32_t base = server->second.function - 0xB5B0u;
                    const uint32_t function = (*it)->function;
                    const uint32_t tableLink = 0xDCCCu + function * 4u;
                    const uint32_t tableReloc = base + tableLink;
                    char text[384];
                    std::snprintf(text, sizeof(text),
                                  "[iop] korg dispatch fn=%u dispatcher=0x%08X base=0x%08X"
                                  " absTable[0x%08X]=0x%08X relTable[0x%08X]=0x%08X expected=0x%08X lui@%08X=0x%08X lw@%08X=0x%08X",
                                  function, server->second.function, base, tableLink, m_bus.read32(tableLink),
                                  tableReloc, m_bus.read32(tableReloc), base + 0xA070u, base + 0xB5CCu,
                                  m_bus.read32(base + 0xB5CCu), base + 0xB5D4u,
                                  m_bus.read32(base + 0xB5D4u));
                    const uint32_t luiWord = m_bus.read32(base + 0xB5CCu);
                    const uint32_t lwWord = m_bus.read32(base + 0xB5D4u);
                    const uint32_t at = ((luiWord & 0xFFFFu) << 16) + function * 4u;
                    const uint32_t effective =
                        at + static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(lwWord & 0xFFFFu)));
                    char extra[160];
                    std::snprintf(extra, sizeof(extra), " | dispatcherReads[0x%08X]=0x%08X", effective,
                                  m_bus.read32(effective));
                    m_ee.log(extra);
                    m_ee.log(text);
                }
            }
            if (std::getenv("TOL_TRACE_IOP_RPC") != nullptr)
            {
                static uint32_t sLogged = 0u;
                if (sLogged < 60u)
                {
                    ++sLogged;
                    // handler here is the pointer the server registered: if it is 0 or the owning thread is
                    // not parked in sifRpcLoop the request can never be delivered.
                    std::fprintf(stderr,
                                 "[sifrpc] request sid=0x%08X fn=0x%08X -> handler=0x%08X buff=0x%08X thread=%d"
                                 " wait=%d active=%d pc=0x%08X deliver=%s\n",
                                 (*it)->sid, (*it)->function, server->second.function, server->second.buffer,
                                 static_cast<int>(server->second.thread),
                                 owner == m_threads.end() ? -1 : static_cast<int>(owner->second.wait),
                                 active ? 1 : 0, owner == m_threads.end() ? 0u : owner->second.context.pc,
                                 deliverable ? "yes"
                                             : (owner == m_threads.end() ? "no(thread missing)"
                                                                         : (active ? "no(busy)" : "no(not parked)")));
                }
            }
            if (!deliverable)
            {
                ++it;
                continue;
            }
            Thread &thread = owner->second;
            const Request &request = **it;
            if (server->second.buffer != 0u && !request.send.empty())
                writeMemory(server->second.buffer, request.send.data(), static_cast<uint32_t>(request.send.size()));
            // Call the server function on top of the loop's own frame.
            m_saved[thread.id] = thread.context;
            CpuContext &c = thread.context;
            c.pc = server->second.function;
            c.gpr[4] = request.function;
            c.gpr[5] = server->second.buffer;
            c.gpr[6] = static_cast<uint32_t>(request.send.size());
            c.gpr[29] -= 64u;
            c.branchPending = false;
            c.loadRegister = 0;
            m_active[thread.id] = *it;
            makeReady(thread, 0u);
            it = m_requests.erase(it);
        }
    }

    void Iop::finishRequest(Thread &thread, uint32_t resultAddress)
    {
        const auto active = m_active.find(thread.id);
        if (active == m_active.end())
            return;
        Request &request = *active->second;
        if (request.receiveSize != 0u && request.receiveAddress != 0u && resultAddress != 0u)
        {
            std::vector<uint8_t> reply(request.receiveSize);
            readMemory(resultAddress, reply.data(), request.receiveSize);
            m_ee.writeEe(request.receiveAddress, reply.data(), request.receiveSize);
        }
        request.done = true;
        m_active.erase(active);
        thread.context = m_saved[thread.id];
        thread.wait = Wait::Rpc;
        reschedule();
    }

    // ------------------------------------------------------------------ modules

    void Iop::linkImports(const std::vector<IrxImport> &imports)
    {
        for (const IrxImport &import : imports)
        {
            uint32_t word = 0;
            const auto exported = m_exports.find(import.library);
            if (exported != m_exports.end() && import.ordinal < exported->second.size() &&
                exported->second[import.ordinal] != 0u)
                word = 0x08000000u | ((exported->second[import.ordinal] >> 2) & 0x03FFFFFFu); // j target
            else
                word = syscallWord(handlerFor(import.library, import.ordinal));
            m_bus.write32(import.stubAddress, word);
        }
    }

    int32_t Iop::loadModule(const std::vector<uint8_t> &file, const std::string &path,
                            const std::vector<std::string> &arguments)
    {
        IrxImage irx;
        std::string error;
        if (!parseIrx(file, irx, error))
        {
            m_ee.log("[iop] " + path + ": " + error);
            return -1;
        }
        const uint32_t size = static_cast<uint32_t>(irx.image.size()) + irx.bssSize;
        const uint32_t base = allocate(size);
        std::vector<IrxImport> imports;
        if (base == 0u || !relocateIrx(irx, m_bus.ram(), Bus::kRamBytes, base, imports, error))
        {
            m_ee.log("[iop] " + path + ": " + (base == 0u ? std::string("out of IOP memory") : error));
            release(base);
            return -1;
        }
        linkImports(imports);

        // argv: the path followed by the arguments, as C strings.
        std::vector<std::string> argv{path};
        argv.insert(argv.end(), arguments.begin(), arguments.end());
        uint32_t bytes = static_cast<uint32_t>(argv.size() + 1u) * 4u;
        for (const auto &text : argv)
            bytes += static_cast<uint32_t>(text.size()) + 1u;
        const uint32_t block = allocate(bytes);
        uint32_t strings = block + static_cast<uint32_t>(argv.size() + 1u) * 4u;
        for (size_t index = 0; index < argv.size(); ++index)
        {
            m_bus.write32(block + static_cast<uint32_t>(index) * 4u, strings);
            writeMemory(strings, argv[index].c_str(), static_cast<uint32_t>(argv[index].size()) + 1u);
            strings += static_cast<uint32_t>(argv[index].size()) + 1u;
        }
        m_bus.write32(block + static_cast<uint32_t>(argv.size()) * 4u, 0u);

        // The start function runs in a thread of its own, like MODLOAD's.
        Thread loader;
        loader.id = m_nextId++;
        loader.priority = loader.initialPriority = 8;
        loader.stackSize = 0x2000u;
        loader.stackBase = allocate(loader.stackSize);
        loader.gp = base + irx.gp;
        loader.dormant = false;
        loader.context.pc = base + irx.entry;
        loader.context.gpr[4] = static_cast<uint32_t>(argv.size());
        loader.context.gpr[5] = block;
        loader.context.gpr[28] = loader.gp;
        loader.context.gpr[29] = loader.stackBase + loader.stackSize - 16u;
        loader.context.gpr[31] = m_returnTrap;
        loader.readySequence = ++m_readySequence;
        const int32_t loaderId = loader.id;
        m_threads[loaderId] = loader;
        m_loaderResult = 0xFFFFFFFFu;
        m_loaderThread = loaderId;
        for (int round = 0; round < 64 && m_threads.count(loaderId) && !m_threads.at(loaderId).dormant; ++round)
            runThreads(2'000'000u);
        const uint32_t result = m_loaderResult;
        m_loaderThread = 0;
        if (m_threads.count(loaderId))
        {
            release(m_threads.at(loaderId).stackBase);
            m_threads.erase(loaderId);
        }
        release(block);

        Module module{m_nextId++, irx.name, base, size};
        if ((result & 3u) == 1u)
        {
            // NO_RESIDENT_END: the module is done and leaves nothing behind.
            release(base);
            m_ee.log("[iop] " + irx.name + " did not stay resident");
            return module.id;
        }
        m_modules.push_back(module);
        m_ee.log("[iop] started " + irx.name + " at " + std::to_string(base));
        return module.id;
    }
}
