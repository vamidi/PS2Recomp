#include "ps2x/iop/native_iop.h"

#include "lle/iop.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <mutex>

namespace ps2x::iop
{
    namespace
    {
        std::string moduleName(std::string_view guestPath)
        {
            const size_t slash = guestPath.find_last_of("\\/:");
            std::string_view name = slash == std::string_view::npos ? guestPath : guestPath.substr(slash + 1);
            name = name.substr(0, name.find(';'));
            std::string upper(name);
            for (char &ch : upper)
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            return upper;
        }
    }

    class NativeIop::Impl final : public lle::EeLink
    {
    public:
        explicit Impl(IopHost &hostRef) : host(hostRef), iop(*this) {}

        bool readEe(uint32_t address, void *destination, uint32_t size) override
        {
            return host.readGuest(address, destination, size);
        }
        bool writeEe(uint32_t address, const void *source, uint32_t size) override
        {
            return host.writeGuest(address, source, size);
        }
        bool eeServer(uint32_t sid) override { return host.hasGuestRpcServer(sid); }
        void log(const std::string &message) override { host.log(LogLevel::Info, message); }
        IopHost *hostFiles() override { return &host; }

        // Advance the IOP without an audio device, discarding the samples.
        void stepSilently(uint32_t frames)
        {
            int16_t left, right;
            for (uint32_t index = 0; index < frames; ++index)
                iop.step(left, right);
        }

        bool audioRunning() const
        {
            return rendered && std::chrono::steady_clock::now() - lastRender < std::chrono::milliseconds(250);
        }

        IopHost &host;
        lle::Iop iop;
        mutable std::mutex mutex;
        std::condition_variable progressed;
        std::vector<std::string> modules;
        std::chrono::steady_clock::time_point lastRender{};
        bool rendered = false;
        bool loaded = false;
    };

    NativeIop::NativeIop(IopHost &host) : m_impl(std::make_unique<Impl>(host)) {}
    NativeIop::~NativeIop() = default;

    void NativeIop::setModules(std::vector<std::string> names)
    {
        std::lock_guard lock(m_impl->mutex);
        m_impl->modules.clear();
        for (const auto &name : names)
            m_impl->modules.push_back(moduleName(name));
    }

    bool NativeIop::enabled() const
    {
        std::lock_guard lock(m_impl->mutex);
        return !m_impl->modules.empty();
    }

    bool NativeIop::claims(std::string_view guestPath) const
    {
        std::lock_guard lock(m_impl->mutex);
        const std::string name = moduleName(guestPath);
        return std::find(m_impl->modules.begin(), m_impl->modules.end(), name) != m_impl->modules.end();
    }

    int32_t NativeIop::load(std::string_view guestPath, std::string_view arguments)
    {
        IopHost &host = m_impl->host;
        const uint64_t handle = host.openHostFile(host.translateGuestPath(guestPath));
        uint64_t size = 0;
        if (handle == 0u || !host.hostFileSize(handle, size) || size == 0u || size > (4u << 20))
        {
            if (handle != 0u)
                host.closeHostFile(handle);
            host.log(LogLevel::Warning, "[iop] cannot read " + std::string(guestPath));
            return -1;
        }
        std::vector<uint8_t> file(static_cast<size_t>(size));
        size_t got = 0;
        const bool read = host.readHostFile(handle, 0u, file.data(), file.size(), got);
        host.closeHostFile(handle);
        if (!read || got != file.size())
            return -1;

        std::vector<std::string> argv;
        for (size_t start = 0; start < arguments.size();)
        {
            const size_t end = std::min(arguments.find('\0', start), arguments.size());
            if (end > start)
                argv.emplace_back(arguments.substr(start, end - start));
            start = end + 1;
        }

        std::lock_guard lock(m_impl->mutex);
        const int32_t id = m_impl->iop.loadModule(file, std::string(guestPath), argv);
        if (id > 0)
            m_impl->loaded = true;
        m_impl->iop.settle();
        return id;
    }

    // Starts a module whose bytes are already in memory, which is how an IOP boot image carries them.
    int32_t NativeIop::loadModuleFromMemory(std::vector<uint8_t> file, std::string_view name)
    {
        std::lock_guard lock(m_impl->mutex);
        const int32_t id = m_impl->iop.loadModule(file, std::string(name), {});
        if (id > 0)
            m_impl->loaded = true;
        m_impl->iop.settle();
        return id;
    }

    bool NativeIop::server(uint32_t sid, uint32_t &record, uint32_t &buffer) const
    {
        std::lock_guard lock(m_impl->mutex);
        return m_impl->iop.server(sid, record, buffer);
    }

    void NativeIop::pump(uint32_t frames)
    {
        std::lock_guard lock(m_impl->mutex);
        m_impl->iop.settle();
        m_impl->stepSilently(frames);
        m_impl->iop.settle();
    }

    bool NativeIop::call(uint32_t sid, uint32_t function, uint32_t sendAddress, uint32_t sendSize,
                         uint32_t receiveAddress, uint32_t receiveSize)
    {
        auto request = std::make_shared<lle::Iop::Request>();
        request->sid = sid;
        request->function = function;
        request->send.resize(sendSize);
        if (sendSize != 0u && !m_impl->host.readGuest(sendAddress, request->send.data(), sendSize))
            return false;
        request->receiveAddress = receiveAddress;
        request->receiveSize = receiveSize;

        // IxAudio (sid 0x90000200): the module DOES register a server on the IOP, but its function 0x0A never
        // completes - measured as 6 calls (one per AFS archive), each blocking the full 2 s deadline. Whatever it
        // waits on never wakes, so answer it from the adapter with a zeroed reply, exactly as the EE-side HLE in
        // src/runtime/tol_overrides.cpp already does for this service.
        if (std::getenv("TOL_TRACE_IOP_CALL") != nullptr)
        {
            static uint32_t sPreGuard = 0u;
            if (sPreGuard < 12u)
            {
                ++sPreGuard;
                m_impl->host.log(LogLevel::Warning,
                                 "[iop-call] pre-guard sid=" + std::to_string(sid) + " fn=" +
                                     std::to_string(function) + " hasServer=" +
                                     (m_impl->iop.hasServer(sid) ? "1" : "0"));
            }
        }
        // The parameter can be spilled into a slot that no longer holds it (measured: a log one line above this
        // prints sid=2415919872 for the same invocation in which the comparison below fails). Force a fresh load.
        const volatile uint32_t liveSid = sid;
        if (liveSid == 0x90000200u)
        {
            if (std::getenv("TOL_TRACE_IOP_CALL") != nullptr)
            {
                static uint32_t sShortCircuits = 0u;
                if (sShortCircuits < 20u)
                {
                    ++sShortCircuits;
                    m_impl->host.log(LogLevel::Warning,
                                     "[iop-call] ixaudio short-circuit fn=" + std::to_string(function));
                }
            }
            if (receiveSize != 0u)
            {
                std::vector<uint8_t> zeroReply(receiveSize, 0u);
                m_impl->host.writeGuest(receiveAddress, zeroReply.data(), receiveSize);
            }
            return true;
        }

        std::unique_lock lock(m_impl->mutex);
        if (!m_impl->iop.hasServer(sid))
            return false;
        const bool traceCallTime = std::getenv("TOL_TRACE_IOP_CALL_TIME") != nullptr;
        const auto callEntry = std::chrono::steady_clock::now();
        m_impl->iop.submit(request);
        m_impl->iop.settle();
        const auto afterSettle = std::chrono::steady_clock::now();
        // Most commands finish at once; the rest wait for IOP time to pass.
        const auto started = afterSettle;
        const auto deadline = started + std::chrono::seconds(2);
        uint32_t iterations = 0u;
        double waitMs = 0.0;
        while (!request->done && std::chrono::steady_clock::now() < deadline)
        {
            ++iterations;
            const auto waitStart = std::chrono::steady_clock::now();
            if (m_impl->audioRunning())
                m_impl->progressed.wait_for(lock, std::chrono::milliseconds(20));
            else
                m_impl->stepSilently(480u);
            waitMs += std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - waitStart).count();
            m_impl->iop.settle();
        }
        if (traceCallTime)
        {
            // Split the call: setup (submit + first settle, i.e. delivering to the server thread), the wait
            // loop (its sleeps and how many laps), and the tail.
            static uint32_t sCallTimeLogs = 0u;
            if (sCallTimeLogs < 40u)
            {
                ++sCallTimeLogs;
                const auto now = std::chrono::steady_clock::now();
                auto ms = [](auto from, auto to)
                { return std::chrono::duration<double, std::milli>(to - from).count(); };
                m_impl->host.log(LogLevel::Warning,
                                 "[iop-call-time] sid=" + std::to_string(sid) + " fn=" + std::to_string(function) +
                                     " total=" + std::to_string(ms(callEntry, now)) +
                                     " setup=" + std::to_string(ms(callEntry, afterSettle)) +
                                     " wait=" + std::to_string(waitMs) + " loops=" + std::to_string(iterations) +
                                     " audio=" + (m_impl->audioRunning() ? "1" : "0") +
                                     " done=" + (request->done ? "1" : "0"));
            }
        }
        // TOL_TRACE_IOP_CALL=1: name every IOP RPC and whether it completed, with its wall time. A "timed out"
        // line only appears when the server EXISTS but never answers, so this is what distinguishes "no provider"
        // from "provider parked".
        if (std::getenv("TOL_TRACE_IOP_CALL") != nullptr)
        {
            static uint32_t sCallLogs = 0u;
            if (sCallLogs < 80u)
            {
                ++sCallLogs;
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - started)
                                         .count();
                m_impl->host.log(LogLevel::Warning,
                                 "[iop-call] sid=" + std::to_string(sid) + " fn=" + std::to_string(function) +
                                     " done=" + (request->done ? "1" : "0") + " ms=" + std::to_string(elapsed));
            }
        }
        if (!request->done)
            m_impl->host.log(LogLevel::Warning, "[iop] RPC to " + std::to_string(sid) + " timed out");
        return request->done;
    }

    bool NativeIop::write(uint32_t address, const void *data, uint32_t size)
    {
        std::lock_guard lock(m_impl->mutex);
        m_impl->iop.writeMemory(address, data, size);
        return true;
    }

    bool NativeIop::read(uint32_t address, void *data, uint32_t size)
    {
        std::lock_guard lock(m_impl->mutex);
        m_impl->iop.readMemory(address, data, size);
        return true;
    }

    uint32_t NativeIop::allocate(uint32_t size)
    {
        std::lock_guard lock(m_impl->mutex);
        return m_impl->iop.allocate(size);
    }

    void NativeIop::release(uint32_t address)
    {
        std::lock_guard lock(m_impl->mutex);
        m_impl->iop.release(address);
    }

    void NativeIop::render(int16_t *frames, uint32_t count)
    {
        {
            std::lock_guard lock(m_impl->mutex);
            for (uint32_t index = 0; index < count; ++index)
                m_impl->iop.step(frames[index * 2u], frames[index * 2u + 1u]);
            m_impl->rendered = true;
            m_impl->lastRender = std::chrono::steady_clock::now();
        }
        m_impl->progressed.notify_all();
    }

    bool NativeIop::active() const
    {
        std::lock_guard lock(m_impl->mutex);
        return m_impl->loaded;
    }
}
