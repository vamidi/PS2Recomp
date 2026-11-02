#include "ps2_iop_host.h"

#include "ps2_iop_transport.h"
#include "ps2_runtime.h"
#include "ps2_stubs.h"
#include "Kernel/Stubs/SIF.h"
#include "runtime/ps2_memory.h"
#include "Kernel/Stubs/MemoryCard.h"
#include "Kernel/Syscalls/Common.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <limits>
#include <utility>

#if !defined(_WIN32)
#include <sys/types.h>
#endif

PS2IopHostAdapter::CallScope::CallScope(PS2IopHostAdapter &owner, R5900Context *context, uint8_t *rdram)
    : m_lock(owner.m_callMutex),
      m_owner(&owner),
      m_previousContext(owner.m_activeContext),
      m_previousRdram(owner.m_activeRdram),
      m_previousToken(owner.m_activeToken)
{
    m_token = owner.m_nextToken++;
    if (m_token == 0)
    {
        m_token = owner.m_nextToken++;
    }
    owner.m_activeContext = context;
    owner.m_activeRdram = rdram;
    owner.m_activeToken = m_token;
}

PS2IopHostAdapter::CallScope::~CallScope()
{
    release();
}

PS2IopHostAdapter::CallScope::CallScope(CallScope &&other) noexcept
    : m_lock(std::move(other.m_lock)),
      m_owner(std::exchange(other.m_owner, nullptr)),
      m_previousContext(other.m_previousContext),
      m_previousRdram(other.m_previousRdram),
      m_previousToken(other.m_previousToken),
      m_token(other.m_token)
{
}

PS2IopHostAdapter::CallScope &PS2IopHostAdapter::CallScope::operator=(CallScope &&other) noexcept
{
    if (this != &other)
    {
        release();
        m_lock = std::move(other.m_lock);
        m_owner = std::exchange(other.m_owner, nullptr);
        m_previousContext = other.m_previousContext;
        m_previousRdram = other.m_previousRdram;
        m_previousToken = other.m_previousToken;
        m_token = other.m_token;
    }
    return *this;
}

void PS2IopHostAdapter::CallScope::release()
{
    if (m_owner)
    {
        m_owner->m_activeContext = m_previousContext;
        m_owner->m_activeRdram = m_previousRdram;
        m_owner->m_activeToken = m_previousToken;
        m_owner = nullptr;
    }
}

PS2IopHostAdapter::PS2IopHostAdapter(PS2Runtime &runtime)
    : m_runtime(runtime)
{
}

PS2IopHostAdapter::~PS2IopHostAdapter()
{
    std::lock_guard<std::mutex> lock(m_hostFileMutex);
    for (auto &[handle, file] : m_hostFiles)
    {
        (void)handle;
        if (file.stream)
        {
            std::fclose(file.stream);
        }
    }
    m_hostFiles.clear();
}

PS2IopHostAdapter::CallScope PS2IopHostAdapter::enterCall(R5900Context *context, uint8_t *rdram)
{
    return CallScope(*this, context, rdram);
}

bool PS2IopHostAdapter::guestRange(uint32_t address, size_t size, uint8_t *&begin) const
{
    begin = nullptr;
    uint8_t *const rdram = m_activeRdram
                               ? m_activeRdram
                               : m_runtime.memory().getRDRAM();
    if (!rdram)
    {
        return false;
    }
    if (size == 0)
    {
        begin = getMemPtr(rdram, address);
        return begin != nullptr;
    }
    if (size - 1 > std::numeric_limits<uint32_t>::max() - address)
    {
        return false;
    }
    uint8_t *const first = getMemPtr(rdram, address);
    uint8_t *const last = getMemPtr(rdram, address + static_cast<uint32_t>(size - 1));
    if (!first || !last || last < first || static_cast<size_t>(last - first) != size - 1)
    {
        return false;
    }
    begin = first;
    return true;
}

bool PS2IopHostAdapter::readGuest(uint32_t address, void *destination, size_t size) const
{
    if (!destination && size != 0)
    {
        return false;
    }
    if (ps2_stubs::isSifIopHeapAddress(address))
    {
        return ps2_stubs::readSifIopHeap(address, destination, size);
    }

    uint8_t *source = nullptr;
    if (!guestRange(address, size, source))
    {
        return false;
    }
    if (size != 0)
    {
        std::memcpy(destination, source, size);
    }
    return true;
}

bool PS2IopHostAdapter::writeGuest(uint32_t address, const void *source, size_t size)
{
    if (!source && size != 0)
    {
        return false;
    }
    if (ps2_stubs::isSifIopHeapAddress(address))
    {
        return ps2_stubs::writeSifIopHeap(address, source, size);
    }

    uint8_t *destination = nullptr;
    if (!guestRange(address, size, destination))
    {
        return false;
    }
    if (size != 0)
    {
        uint8_t *const rdram = m_activeRdram ? m_activeRdram : m_runtime.memory().getRDRAM();
        ps2TraceGuestRangeWrite(rdram, address, static_cast<uint32_t>(size), "IopHost::writeGuest", nullptr);
        std::memcpy(destination, source, size);
    }
    return true;
}

bool PS2IopHostAdapter::zeroGuest(uint32_t address, size_t size)
{
    if (ps2_stubs::isSifIopHeapAddress(address))
    {
        return ps2_stubs::zeroSifIopHeap(address, size);
    }

    uint8_t *destination = nullptr;
    if (!guestRange(address, size, destination))
    {
        return false;
    }
    if (size != 0)
    {
        uint8_t *const rdram = m_activeRdram ? m_activeRdram : m_runtime.memory().getRDRAM();
        ps2TraceGuestRangeWrite(rdram, address, static_cast<uint32_t>(size), "IopHost::zeroGuest", nullptr);
        std::memset(destination, 0, size);
    }
    return true;
}

bool PS2IopHostAdapter::normalizeGuestAddress(uint32_t address, uint32_t &normalized) const
{
    if (ps2_stubs::isSifIopHeapAddress(address))
    {
        normalized = address;
        return ps2_stubs::isSifIopHeapRange(address, 0u);
    }

    bool scratchpad = false;
    if (!ps2ResolveGuestPointer(address, normalized, scratchpad) || scratchpad)
    {
        normalized = 0;
        return false;
    }
    return true;
}

uint32_t PS2IopHostAdapter::allocateIopHandle(ps2x::iop::IopHandleKind kind)
{
    uint8_t *const rdram = m_activeRdram
                               ? m_activeRdram
                               : m_runtime.memory().getRDRAM();
    if (!rdram)
    {
        return 0;
    }
    return kind == ps2x::iop::IopHandleKind::RpcPacket
               ? rpcAllocPacketAddr(rdram)
               : rpcAllocServerAddr(rdram);
}

uint32_t PS2IopHostAdapter::allocateGuest(uint32_t size, uint32_t alignment)
{
    return m_runtime.guestMalloc(size, alignment);
}

void PS2IopHostAdapter::freeGuest(uint32_t address)
{
    m_runtime.guestFree(address);
}

void PS2IopHostAdapter::audioCommand(uint32_t sid,
                                     uint32_t function,
                                     ps2x::iop::GuestBuffer send,
                                     ps2x::iop::GuestBuffer receive)
{
    uint8_t *sendPointer = nullptr;
    uint8_t *receivePointer = nullptr;
    if (send.address && !guestRange(send.address, send.size, sendPointer))
    {
        sendPointer = nullptr;
    }
    if (receive.address && !guestRange(receive.address, receive.size, receivePointer))
    {
        receivePointer = nullptr;
    }
    m_runtime.audioBackend().onSoundCommand(sid,
                                            function,
                                            sendPointer,
                                            send.size,
                                            receivePointer,
                                            receive.size);
}

std::string PS2IopHostAdapter::hostPath(ps2x::iop::HostPathKind kind) const
{
    const PS2Runtime::IoPaths &paths = PS2Runtime::getIoPaths();
    switch (kind)
    {
    case ps2x::iop::HostPathKind::CdRoot:
        return paths.cdRoot.string();
    case ps2x::iop::HostPathKind::CdImage:
        return paths.cdImage.string();
    case ps2x::iop::HostPathKind::HostRoot:
        return paths.hostRoot.string();
    case ps2x::iop::HostPathKind::MemoryCardRoot:
        return paths.mcRoot.string();
    case ps2x::iop::HostPathKind::ElfDirectory:
    default:
        return paths.elfDirectory.string();
    }
}

std::string PS2IopHostAdapter::translateGuestPath(std::string_view path) const
{
    return translatePs2Path(std::string(path).c_str());
}

// SIF load-module commands carry a guest path ("cdrom0:\IRX\IOPRP300.IMG;1") instead of an RPC, so the
// runtime has to reach the same file layer the IOP would. Translating and opening here keeps one choke
// point for every IOP-side read, which is what TOL_TRACE_FILEIO reports on.
bool PS2IopTransport::readHostFile(PS2Runtime *runtime, std::string_view guestPath, std::vector<uint8_t> &out){
    out.clear();
    if (!runtime || !runtime->m_iopHost || guestPath.empty())
    {
        return false;
    }

    const std::string hostPath = runtime->m_iopHost->translateGuestPath(guestPath);
    const uint64_t handle = runtime->m_iopHost->openHostFile(hostPath);
    if (handle == 0u)
    {
        return false;
    }

    bool ok = false;
    uint64_t size = 0u;
    // An IOP image is a few hundred KiB; refuse anything absurd rather than allocating it.
    if (runtime->m_iopHost->hostFileSize(handle, size) && size > 0u && size <= (16u << 20))
    {
        out.resize(static_cast<size_t>(size));
        size_t read = 0u;
        ok = runtime->m_iopHost->readHostFile(handle, 0u, out.data(), out.size(), read) && read == out.size();
        if (!ok)
        {
            out.clear();
        }
    }
    runtime->m_iopHost->closeHostFile(handle);
    return ok;
}

// Boots an IOP boot image (IOPRP*.IMG). The container is a romdir table followed by the module ELFs; the
// table's first three entries (RESET, ROMDIR, EXTINFO) are the image's own tables, and the remaining names
// line up with the ELFs in file order. Modules this runtime already provides as high-level LLE kernel
// services are skipped - loading them would register the same libraries twice.
int PS2IopTransport::bootIopImage(PS2Runtime *runtime, const std::vector<uint8_t> &image)
{
    if (!runtime || !runtime->m_iopSubsystem || image.size() < 0x200u)
    {
        return -1;
    }
    ps2x::iop::NativeIop &iop = runtime->m_iopSubsystem->native();

    // romdir: {char name[10]; uint16 extinfo; uint32 size} from 0, terminated by an empty name.
    std::vector<std::string> names;
    for (size_t offset = 0; offset + 16u <= image.size(); offset += 16u)
    {
        const char *raw = reinterpret_cast<const char *>(image.data() + offset);
        const std::string name(raw, strnlen(raw, 10u));
        if (name.empty())
        {
            break;
        }
        names.push_back(name);
    }
    if (names.size() < 4u)
    {
        return -1; // not a romdir container
    }

    // Modules the LLE kernel emulates itself (sysmem, loadcore, sifman/sifcmd, threadman, ioman, fileio,
    // timrman, sysclib, stdio). Their kernel-side counterparts must not be loaded on top.
    static const char *kEmulated[] = {"RESET", "ROMDIR", "EXTINFO", "SYSMEM", "LOADCORE", "SIFCMD", "SIFMAN",
                                      "THREADMAN", "IOMAN", "FILEIO", "TIMEMANI", "SYSCLIB", "STDIO"};
    const auto emulated = [](const std::string &name)
    {
        for (const char *candidate : kEmulated)
            if (name == candidate)
                return true;
        return false;
    };

    // The module images are ELF files; their offsets are found by magic because the romdir sizes are not the
    // layout. Size comes from the program headers.
    std::vector<std::pair<size_t, size_t>> modules; // offset, size
    for (size_t offset = 0; offset + 52u <= image.size(); ++offset)
    {
        if (image[offset] != 0x7Fu || image[offset + 1] != 'E' || image[offset + 2] != 'L' ||
            image[offset + 3] != 'F')
        {
            continue;
        }
        const uint32_t phoff = *reinterpret_cast<const uint32_t *>(image.data() + offset + 0x1C);
        const uint16_t phnum = *reinterpret_cast<const uint16_t *>(image.data() + offset + 0x2C);
        size_t end = 0x34u;
        for (uint16_t index = 0; index < phnum; ++index)
        {
            const size_t entry = phoff + static_cast<size_t>(index) * 32u;
            if (offset + entry + 32u > image.size())
                break;
            const uint32_t type = *reinterpret_cast<const uint32_t *>(image.data() + offset + entry);
            const uint32_t fileOffset = *reinterpret_cast<const uint32_t *>(image.data() + offset + entry + 4u);
            const uint32_t fileSize = *reinterpret_cast<const uint32_t *>(image.data() + offset + entry + 16u);
            if (type == 1u)
                end = std::max(end, static_cast<size_t>(fileOffset) + fileSize);
        }
        if (end != 0u && offset + end <= image.size())
        {
            modules.emplace_back(offset, end);
        }
        offset += 3u;
    }
    if (modules.empty())
    {
        return -1;
    }

    const bool trace = std::getenv("TOL_TRACE_FILEIO") != nullptr;
    int started = 0;
    // names[0..2] are RESET/ROMDIR/EXTINFO; the rest line up with the ELFs in order.
    for (size_t index = 0; index < modules.size(); ++index)
    {
        const std::string name = (index + 3u < names.size()) ? names[index + 3u] : std::string("module");
        if (emulated(name))
        {
            if (trace)
                std::fprintf(stderr, "[ioprp] skip %s (emulated by the LLE kernel)\n", name.c_str());
            continue;
        }
        const std::pair<size_t, size_t> module = modules[index];
        std::vector<uint8_t> file(image.begin() + static_cast<long>(module.first),
                                 image.begin() + static_cast<long>(module.first + module.second));
        const int32_t id = iop.loadModuleFromMemory(std::move(file), name);
        if (trace)
            std::fprintf(stderr, "[ioprp] %s -> %s (%zu bytes)\n", name.c_str(), id > 0 ? "loaded" : "FAILED",
                         module.second);
        if (id > 0)
            ++started;
    }
    return started;
}

uint64_t PS2IopHostAdapter::openHostFile(std::string_view path)
{
    if (path.empty())
    {
        return 0u;
    }

    // TOL_TRACE_FILEIO=1: this is the IOP-side host opener (cdrom0:, host:, mc0:). Without it a quiet run
    // cannot distinguish "no file I/O" from "file I/O that succeeded", because failures are the only thing
    // the stub layers log.
    const bool traceFileIo = std::getenv("TOL_TRACE_FILEIO") != nullptr;

    const std::filesystem::path hostPath{std::string(path)};
#if defined(_WIN32)
    std::FILE *stream = ::_wfopen(hostPath.c_str(), L"rb");
#else
    std::FILE *stream = std::fopen(hostPath.string().c_str(), "rb");
#endif
    if (!stream)
    {
        if (traceFileIo)
            std::fprintf(stderr, "[fileio] iop open '%s' -> FAILED (missing)\n", hostPath.string().c_str());
        return 0u;
    }

    std::error_code error;
    const uint64_t size = std::filesystem::file_size(hostPath, error);
    if (error)
    {
        std::fclose(stream);
        return 0u;
    }

    std::lock_guard<std::mutex> lock(m_hostFileMutex);
    uint64_t handle = m_nextHostFileHandle++;
    if (handle == 0u)
    {
        handle = m_nextHostFileHandle++;
    }
    m_hostFiles.emplace(handle, HostFile{stream, size});
    if (traceFileIo)
        std::fprintf(stderr, "[fileio] iop open '%s' -> ok, %llu bytes (handle %llu)\n",
                     hostPath.string().c_str(), static_cast<unsigned long long>(size),
                     static_cast<unsigned long long>(handle));
    return handle;
}

bool PS2IopHostAdapter::hostFileSize(uint64_t handle, uint64_t &size) const
{
    size = 0u;
    std::lock_guard<std::mutex> lock(m_hostFileMutex);
    const auto it = m_hostFiles.find(handle);
    if (it == m_hostFiles.end() || !it->second.stream)
    {
        return false;
    }
    size = it->second.size;
    return true;
}

bool PS2IopHostAdapter::readHostFile(uint64_t handle,
                                     uint64_t offset,
                                     void *destination,
                                     size_t size,
                                     size_t &bytesRead)
{
    bytesRead = 0u;
    if (!destination && size != 0u)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_hostFileMutex);
    const auto it = m_hostFiles.find(handle);
    if (it == m_hostFiles.end() || !it->second.stream)
    {
        return false;
    }

#if defined(_WIN32)
    if (offset > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
        _fseeki64(it->second.stream, static_cast<int64_t>(offset), SEEK_SET) != 0)
#else
    if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max()) ||
        fseeko(it->second.stream, static_cast<off_t>(offset), SEEK_SET) != 0)
#endif
    {
        return false;
    }

    bytesRead = size == 0u
                    ? 0u
                    : std::fread(destination, 1u, size, it->second.stream);
    if (bytesRead < size && std::ferror(it->second.stream))
    {
        std::clearerr(it->second.stream);
        return false;
    }
    return true;
}

void PS2IopHostAdapter::closeHostFile(uint64_t handle)
{
    std::FILE *stream = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_hostFileMutex);
        const auto it = m_hostFiles.find(handle);
        if (it == m_hostFiles.end())
        {
            return;
        }
        stream = it->second.stream;
        m_hostFiles.erase(it);
    }
    if (stream)
    {
        std::fclose(stream);
    }
}

int32_t PS2IopHostAdapter::memoryCard(const ps2x::iop::MemoryCardRequest &request)
{
    using Handler = void (*)(uint8_t *, R5900Context *, PS2Runtime *);
    Handler handler = nullptr;
    switch (request.operation)
    {
    case ps2x::iop::MemoryCardOperation::Init:
        handler = ps2_stubs::sceMcInit;
        break;
    case ps2x::iop::MemoryCardOperation::GetInfo:
        handler = ps2_stubs::sceMcGetInfo;
        break;
    case ps2x::iop::MemoryCardOperation::Open:
        handler = ps2_stubs::sceMcOpen;
        break;
    case ps2x::iop::MemoryCardOperation::Close:
        handler = ps2_stubs::sceMcClose;
        break;
    case ps2x::iop::MemoryCardOperation::Seek:
        handler = ps2_stubs::sceMcSeek;
        break;
    case ps2x::iop::MemoryCardOperation::Read:
        handler = ps2_stubs::sceMcRead;
        break;
    case ps2x::iop::MemoryCardOperation::Write:
        handler = ps2_stubs::sceMcWrite;
        break;
    case ps2x::iop::MemoryCardOperation::Flush:
        handler = ps2_stubs::sceMcFlush;
        break;
    case ps2x::iop::MemoryCardOperation::Chdir:
        handler = ps2_stubs::sceMcChdir;
        break;
    case ps2x::iop::MemoryCardOperation::GetDir:
        handler = ps2_stubs::sceMcGetDir;
        break;
    case ps2x::iop::MemoryCardOperation::SetFileInfo:
        handler = ps2_stubs::sceMcSetFileInfo;
        break;
    case ps2x::iop::MemoryCardOperation::Delete:
        handler = ps2_stubs::sceMcDelete;
        break;
    case ps2x::iop::MemoryCardOperation::Format:
        handler = ps2_stubs::sceMcFormat;
        break;
    case ps2x::iop::MemoryCardOperation::Unformat:
        handler = ps2_stubs::sceMcUnformat;
        break;
    case ps2x::iop::MemoryCardOperation::Mkdir:
        handler = ps2_stubs::sceMcMkdir;
        break;
    }
    if (!handler)
    {
        return -1;
    }

    R5900Context context{};
    for (size_t i = 0; i < 4u; ++i)
    {
        setRegU32(&context, static_cast<int>(4 + i), request.arguments[i]);
    }

    // EE n32 ABI: the fifth argument travels in $t0, matching the sceMc* stubs.
    setRegU32(&context, 8, request.arguments[4]);

    handler(m_activeRdram ? m_activeRdram : m_runtime.memory().getRDRAM(),
            &context,
            &m_runtime);
    return ps2_stubs::getMemoryCardDebugSnapshot().lastResult;
}

bool PS2IopHostAdapter::hasGuestFunction(uint32_t address) const
{
    return m_runtime.hasFunction(address);
}

bool PS2IopHostAdapter::hasGuestRpcServer(uint32_t sid) const
{
    uint32_t record = 0u;
    {
        std::lock_guard<std::mutex> lock(g_rpc_mutex);
        const auto found = g_rpc_servers.find(sid);
        if (found == g_rpc_servers.end())
        {
            return false;
        }
        record = found->second.sd_ptr;
    }
    // Binding from the EE side leaves a placeholder with no function.
    t_SifRpcServerData server{};
    return record != 0u && readGuest(record, &server, sizeof(server)) && server.func != 0u;
}

bool PS2IopHostAdapter::invokeGuestFunction(uint64_t callToken,
                                            uint32_t address,
                                            uint32_t a0,
                                            uint32_t a1,
                                            uint32_t a2,
                                            uint32_t a3,
                                            uint32_t *resultAddress)
{
    (void)callToken;
    (void)address;
    (void)a0;
    (void)a1;
    (void)a2;
    (void)a3;
    if (resultAddress)
    {
        *resultAddress = 0u;
    }
    return false;
}

void PS2IopHostAdapter::log(ps2x::iop::LogLevel level, std::string_view message)
{
    const char *prefix = "[ps2xIOP]";
    if (level == ps2x::iop::LogLevel::Warning)
    {
        prefix = "[ps2xIOP:warning]";
    }
    else if (level == ps2x::iop::LogLevel::Error)
    {
        prefix = "[ps2xIOP:error]";
    }
    std::cerr << prefix << ' ' << message << std::endl;
}
