#include "iop.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace ps2x::iop::lle
{
    namespace
    {
        // About 100 us, a SIF command to the EE and its answer.
        constexpr uint64_t kSifRoundTrip = Iop::kClock / 10'000u;

        struct Binding
        {
            const char *library;
            uint16_t ordinal;
            const char *handler;
        };

        // Library ordinals as the IOP kernel exports them.
        constexpr Binding kBindings[] = {
            {"sysmem", 4, "allocSysMemory"}, {"sysmem", 5, "freeSysMemory"},
            {"sysmem", 7, "queryMaxFreeMemSize"}, {"sysmem", 8, "queryTotalFreeMemSize"},
            {"sysmem", 14, "kprintf"},
            {"loadcore", 4, "noop"}, {"loadcore", 5, "noop"},
            {"loadcore", 6, "registerLibraryEntries"}, {"loadcore", 7, "releaseLibraryEntries"},
            {"intrman", 4, "registerIntrHandler"}, {"intrman", 5, "releaseIntrHandler"},
            {"intrman", 6, "enableIntr"}, {"intrman", 7, "disableIntr"},
            {"intrman", 17, "cpuSuspendIntr"}, {"intrman", 18, "cpuResumeIntr"},
            {"intrman", 23, "queryIntrContext"},
            {"stdio", 4, "kprintf"},
            {"sysclib", 8, "lookCtypeTable"}, {"sysclib", 11, "memcmpHandler"},
            {"sysclib", 12, "memcpyHandler"}, {"sysclib", 13, "memmoveHandler"},
            {"sysclib", 14, "memsetHandler"}, {"sysclib", 17, "bzeroHandler"},
            // 19 is sprintf. The module's callers only need the literal copied; arguments are not
            // formatted here, which matches the emulator-side IopSysclib fallback for the same ordinal.
            // Before this it resolved to unknownImport and the audio module logged
            // "[iop] no kernel service for sysclib #19".
            {"sysclib", 19, "strcpyHandler"},
            {"sysclib", 22, "strcmpHandler"}, {"sysclib", 23, "strcpyHandler"},
            {"sysclib", 27, "strlenHandler"}, {"sysclib", 29, "strncmpHandler"},
            {"sysclib", 30, "strncpyHandler"}, {"sysclib", 36, "strtolHandler"},
            {"thbase", 4, "createThread"}, {"thbase", 5, "deleteThread"}, {"thbase", 6, "startThread"},
            {"thbase", 8, "exitThread"}, {"thbase", 10, "terminateThread"}, {"thbase", 11, "terminateThread"},
            {"thbase", 14, "changeThreadPriority"}, {"thbase", 15, "changeThreadPriority"},
            {"thbase", 16, "rotateThreadReadyQueue"}, {"thbase", 17, "rotateThreadReadyQueue"},
            {"thbase", 20, "getThreadId"}, {"thbase", 22, "referThreadStatus"},
            {"thbase", 23, "referThreadStatus"}, {"thbase", 24, "sleepThread"},
            {"thbase", 25, "wakeupThread"}, {"thbase", 26, "wakeupThread"},
            {"thbase", 27, "cancelWakeupThread"}, {"thbase", 28, "cancelWakeupThread"},
            {"thbase", 33, "delayThread"}, {"thbase", 34, "getSystemTime"},
            {"thbase", 35, "setAlarm"}, {"thbase", 36, "setAlarm"},
            {"thbase", 37, "cancelAlarm"}, {"thbase", 38, "cancelAlarm"},
            {"thbase", 39, "usecToSysClock"}, {"thbase", 40, "sysClockToUsec"},
            {"thsemap", 4, "createSema"}, {"thsemap", 5, "deleteSema"}, {"thsemap", 6, "signalSema"},
            {"thsemap", 7, "signalSema"}, {"thsemap", 8, "waitSema"}, {"thsemap", 9, "pollSema"},
            {"thsemap", 10, "pollSema"}, {"thsemap", 11, "referSemaStatus"}, {"thsemap", 12, "referSemaStatus"},
            {"thevent", 4, "createEventFlag"}, {"thevent", 5, "deleteEventFlag"},
            {"thevent", 6, "setEventFlag"}, {"thevent", 7, "setEventFlag"},
            {"thevent", 8, "clearEventFlag"}, {"thevent", 9, "clearEventFlag"},
            {"thevent", 10, "waitEventFlag"}, {"thevent", 11, "pollEventFlag"},
            {"thmsgbx", 4, "createMbx"}, {"thmsgbx", 5, "deleteMbx"}, {"thmsgbx", 6, "sendMbx"},
            {"thmsgbx", 7, "sendMbx"}, {"thmsgbx", 8, "receiveMbx"}, {"thmsgbx", 9, "pollMbx"},
            {"sifman", 5, "noop"}, {"sifman", 7, "sifSetDma"}, {"sifman", 8, "sifDmaStat"},
            {"sifman", 29, "sifCheckInit"},
            {"sifcmd", 4, "noop"}, {"sifcmd", 14, "noop"}, {"sifcmd", 15, "sifBindRpc"},
            {"sifcmd", 16, "sifCallRpc"}, {"sifcmd", 17, "sifRegisterRpc"}, {"sifcmd", 19, "sifSetRpcQueue"},
            {"sifcmd", 22, "sifRpcLoop"}, {"sifcmd", 23, "sifGetOtherData"}, {"sifcmd", 24, "sifRemoveRpc"},
            {"sifcmd", 25, "noop"},
            {"timrman", 4, "allocHardTimer"}, {"timrman", 6, "freeHardTimer"},
            {"timrman", 10, "getTimerCounter"}, {"timrman", 20, "setTimerHandler"},
            {"timrman", 22, "setupHardTimer"}, {"timrman", 23, "startHardTimer"},
            {"timrman", 24, "stopHardTimer"},
            // IOP file services. Modules load their data through these; without them an init that opens a
            // file stops before it registers its RPC server (LIBSD is the case in Tales of Legendia).
            {"ioman", 4, "iomanOpen"}, {"ioman", 5, "iomanClose"},
            {"ioman", 6, "iomanRead"}, {"ioman", 7, "iomanWrite"},
            {"ioman", 8, "iomanLseek"},
            {"ioman", 9, "iomanClose"}, {"ioman", 11, "iomanOpen"}, {"ioman", 12, "iomanRead"},
            {"ioman", 13, "iomanWrite"}, {"ioman", 14, "iomanLseek"},
            // The IOP has no vblank of its own. A 60 Hz counter off the IOP clock is the stand-in: IxAudio
            // polls this in a loop, and a constant 0 leaves that loop spinning forever.
            {"vblank", 5, "vblankCount"},
            // cdvdman. Ordinals are the real export numbers (confirmed against the CDVDMAN module in
            // IOPRP300.IMG and the CDVDMAN interface docs): #6 sceCdRead, #8 sceCdGetError, #11 sceCdSync,
            // #13 sceCdDiskReady, #114 _sceCdRE (the read cdvdfsv uses). The rest complete synchronously.
            {"cdvdman", 4, "cdvdInit"},          {"cdvdman", 5, "cdvdStandby"},
            {"cdvdman", 6, "cdvdRead"},          {"cdvdman", 7, "cdvdSeek"},
            {"cdvdman", 8, "cdvdGetError"},      {"cdvdman", 9, "cdvdGetToc"},
            {"cdvdman", 10, "cdvdSearchFile"},   {"cdvdman", 11, "cdvdSync"},
            {"cdvdman", 12, "cdvdGetDiskType"},  {"cdvdman", 13, "cdvdDiskReady"},
            {"cdvdman", 14, "cdvdTrayReq"},      {"cdvdman", 15, "cdvdStop"},
            {"cdvdman", 16, "cdvdPosToInt"},     {"cdvdman", 17, "cdvdIntToPos"},
            {"cdvdman", 22, "cdvdReadId"},       {"cdvdman", 24, "cdvdCallback"},
            {"cdvdman", 28, "cdvdStatus"},       {"cdvdman", 29, "cdvdOk"},
            {"cdvdman", 37, "cdvdCallback"},     {"cdvdman", 38, "cdvdPause"},
            {"cdvdman", 39, "cdvdBreak"},        {"cdvdman", 40, "cdvdOk"},
            {"cdvdman", 44, "cdvdOk"},           {"cdvdman", 45, "cdvdOk"},
            {"cdvdman", 47, "cdvdOk"},           {"cdvdman", 50, "cdvdSC"},
            {"cdvdman", 54, "cdvdOk"},           {"cdvdman", 62, "cdvdOk"},
            {"cdvdman", 63, "cdvdOk"},           {"cdvdman", 64, "cdvdOk"},
            {"cdvdman", 74, "cdvdOk"},           {"cdvdman", 75, "cdvdMmode"},
            {"cdvdman", 81, "cdvdOk"},           {"cdvdman", 83, "cdvdReadDvdDualInfo"},
            {"cdvdman", 84, "cdvdSearchFile"},   {"cdvdman", 114, "cdvdRead"},
        };

        struct Named
        {
            const char *name;
            void (Iop::*handler)(CpuContext &);
        };

        // ---------------------------------------------------------------- CDVD device
        // The title's raw sector layer talks to cdvdman, not to the EE file server: cdvdfsv calls
        // _sceCdRE/sceCdRead with an LSN and expects the bytes in IOP RAM. The host side of that is simply
        // the detected disc image (main.cpp fills IoPaths::cdImage from CDVD.000 / *.iso beside the ELF),
        // so every command completes synchronously and reads are served from the real retail layout.
        constexpr uint32_t kCdvdSectorSize = 2048u;
        constexpr uint32_t kCdvdErrorNone = 0u;
        constexpr uint32_t kCdvdErrorAbort = 0x01u;
        constexpr uint32_t kCdvdErrorRead = 0x30u;
        constexpr uint32_t kCdvdTypePs2Dvd = 0x14u;
        constexpr uint32_t kCdvdTypeUnknown = 0x05u;
        constexpr uint32_t kCdvdReadyComplete = 2u;

        struct CdvdDevice
        {
            uint64_t imageHandle = 0u;
            uint64_t imageBytes = 0u;
            uint32_t lastError = kCdvdErrorNone;
            uint32_t callback = 0u;
            uint32_t reads = 0u;
        };
        CdvdDevice g_cdvd;

        // Opens the image once and revalidates the cached handle, so a host-side reset cannot leave a
        // stale descriptor behind.
        bool cdvdOpenImage(IopHost *files, std::string &path)
        {
            if (files == nullptr)
                return false;
            path = files->hostPath(HostPathKind::CdImage);
            if (path.empty())
            {
                const std::string root = files->hostPath(HostPathKind::CdRoot);
                if (!root.empty())
                    path = root + "/CDVD.000";
            }
            if (path.empty())
                return false;
            if (g_cdvd.imageHandle != 0u && files->hostFileSize(g_cdvd.imageHandle, g_cdvd.imageBytes))
                return true;
            g_cdvd.imageHandle = files->openHostFile(path);
            g_cdvd.imageBytes = 0u;
            if (g_cdvd.imageHandle == 0u)
                return false;
            files->hostFileSize(g_cdvd.imageHandle, g_cdvd.imageBytes);
            if (std::getenv("TOL_TRACE_CDVD") != nullptr)
                std::fprintf(stderr, "[cdvd] image '%s' -> %llu bytes\n", path.c_str(),
                             static_cast<unsigned long long>(g_cdvd.imageBytes));
            return true;
        }

        bool cdvdReadImage(IopHost *files, uint64_t offset, void *destination, size_t size, size_t &read)
        {
            read = 0u;
            std::string path;
            if (!cdvdOpenImage(files, path))
                return false;
            return files->readHostFile(g_cdvd.imageHandle, offset, destination, size, read);
        }

        uint32_t cdvdReadLe32(const uint8_t *bytes)
        {
            return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
                   (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
        }

        void cdvdWriteLe32(uint8_t *bytes, uint32_t value)
        {
            bytes[0] = static_cast<uint8_t>(value);
            bytes[1] = static_cast<uint8_t>(value >> 8);
            bytes[2] = static_cast<uint8_t>(value >> 16);
            bytes[3] = static_cast<uint8_t>(value >> 24);
        }

        // ISO9660 identifiers are uppercase and carry a ";1" version suffix on files.
        std::string cdvdIsoName(std::string name)
        {
            const size_t version = name.find(';');
            if (version != std::string::npos)
                name.erase(version);
            while (name.size() > 1u && name.back() == '.')
                name.pop_back();
            for (char &ch : name)
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            return name;
        }

        std::vector<std::string> cdvdPathComponents(const std::string &path)
        {
            std::string text = path;
            const size_t colon = text.find(':');
            if (colon != std::string::npos)
                text.erase(0, colon + 1u);
            for (char &ch : text)
                if (ch == '\\')
                    ch = '/';
            std::vector<std::string> parts;
            size_t begin = 0u;
            while (begin <= text.size())
            {
                const size_t end = text.find('/', begin);
                const std::string part =
                    text.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
                if (!part.empty() && part != ".")
                {
                    if (part == "..")
                        return {};
                    parts.push_back(cdvdIsoName(part));
                }
                if (end == std::string::npos)
                    break;
                begin = end + 1u;
            }
            return parts;
        }

        struct CdvdIsoEntry
        {
            uint32_t lsn = 0u;
            uint32_t size = 0u;
            uint8_t flags = 0u;
            std::string name;
        };

        bool cdvdIsoFind(IopHost *files, uint32_t directoryLsn, uint32_t directoryBytes,
                         const std::string &wanted, CdvdIsoEntry &out)
        {
            if (directoryBytes == 0u)
                return false;
            std::vector<uint8_t> directory(directoryBytes);
            size_t read = 0u;
            if (!cdvdReadImage(files, static_cast<uint64_t>(directoryLsn) * kCdvdSectorSize, directory.data(),
                               directory.size(), read) ||
                read < directory.size())
                return false;
            size_t offset = 0u;
            while (offset + 33u <= directory.size())
            {
                const uint32_t recordBytes = directory[offset];
                if (recordBytes == 0u)
                {
                    // A record never spans a sector; zero means "rest of this sector is padding".
                    offset = ((offset / kCdvdSectorSize) + 1u) * kCdvdSectorSize;
                    continue;
                }
                if (recordBytes < 33u || recordBytes > directory.size() - offset)
                    break;
                const uint8_t *record = directory.data() + offset;
                const uint8_t nameBytes = record[32];
                if (nameBytes != 0u && 33u + nameBytes <= recordBytes)
                {
                    const uint8_t *name = record + 33u;
                    const bool self = nameBytes == 1u && (name[0] == 0u || name[0] == 1u);
                    if (!self)
                    {
                        const std::string identifier =
                            cdvdIsoName(std::string(reinterpret_cast<const char *>(name), nameBytes));
                        if (identifier == wanted)
                        {
                            out.lsn = cdvdReadLe32(record + 2u);
                            out.size = cdvdReadLe32(record + 10u);
                            out.flags = record[25];
                            out.name = identifier;
                            return true;
                        }
                    }
                }
                offset += recordBytes;
            }
            return false;
        }
    }

    void Iop::installKernel()
    {
#define PS2X_IOP_HANDLER(name)                    \
    m_handlers.push_back(&Iop::name);             \
    m_handlerLabels.emplace_back(#name);
#include "kernel_handlers.inc"
#undef PS2X_IOP_HANDLER
    }

    uint32_t Iop::handlerFor(const std::string &library, uint16_t ordinal)
    {
        static const std::vector<std::string> names = {
#define PS2X_IOP_HANDLER(name) #name,
#include "kernel_handlers.inc"
#undef PS2X_IOP_HANDLER
        };
        const auto index = [&](const char *name) {
            return static_cast<uint32_t>(std::find(names.begin(), names.end(), name) - names.begin());
        };
        if (library.empty())
            return index(ordinal == 1u ? "functionReturn" : "rpcReturn");
        for (const Binding &binding : kBindings)
            if (library == binding.library && ordinal == binding.ordinal)
                return index(binding.handler);
        m_ee.log("[iop] no kernel service for " + library + " #" + std::to_string(ordinal));
        // Give each unbound import its own handler entry so a call to it can be named later.
        m_handlers.push_back(&Iop::unknownImport);
        m_handlerLabels.push_back(library + " #" + std::to_string(ordinal));
        return static_cast<uint32_t>(m_handlers.size() - 1u);
    }

    void Iop::unknownImport(CpuContext &c)
    {
        if (std::getenv("TOL_TRACE_IOP_IMPORTS") != nullptr)
        {
            char pc[16];
            std::snprintf(pc, sizeof(pc), "%08X", c.pc);
            m_ee.log("[iop] call to unbound import " +
                     (m_lastHandler < m_handlerLabels.size() ? m_handlerLabels[m_lastHandler]
                                                             : std::string("?")) +
                     " from 0x" + pc + " a0=0x" + [&] {
                         char text[16];
                         std::snprintf(text, sizeof(text), "%08X", arg(c, 0));
                         return std::string(text);
                     }() +
                     " a1=0x" + [&] {
                         char text[16];
                         std::snprintf(text, sizeof(text), "%08X", arg(c, 1));
                         return std::string(text);
                     }() +
                     " a2=0x" + [&] {
                         char text[16];
                         std::snprintf(text, sizeof(text), "%08X", arg(c, 2));
                         return std::string(text);
                     }());
        }
        ret(c, 0);
    }
    void Iop::noop(CpuContext &c) { ret(c, 0); }

    // IOP file services. Modules that load data from the disc go through these; the host file layer does the
    // translation, so a "cdrom0:\\..." path resolves exactly as the EE side's does. Read-only for now.
    void Iop::iomanOpen(CpuContext &c)
    {
        IopHost *files = m_ee.hostFiles();
        const std::string path = readString(arg(c, 0), 256);
        if (!files || path.empty())
        {
            ret(c, static_cast<uint32_t>(-2)); // ENOENT
            return;
        }
        const uint64_t handle = files->openHostFile(files->translateGuestPath(path));
        if (handle == 0u)
        {
            ret(c, static_cast<uint32_t>(-2));
            return;
        }
        const int32_t descriptor = m_nextFileDescriptor++;
        m_openFiles[descriptor] = OpenFile{handle, 0u};
        if (std::getenv("TOL_TRACE_IOP_FILEIO") != nullptr)
            m_ee.log("[iop] ioman open '" + path + "' -> fd " + std::to_string(descriptor));
        ret(c, static_cast<uint32_t>(descriptor));
    }

    void Iop::iomanClose(CpuContext &c)
    {
        const auto found = m_openFiles.find(static_cast<int32_t>(arg(c, 0)));
        if (found == m_openFiles.end())
        {
            ret(c, static_cast<uint32_t>(-9)); // EBADF
            return;
        }
        if (IopHost *files = m_ee.hostFiles())
            files->closeHostFile(found->second.handle);
        m_openFiles.erase(found);
        ret(c, 0);
    }

    void Iop::iomanRead(CpuContext &c)
    {
        const auto found = m_openFiles.find(static_cast<int32_t>(arg(c, 0)));
        IopHost *files = m_ee.hostFiles();
        const uint32_t destination = arg(c, 1);
        const uint32_t size = arg(c, 2);
        if (found == m_openFiles.end() || !files || size == 0u)
        {
            ret(c, found == m_openFiles.end() ? static_cast<uint32_t>(-9) : 0u);
            return;
        }
        std::vector<uint8_t> data(size);
        size_t read = 0u;
        if (!files->readHostFile(found->second.handle, found->second.position, data.data(), size, read))
        {
            ret(c, static_cast<uint32_t>(-5)); // EIO
            return;
        }
        for (size_t index = 0; index < read; ++index)
            m_bus.write8(destination + static_cast<uint32_t>(index), data[index]);
        found->second.position += read;
        ret(c, static_cast<uint32_t>(read));
    }

    void Iop::iomanLseek(CpuContext &c)
    {
        const auto found = m_openFiles.find(static_cast<int32_t>(arg(c, 0)));
        if (found == m_openFiles.end())
        {
            ret(c, static_cast<uint32_t>(-9)); // EBADF
            return;
        }
        const int32_t offset = static_cast<int32_t>(arg(c, 1));
        const uint32_t whence = arg(c, 2);
        uint64_t base = 0u;
        if (whence == 1u)
            base = found->second.position;
        else if (whence == 2u && m_ee.hostFiles())
        {
            uint64_t size = 0u;
            if (m_ee.hostFiles()->hostFileSize(found->second.handle, size))
                base = size;
        }
        const int64_t target = static_cast<int64_t>(base) + offset;
        found->second.position = target < 0 ? 0u : static_cast<uint64_t>(target);
        ret(c, static_cast<uint32_t>(found->second.position));
    }

    void Iop::iomanWrite(CpuContext &c)
    {
        // The host file layer is read-only, and no module in this title writes to the disc.
        ret(c, static_cast<uint32_t>(-5)); // EIO
    }

    // ---------------------------------------------------------------- cdvdman
    // The commands are asynchronous on hardware, but the host file layer is not: they complete here and
    // sceCdSync reports "completed" immediately.

    void Iop::cdvdInit(CpuContext &c)
    {
        if (arg(c, 0) != 5u) // SCECdEXIT leaves the last error alone
            g_cdvd.lastError = kCdvdErrorNone;
        ret(c, 1u);
    }

    void Iop::cdvdStandby(CpuContext &c)
    {
        g_cdvd.lastError = kCdvdErrorNone;
        ret(c, 1u);
    }

    void Iop::cdvdStop(CpuContext &c)
    {
        g_cdvd.lastError = kCdvdErrorNone;
        ret(c, 1u);
    }

    void Iop::cdvdPause(CpuContext &c)
    {
        g_cdvd.lastError = kCdvdErrorNone;
        ret(c, 1u);
    }

    void Iop::cdvdSeek(CpuContext &c)
    {
        g_cdvd.lastError = kCdvdErrorNone;
        ret(c, 1u);
    }

    void Iop::cdvdRead(CpuContext &c)
    {
        const uint32_t lsn = arg(c, 0);
        const uint32_t sectors = arg(c, 1);
        const uint32_t destination = arg(c, 2);
        const bool trace = std::getenv("TOL_TRACE_CDVD") != nullptr;
        if (sectors == 0u)
        {
            g_cdvd.lastError = kCdvdErrorNone;
            ret(c, 1u);
            return;
        }
        const uint64_t bytes64 = static_cast<uint64_t>(sectors) * kCdvdSectorSize;
        if (bytes64 > Bus::kRamBytes || destination >= Bus::kRamBytes ||
            bytes64 > Bus::kRamBytes - static_cast<uint64_t>(destination))
        {
            g_cdvd.lastError = kCdvdErrorRead;
            if (trace)
                std::fprintf(stderr, "[cdvd] read reject=ram-range lsn=%u sectors=%u dest=0x%08X\n", lsn, sectors,
                             destination);
            ret(c, 0u);
            return;
        }

        const size_t bytes = static_cast<size_t>(bytes64);
        std::vector<uint8_t> data(bytes, 0u);
        IopHost *files = m_ee.hostFiles();
        const uint64_t offset = static_cast<uint64_t>(lsn) * kCdvdSectorSize;
        bool ok = false;
        const char *reason = "no-image";
        if (files != nullptr)
        {
            size_t read = 0u;
            if (cdvdReadImage(files, offset, data.data(), bytes, read))
            {
                if (read == bytes)
                {
                    ok = true;
                    reason = "image";
                }
                else if (read != 0u)
                {
                    // Straddles the end of our dump: the tail stays zero and the command still succeeds,
                    // because a streaming reader cannot recover from a drive error mid-transfer.
                    ok = true;
                    reason = "past-eof";
                }
                else if (offset >= g_cdvd.imageBytes)
                {
                    ok = true;
                    reason = "past-eof-zero-filled";
                }
                else
                {
                    reason = "short-read";
                }
            }
            else
            {
                reason = "read-failed";
            }
        }
        if (trace)
        {
            static uint32_t sLogs = 0u;
            if (sLogs < 40u || !ok)
            {
                ++sLogs;
                std::fprintf(stderr, "[cdvd] read lsn=%u sectors=%u dest=0x%08X image=%llu bytes ok=%d reason=%s\n",
                             lsn, sectors, destination, static_cast<unsigned long long>(g_cdvd.imageBytes),
                             ok ? 1 : 0, reason);
            }
        }
        if (!ok)
        {
            g_cdvd.lastError = kCdvdErrorRead;
            ret(c, 0u);
            return;
        }
        writeMemory(destination, data.data(), static_cast<uint32_t>(bytes));
        ++g_cdvd.reads;
        g_cdvd.lastError = kCdvdErrorNone;
        ret(c, 1u);
    }

    void Iop::cdvdGetError(CpuContext &c)
    {
        ret(c, g_cdvd.lastError);
    }

    void Iop::cdvdGetToc(CpuContext &c)
    {
        const uint32_t buffer = arg(c, 0);
        if (buffer != 0u && buffer < Bus::kRamBytes)
        {
            const uint32_t bytes = std::min<uint32_t>(1024u, Bus::kRamBytes - buffer);
            std::vector<uint8_t> toc(bytes, 0u);
            writeMemory(buffer, toc.data(), bytes);
        }
        g_cdvd.lastError = kCdvdErrorNone;
        ret(c, 1u);
    }

    void Iop::cdvdSearchFile(CpuContext &c)
    {
        const uint32_t fileAddress = arg(c, 0);
        const uint32_t nameAddress = arg(c, 1);
        const bool trace = std::getenv("TOL_TRACE_CDVD") != nullptr;
        IopHost *files = m_ee.hostFiles();
        std::string imagePath;
        if (fileAddress == 0u || !cdvdOpenImage(files, imagePath))
        {
            ret(c, 0u);
            return;
        }

        const std::string guestPath = readString(nameAddress, 256u);
        const std::vector<std::string> parts = cdvdPathComponents(guestPath);
        if (parts.empty())
        {
            if (trace)
                std::fprintf(stderr, "[cdvd] search '%s' -> empty path\n", guestPath.c_str());
            ret(c, 0u);
            return;
        }

        uint8_t primary[kCdvdSectorSize];
        size_t read = 0u;
        if (!cdvdReadImage(files, 16ull * kCdvdSectorSize, primary, sizeof(primary), read) ||
            read < sizeof(primary) || primary[0] != 1u || std::memcmp(primary + 1u, "CD001", 5u) != 0)
        {
            if (trace)
                std::fprintf(stderr, "[cdvd] search '%s' -> no ISO9660 primary volume descriptor\n",
                             guestPath.c_str());
            ret(c, 0u);
            return;
        }

        uint32_t directoryLsn = cdvdReadLe32(primary + 156u + 2u);
        uint32_t directoryBytes = cdvdReadLe32(primary + 156u + 10u);
        CdvdIsoEntry entry;
        for (size_t index = 0u; index < parts.size(); ++index)
        {
            if (!cdvdIsoFind(files, directoryLsn, directoryBytes, parts[index], entry))
            {
                if (trace)
                    std::fprintf(stderr, "[cdvd] search '%s' -> missing '%s'\n", guestPath.c_str(),
                                 parts[index].c_str());
                ret(c, 0u);
                return;
            }
            if (index + 1u < parts.size())
            {
                if ((entry.flags & 0x02u) == 0u)
                {
                    ret(c, 0u);
                    return;
                }
                directoryLsn = entry.lsn;
                directoryBytes = entry.size;
            }
        }

        // sceCdlFILE: lsn, size, name[16], date/flags[8].
        uint8_t result[32] = {};
        cdvdWriteLe32(result + 0u, entry.lsn);
        cdvdWriteLe32(result + 4u, entry.size);
        std::memcpy(result + 8u, entry.name.data(), std::min<size_t>(16u, entry.name.size()));
        result[24] = (entry.flags & 0x02u) ? 2u : 0u;
        writeMemory(fileAddress, result, sizeof(result));
        g_cdvd.lastError = kCdvdErrorNone;
        if (trace)
            std::fprintf(stderr, "[cdvd] search '%s' -> lsn=%u size=%u\n", guestPath.c_str(), entry.lsn,
                         entry.size);
        ret(c, 1u);
    }

    void Iop::cdvdSync(CpuContext &c)
    {
        (void)c;
        ret(c, 0u); // completed
    }

    void Iop::cdvdGetDiskType(CpuContext &c)
    {
        IopHost *files = m_ee.hostFiles();
        std::string imagePath;
        ret(c, cdvdOpenImage(files, imagePath) ? kCdvdTypePs2Dvd : kCdvdTypeUnknown);
    }

    void Iop::cdvdDiskReady(CpuContext &c)
    {
        (void)c;
        ret(c, kCdvdReadyComplete);
    }

    void Iop::cdvdTrayReq(CpuContext &c)
    {
        if (arg(c, 1) != 0u)
            m_bus.write32(arg(c, 1), 0u);
        ret(c, 1u);
    }

    void Iop::cdvdStatus(CpuContext &c)
    {
        (void)c;
        ret(c, 0x02u); // spinning / ready
    }

    void Iop::cdvdCallback(CpuContext &c)
    {
        const uint32_t previous = g_cdvd.callback;
        g_cdvd.callback = arg(c, 0);
        ret(c, previous);
    }

    void Iop::cdvdBreak(CpuContext &c)
    {
        (void)c;
        g_cdvd.lastError = kCdvdErrorAbort;
        ret(c, 1u);
    }

    void Iop::cdvdSC(CpuContext &c)
    {
        // Internal control channel used by cdvdfsv. The values mirror the HLE cdvd implementation:
        // timeouts, the drive's event-flag id, the module version, and the last error code.
        const int32_t code = static_cast<int32_t>(arg(c, 0));
        const uint32_t param = arg(c, 1);
        switch (code)
        {
        case -23: // translate a logical sector
            ret(c, param != 0u ? m_bus.read32(param) : 0u);
            return;
        case -18: // set the read timeout
            ret(c, 0u);
            return;
        case -17: // get the streaming timeout
            ret(c, 0x1000u);
            return;
        case -15: // get the sync timeout
            ret(c, 0x1000u);
            return;
        case -11: // interrupt event-flag id (0: none)
            ret(c, 0u);
            return;
        case -9: // module version (PsIIcdvdman 300a)
            ret(c, 0x300Au);
            return;
        case -2: // push an error into the driver
            if (param != 0u)
                g_cdvd.lastError = m_bus.read8(param);
            ret(c, g_cdvd.lastError);
            return;
        case -1:
        case 0:
        case 1:
        case 2:
            if (param != 0u)
                m_bus.write32(param, g_cdvd.lastError & 0xFFu);
            ret(c, 0u);
            return;
        default:
            ret(c, 0u);
            return;
        }
    }

    void Iop::cdvdMmode(CpuContext &c)
    {
        (void)c;
        ret(c, 1u);
    }

    void Iop::cdvdReadDvdDualInfo(CpuContext &c)
    {
        if (arg(c, 0) != 0u)
            m_bus.write32(arg(c, 0), 0u);
        if (arg(c, 1) != 0u)
            m_bus.write32(arg(c, 1), 0u);
        ret(c, 1u);
    }

    void Iop::cdvdPosToInt(CpuContext &c)
    {
        const uint32_t address = arg(c, 0);
        const auto bcd = [](uint8_t value) -> uint32_t
        { return (value >> 4) * 10u + (value & 0x0Fu); };
        const uint32_t minute = bcd(m_bus.read8(address + 0u));
        const uint32_t second = bcd(m_bus.read8(address + 1u));
        const uint32_t sector = bcd(m_bus.read8(address + 2u));
        const uint32_t lsn = (minute * 60u + second) * 75u + sector;
        ret(c, lsn >= 150u ? lsn - 150u : 0u);
    }

    void Iop::cdvdIntToPos(CpuContext &c)
    {
        const uint32_t address = arg(c, 1);
        const auto bcd = [](uint32_t value) -> uint8_t
        { return static_cast<uint8_t>(((value / 10u) << 4) | (value % 10u)); };
        const uint32_t lsn = arg(c, 0) + 150u;
        m_bus.write8(address + 0u, bcd((lsn / 75u) / 60u));
        m_bus.write8(address + 1u, bcd((lsn / 75u) % 60u));
        m_bus.write8(address + 2u, bcd(lsn % 75u));
        m_bus.write8(address + 3u, 0u);
        ret(c, address);
    }

    void Iop::cdvdReadId(CpuContext &c)
    {
        const uint32_t buffer = arg(c, 0);
        for (uint32_t index = 0u; index < 8u; ++index)
            m_bus.write8(buffer + index, 0u);
        if (arg(c, 1) != 0u)
            m_bus.write32(arg(c, 1), 0u);
        ret(c, 1u);
    }

    void Iop::cdvdOk(CpuContext &c)
    {
        (void)c;
        ret(c, 1u);
    }

    void Iop::vblankCount(CpuContext &c)
    {
        // 60 Hz off the IOP clock (36.864 MHz). Modules that wait for the count to change now progress.
        ret(c, static_cast<uint32_t>((m_cycle * 60u) / kClock));
    }

    void Iop::functionReturn(CpuContext &c)
    {
        // A thread's entry function returned: that is ExitThread.
        Thread *thread = current();
        if (!thread)
            return;
        if (thread->id == m_loaderThread)
            m_loaderResult = c.gpr[2];
        thread->dormant = true;
        reschedule();
    }

    void Iop::rpcReturn(CpuContext &c)
    {
        if (Thread *thread = current())
            finishRequest(*thread, c.gpr[2]);
    }

    // ---------------------------------------------------------------- sysmem, loadcore, stdio

    void Iop::allocSysMemory(CpuContext &c) { ret(c, allocate(arg(c, 1))); }

    void Iop::freeSysMemory(CpuContext &c)
    {
        release(arg(c, 0));
        ret(c, 0);
    }

    void Iop::queryMaxFreeMemSize(CpuContext &c)
    {
        uint32_t largest = 0, cursor = 0;
        for (const auto &[address, length] : m_allocations)
        {
            largest = std::max(largest, address > cursor ? address - cursor : 0u);
            cursor = std::max(cursor, address + length);
        }
        ret(c, std::max(largest, Bus::kRamBytes - cursor));
    }

    void Iop::queryTotalFreeMemSize(CpuContext &c)
    {
        uint32_t used = 0;
        for (const auto &[address, length] : m_allocations)
            used += length;
        ret(c, Bus::kRamBytes - used);
    }

    void Iop::kprintf(CpuContext &c)
    {
        // Modules log through this; formatting the common conversions makes their diagnostics readable
        // (the driver messages that matter name a device or an error code).
        const std::string format = readString(arg(c, 0));
        std::string text;
        unsigned argument = 1u;
        for (size_t index = 0u; index < format.size(); ++index)
        {
            if (format[index] != '%' || index + 1u >= format.size())
            {
                text.push_back(format[index]);
                continue;
            }
            size_t next = index + 1u;
            if (format[next] == '%')
            {
                text.push_back('%');
                index = next;
                continue;
            }
            bool zeroPad = false;
            bool leftPad = false;
            while (next < format.size() && (format[next] == '0' || format[next] == '-'))
            {
                zeroPad = zeroPad || format[next] == '0';
                leftPad = leftPad || format[next] == '-';
                ++next;
            }
            unsigned width = 0u;
            while (next < format.size() && format[next] >= '0' && format[next] <= '9')
            {
                width = width * 10u + static_cast<unsigned>(format[next] - '0');
                ++next;
            }
            while (next < format.size() && (format[next] == 'l' || format[next] == 'h'))
                ++next;
            if (next >= format.size())
                break;
            const char conversion = format[next];
            const uint32_t value = arg(c, argument++);
            char buffer[32];
            if (conversion == 's')
            {
                text += readString(value, 256u);
            }
            else if (conversion == 'c')
            {
                text.push_back(static_cast<char>(value & 0xFFu));
            }
            else if (conversion == 'x' || conversion == 'X' || conversion == 'p')
            {
                std::snprintf(buffer, sizeof(buffer), zeroPad ? "%0*x" : "%*x", static_cast<int>(width), value);
                text += buffer;
            }
            else if (conversion == 'd' || conversion == 'i' || conversion == 'u')
            {
                const long long signedValue = static_cast<int32_t>(value);
                std::snprintf(buffer, sizeof(buffer), zeroPad ? "%0*lld" : "%*lld",
                              static_cast<int>(width), conversion == 'u' ? static_cast<long long>(value) : signedValue);
                text += buffer;
            }
            else
            {
                text.push_back('%');
                text.push_back(conversion);
            }
            index = next;
        }
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
            text.pop_back();
        if (!text.empty())
            m_ee.log("[iop] " + text);
        ret(c, 0);
    }

    void Iop::registerLibraryEntries(CpuContext &c)
    {
        const uint32_t table = arg(c, 0);
        std::string name;
        for (uint32_t index = 0; index < 8u; ++index)
        {
            const uint8_t ch = m_bus.read8(table + 12u + index);
            if (ch == 0u)
                break;
            name.push_back(static_cast<char>(ch));
        }
        // The export table's first slots are reserved and hold zero; the real function list follows and is
        // terminated by a zero. Stopping at the first zero (as an import table would) registers no functions
        // at all, which silently disabled every module's exports.
        std::vector<uint32_t> functions;
        bool sawFunction = false;
        for (uint32_t entry = table + 20u; entry < table + 20u + 4096u; entry += 4u)
        {
            const uint32_t address = m_bus.read32(entry);
            if (address == 0u)
            {
                if (sawFunction)
                    break;
                functions.push_back(0u); // reserved ordinal
                continue;
            }
            sawFunction = true;
            functions.push_back(address);
        }
        m_exports[name] = std::move(functions);
        ret(c, 0);
    }

    void Iop::releaseLibraryEntries(CpuContext &c) { ret(c, 0); }

    // ---------------------------------------------------------------- intrman

    void Iop::registerIntrHandler(CpuContext &c)
    {
        Interrupt &line = m_interrupts[arg(c, 0)];
        line.mode = arg(c, 1);
        line.handler = arg(c, 2);
        line.argument = arg(c, 3);
        line.gp = c.gpr[28];
        ret(c, 0);
    }

    void Iop::releaseIntrHandler(CpuContext &c)
    {
        m_interrupts.erase(arg(c, 0));
        ret(c, 0);
    }

    void Iop::enableIntr(CpuContext &c)
    {
        m_interrupts[arg(c, 0) & 0xFFu].enabled = true;
        ret(c, 0);
    }

    void Iop::disableIntr(CpuContext &c)
    {
        auto &line = m_interrupts[arg(c, 0) & 0xFFu];
        if (arg(c, 1) != 0u)
            m_bus.write32(arg(c, 1), line.enabled ? arg(c, 0) : 0u);
        line.enabled = false;
        ret(c, 0);
    }

    void Iop::cpuSuspendIntr(CpuContext &c)
    {
        if (arg(c, 0) != 0u)
            m_bus.write32(arg(c, 0), m_intrSuspend > 0 ? 0u : 1u);
        ++m_intrSuspend;
        ret(c, m_intrSuspend > 1 ? static_cast<uint32_t>(-102) : 0u); // KE_CPUDI when already off
    }

    void Iop::cpuResumeIntr(CpuContext &c)
    {
        if (arg(c, 0) != 0u && m_intrSuspend > 0)
            m_intrSuspend = 0;
        else if (m_intrSuspend > 0)
            --m_intrSuspend;
        ret(c, 0);
    }

    void Iop::queryIntrContext(CpuContext &c) { ret(c, m_inInterrupt ? 1u : 0u); }

    // ---------------------------------------------------------------- sysclib

    void Iop::lookCtypeTable(CpuContext &c)
    {
        // Returns the class of one character, as the table lookup would.
        ret(c, m_bus.read8(m_ctypeTable + 1u + (arg(c, 0) & 0xFFu)));
    }

    void Iop::memcpyHandler(CpuContext &c)
    {
        const uint32_t destination = arg(c, 0), source = arg(c, 1), size = arg(c, 2);
        for (uint32_t index = 0; index < size; ++index)
            m_bus.write8(destination + index, m_bus.read8(source + index));
        ret(c, destination);
    }

    void Iop::memmoveHandler(CpuContext &c)
    {
        const uint32_t destination = arg(c, 0), source = arg(c, 1), size = arg(c, 2);
        std::vector<uint8_t> copy(size);
        for (uint32_t index = 0; index < size; ++index)
            copy[index] = m_bus.read8(source + index);
        for (uint32_t index = 0; index < size; ++index)
            m_bus.write8(destination + index, copy[index]);
        ret(c, destination);
    }

    void Iop::memsetHandler(CpuContext &c)
    {
        const uint32_t destination = arg(c, 0), size = arg(c, 2);
        for (uint32_t index = 0; index < size; ++index)
            m_bus.write8(destination + index, static_cast<uint8_t>(arg(c, 1)));
        ret(c, destination);
    }

    void Iop::memcmpHandler(CpuContext &c)
    {
        int32_t result = 0;
        for (uint32_t index = 0; index < arg(c, 2) && result == 0; ++index)
            result = static_cast<int32_t>(m_bus.read8(arg(c, 0) + index)) - m_bus.read8(arg(c, 1) + index);
        ret(c, static_cast<uint32_t>(result));
    }

    void Iop::bzeroHandler(CpuContext &c)
    {
        for (uint32_t index = 0; index < arg(c, 1); ++index)
            m_bus.write8(arg(c, 0) + index, 0u);
        ret(c, 0);
    }

    void Iop::strlenHandler(CpuContext &c) { ret(c, static_cast<uint32_t>(readString(arg(c, 0), 65536).size())); }

    void Iop::strcmpHandler(CpuContext &c)
    {
        ret(c, static_cast<uint32_t>(readString(arg(c, 0), 65536).compare(readString(arg(c, 1), 65536))));
    }

    void Iop::strncmpHandler(CpuContext &c)
    {
        const uint32_t count = arg(c, 2);
        const std::string a = readString(arg(c, 0), count), b = readString(arg(c, 1), count);
        ret(c, static_cast<uint32_t>(a.compare(b)));
    }

    void Iop::strcpyHandler(CpuContext &c)
    {
        const std::string text = readString(arg(c, 1), 65536);
        writeMemory(arg(c, 0), text.c_str(), static_cast<uint32_t>(text.size()) + 1u);
        ret(c, arg(c, 0));
    }

    void Iop::strncpyHandler(CpuContext &c)
    {
        const uint32_t count = arg(c, 2);
        std::string text = readString(arg(c, 1), count);
        text.resize(count, '\0');
        writeMemory(arg(c, 0), text.data(), count);
        ret(c, arg(c, 0));
    }

    void Iop::strtolHandler(CpuContext &c)
    {
        const uint32_t start = arg(c, 0);
        const std::string text = readString(start, 64);
        char *end = nullptr;
        const long value = std::strtol(text.c_str(), &end, static_cast<int>(arg(c, 2)));
        if (arg(c, 1) != 0u)
            m_bus.write32(arg(c, 1), start + static_cast<uint32_t>(end - text.c_str()));
        ret(c, static_cast<uint32_t>(value));
    }

    // ---------------------------------------------------------------- threads

    void Iop::createThread(CpuContext &c)
    {
        const uint32_t param = arg(c, 0);
        Thread thread;
        thread.id = m_nextId++;
        thread.attr = m_bus.read32(param);
        thread.option = m_bus.read32(param + 4u);
        thread.entry = m_bus.read32(param + 8u);
        thread.stackSize = (m_bus.read32(param + 12u) + 15u) & ~15u;
        thread.priority = thread.initialPriority = static_cast<int32_t>(m_bus.read32(param + 16u));
        thread.stackBase = allocate(thread.stackSize);
        thread.gp = c.gpr[28];
        if (thread.stackBase == 0u)
        {
            ret(c, static_cast<uint32_t>(-400)); // KE_NO_MEMORY
            return;
        }
        m_threads[thread.id] = thread;
        if (std::getenv("TOL_TRACE_IOP_THREADS") != nullptr)
        {
            m_ee.log("[iop] thread " + std::to_string(thread.id) + " created entry=0x" +
                     [&] {
                         char text[16];
                         std::snprintf(text, sizeof(text), "%08X", thread.entry);
                         return std::string(text);
                     }() +
                     " prio=" + std::to_string(thread.priority));
        }
        ret(c, static_cast<uint32_t>(thread.id));
    }

    void Iop::deleteThread(CpuContext &c)
    {
        const auto found = m_threads.find(static_cast<int32_t>(arg(c, 0)));
        if (found == m_threads.end() || !found->second.dormant)
        {
            ret(c, static_cast<uint32_t>(-407));
            return;
        }
        release(found->second.stackBase);
        m_threads.erase(found);
        ret(c, 0);
    }

    void Iop::startThread(CpuContext &c)
    {
        const auto found = m_threads.find(static_cast<int32_t>(arg(c, 0)));
        if (found == m_threads.end())
        {
            ret(c, static_cast<uint32_t>(-407));
            return;
        }
        Thread &thread = found->second;
        thread.context = {};
        thread.context.pc = thread.entry;
        thread.context.gpr[4] = arg(c, 1);
        thread.context.gpr[28] = thread.gp;
        thread.context.gpr[29] = thread.stackBase + thread.stackSize - 16u;
        thread.context.gpr[31] = m_returnTrap;
        thread.priority = thread.initialPriority;
        thread.dormant = false;
        thread.wakeupCount = 0;
        makeReady(thread, 0u);
        if (std::getenv("TOL_TRACE_IOP_THREADS") != nullptr)
        {
            m_ee.log("[iop] thread " + std::to_string(thread.id) + " started");
        }
        ret(c, 0);
    }

    void Iop::exitThread(CpuContext &c)
    {
        (void)c;
        if (Thread *thread = current())
        {
            thread->dormant = true;
            reschedule();
        }
    }

    void Iop::terminateThread(CpuContext &c)
    {
        const auto found = m_threads.find(static_cast<int32_t>(arg(c, 0)));
        if (found != m_threads.end())
        {
            found->second.dormant = true;
            found->second.wait = Wait::None;
            m_active.erase(found->first);
        }
        ret(c, 0);
    }

    void Iop::changeThreadPriority(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        const auto found = m_threads.find(id == 0 ? m_current : id);
        if (found != m_threads.end())
        {
            const int32_t priority = static_cast<int32_t>(arg(c, 1));
            found->second.priority = priority == 0 ? found->second.initialPriority : priority;
            reschedule();
        }
        ret(c, 0);
    }

    void Iop::rotateThreadReadyQueue(CpuContext &c)
    {
        if (Thread *thread = current())
            thread->readySequence = ++m_readySequence;
        reschedule();
        ret(c, 0);
    }

    void Iop::getThreadId(CpuContext &c) { ret(c, static_cast<uint32_t>(m_current)); }

    void Iop::referThreadStatus(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        const auto found = m_threads.find(id == 0 ? m_current : id);
        const uint32_t info = arg(c, 1);
        if (found == m_threads.end() || info == 0u)
        {
            ret(c, static_cast<uint32_t>(-407));
            return;
        }
        const Thread &thread = found->second;
        // struct _iop_thread_status: attr, option, status, entry, stack, stackSize,
        // gpReg, initPriority, currentPriority, waitType, waitId, wakeupCount, ...
        const uint32_t status = thread.dormant ? 0x10u : thread.wait != Wait::None ? 0x04u
                                                : thread.id == m_current ? 0x01u : 0x02u;
        const uint32_t fields[12] = {thread.attr, thread.option, status, thread.entry, thread.stackBase,
                                     thread.stackSize, thread.gp, static_cast<uint32_t>(thread.initialPriority),
                                     static_cast<uint32_t>(thread.priority), 0u, static_cast<uint32_t>(thread.waitId),
                                     static_cast<uint32_t>(thread.wakeupCount)};
        for (uint32_t index = 0; index < 12u; ++index)
            m_bus.write32(info + index * 4u, fields[index]);
        ret(c, 0);
    }

    void Iop::sleepThread(CpuContext &c)
    {
        Thread *thread = current();
        if (thread && thread->wakeupCount > 0)
        {
            --thread->wakeupCount;
            ret(c, 0);
            return;
        }
        ret(c, 0);
        block(Wait::Sleep, 0);
    }

    void Iop::wakeupThread(CpuContext &c)
    {
        const auto found = m_threads.find(static_cast<int32_t>(arg(c, 0)));
        if (found == m_threads.end())
        {
            ret(c, static_cast<uint32_t>(-407));
            return;
        }
        if (found->second.wait == Wait::Sleep)
            makeReady(found->second, 0u);
        else
            ++found->second.wakeupCount;
        ret(c, 0);
    }

    void Iop::cancelWakeupThread(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        const auto found = m_threads.find(id == 0 ? m_current : id);
        int32_t count = 0;
        if (found != m_threads.end())
        {
            count = found->second.wakeupCount;
            found->second.wakeupCount = 0;
        }
        ret(c, static_cast<uint32_t>(count));
    }

    void Iop::delayThread(CpuContext &c)
    {
        Thread *thread = current();
        if (!thread)
            return;
        thread->wakeCycle = m_cycle + static_cast<uint64_t>(arg(c, 0)) * kClock / 1'000'000u;
        ret(c, 0);
        block(Wait::Delay, 0);
    }

    void Iop::getSystemTime(CpuContext &c)
    {
        m_bus.write32(arg(c, 0), static_cast<uint32_t>(m_cycle));
        m_bus.write32(arg(c, 0) + 4u, static_cast<uint32_t>(m_cycle >> 32));
        ret(c, 0);
    }

    void Iop::setAlarm(CpuContext &c)
    {
        // The clock argument points at an iop_sys_clock_t.
        const uint64_t clock = m_bus.read32(arg(c, 0)) | (static_cast<uint64_t>(m_bus.read32(arg(c, 0) + 4u)) << 32);
        m_alarms.emplace(arg(c, 1), Alarm{m_cycle + clock, arg(c, 1), arg(c, 2), c.gpr[28]});
        ret(c, 0);
    }

    void Iop::cancelAlarm(CpuContext &c)
    {
        const auto range = m_alarms.equal_range(arg(c, 0));
        for (auto it = range.first; it != range.second;)
            it = it->second.argument == arg(c, 1) ? m_alarms.erase(it) : std::next(it);
        ret(c, 0);
    }

    void Iop::usecToSysClock(CpuContext &c)
    {
        const uint64_t clock = static_cast<uint64_t>(arg(c, 0)) * kClock / 1'000'000u;
        m_bus.write32(arg(c, 1), static_cast<uint32_t>(clock));
        m_bus.write32(arg(c, 1) + 4u, static_cast<uint32_t>(clock >> 32));
        ret(c, 0);
    }

    void Iop::sysClockToUsec(CpuContext &c)
    {
        const uint64_t clock = m_bus.read32(arg(c, 0)) | (static_cast<uint64_t>(m_bus.read32(arg(c, 0) + 4u)) << 32);
        const uint64_t usec = clock * 1'000'000u / kClock;
        m_bus.write32(arg(c, 1), static_cast<uint32_t>(usec / 1'000'000u));
        m_bus.write32(arg(c, 2), static_cast<uint32_t>(usec % 1'000'000u));
        ret(c, 0);
    }

    // ---------------------------------------------------------------- semaphores

    void Iop::createSema(CpuContext &c)
    {
        const uint32_t param = arg(c, 0);
        Semaphore semaphore;
        semaphore.attr = m_bus.read32(param);
        semaphore.option = m_bus.read32(param + 4u);
        semaphore.count = static_cast<int32_t>(m_bus.read32(param + 8u));
        semaphore.maximum = static_cast<int32_t>(m_bus.read32(param + 12u));
        const int32_t id = m_nextId++;
        m_semaphores[id] = semaphore;
        traceSema("create", id, c.pc);
        ret(c, static_cast<uint32_t>(id));
    }

    void Iop::traceSema(const char *op, int32_t id, uint32_t pc)
    {
        if (std::getenv("TOL_TRACE_IOP_SEMA") == nullptr)
            return;
        static uint32_t sLines = 0u;
        if (sLines++ > 4000u)
            return;
        const auto found = m_semaphores.find(id);
        const int32_t count = found == m_semaphores.end() ? -999 : found->second.count;
        const int32_t maximum = found == m_semaphores.end() ? -999 : found->second.maximum;
        int32_t waiters = 0;
        for (const auto &[threadId, thread] : m_threads)
            waiters += thread.wait == Wait::Semaphore && thread.waitId == id ? 1 : 0;
        Thread *thread = current();
        char text[16];
        std::snprintf(text, sizeof(text), "%08X", pc);
        m_ee.log("[iop] sema " + std::to_string(id) + " " + op + " by thread " +
                 std::to_string(thread ? thread->id : 0) + " at 0x" + text + " count=" +
                 std::to_string(count) + "/" + std::to_string(maximum) + " waiters=" +
                 std::to_string(waiters));
    }

    void Iop::deleteSema(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        for (auto &[threadId, thread] : m_threads)
            if (thread.wait == Wait::Semaphore && thread.waitId == id)
                makeReady(thread, static_cast<uint32_t>(-425)); // KE_WAIT_DELETE
        m_semaphores.erase(id);
        traceSema("delete", id, c.pc);
        ret(c, 0);
    }

    void Iop::signalSema(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        const auto found = m_semaphores.find(id);
        if (found == m_semaphores.end())
        {
            ret(c, static_cast<uint32_t>(-408));
            return;
        }
        // Wake the longest-waiting thread, or count the signal.
        Thread *waiter = nullptr;
        for (auto &[threadId, thread] : m_threads)
            if (thread.wait == Wait::Semaphore && thread.waitId == id &&
                (!waiter || thread.readySequence < waiter->readySequence))
                waiter = &thread;
        if (waiter)
            makeReady(*waiter, 0u);
        else if (found->second.count < found->second.maximum || found->second.maximum == 0)
            ++found->second.count;
        traceSema("signal", id, c.pc);
        ret(c, 0);
    }

    void Iop::waitSema(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        const auto found = m_semaphores.find(id);
        if (found == m_semaphores.end())
        {
            ret(c, static_cast<uint32_t>(-408));
            return;
        }
        if (found->second.count > 0)
        {
            --found->second.count;
            ret(c, 0);
            return;
        }
        if (Thread *thread = current())
            thread->readySequence = ++m_readySequence;
        traceSema("wait", id, c.pc);
        ret(c, 0);
        block(Wait::Semaphore, id);
    }

    void Iop::pollSema(CpuContext &c)
    {
        const auto found = m_semaphores.find(static_cast<int32_t>(arg(c, 0)));
        if (found == m_semaphores.end() || found->second.count <= 0)
        {
            ret(c, static_cast<uint32_t>(-419)); // KE_SEMA_ZERO
            return;
        }
        --found->second.count;
        traceSema("poll", static_cast<int32_t>(arg(c, 0)), c.pc);
        ret(c, 0);
    }

    void Iop::referSemaStatus(CpuContext &c)
    {
        const auto found = m_semaphores.find(static_cast<int32_t>(arg(c, 0)));
        if (found == m_semaphores.end())
        {
            ret(c, static_cast<uint32_t>(-408));
            return;
        }
        int32_t waiting = 0;
        for (const auto &[threadId, thread] : m_threads)
            waiting += thread.wait == Wait::Semaphore && thread.waitId == found->first ? 1 : 0;
        const uint32_t info = arg(c, 1);
        const uint32_t fields[6] = {found->second.attr, found->second.option, 0u,
                                    static_cast<uint32_t>(found->second.maximum),
                                    static_cast<uint32_t>(found->second.count), static_cast<uint32_t>(waiting)};
        for (uint32_t index = 0; index < 6u; ++index)
            m_bus.write32(info + index * 4u, fields[index]);
        ret(c, 0);
    }

    // ---------------------------------------------------------------- event flags

    void Iop::createEventFlag(CpuContext &c)
    {
        const uint32_t param = arg(c, 0);
        EventFlag flag;
        flag.attr = m_bus.read32(param);
        flag.option = m_bus.read32(param + 4u);
        flag.bits = m_bus.read32(param + 8u);
        const int32_t id = m_nextId++;
        m_eventFlags[id] = flag;
        traceEventFlag("create", id, c.pc);
        ret(c, static_cast<uint32_t>(id));
    }

    void Iop::traceEventFlag(const char *op, int32_t id, uint32_t pc)
    {
        if (std::getenv("TOL_TRACE_IOP_SEMA") == nullptr)
            return;
        static uint32_t sLines = 0u;
        if (sLines++ > 4000u)
            return;
        const auto found = m_eventFlags.find(id);
        const uint32_t bits = found == m_eventFlags.end() ? 0xDEADBEEFu : found->second.bits;
        int32_t waiters = 0;
        for (const auto &[threadId, thread] : m_threads)
            waiters += thread.wait == Wait::EventFlag && thread.waitId == id ? 1 : 0;
        Thread *thread = current();
        char text[16];
        char mask[16];
        std::snprintf(text, sizeof(text), "%08X", pc);
        std::snprintf(mask, sizeof(mask), "%08X", bits);
        m_ee.log("[iop] evflag " + std::to_string(id) + " " + op + " by thread " +
                 std::to_string(thread ? thread->id : 0) + " at 0x" + text + " bits=0x" + mask +
                 " waiters=" + std::to_string(waiters));
    }

    void Iop::deleteEventFlag(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        for (auto &[threadId, thread] : m_threads)
            if (thread.wait == Wait::EventFlag && thread.waitId == id)
                makeReady(thread, static_cast<uint32_t>(-425));
        m_eventFlags.erase(id);
        ret(c, 0);
    }

    void Iop::setEventFlag(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        const auto found = m_eventFlags.find(id);
        if (found == m_eventFlags.end())
        {
            ret(c, static_cast<uint32_t>(-409));
            return;
        }
        EventFlag &flag = found->second;
        flag.bits |= arg(c, 1);
        traceEventFlag("set", id, c.pc);
        for (auto &[threadId, thread] : m_threads)
        {
            if (thread.wait != Wait::EventFlag || thread.waitId != id)
                continue;
            // Mode bit 0: OR (any bit) instead of AND; 0x10 clear all, 0x20 clear pattern.
            const bool satisfied = (thread.waitMode & 1u) ? (flag.bits & thread.waitBits) != 0u
                                                          : (flag.bits & thread.waitBits) == thread.waitBits;
            if (!satisfied)
                continue;
            if (thread.waitResult != 0u)
                m_bus.write32(thread.waitResult, flag.bits);
            if (thread.waitMode & 0x10u)
                flag.bits = 0;
            else if (thread.waitMode & 0x20u)
                flag.bits &= ~thread.waitBits;
            makeReady(thread, 0u);
        }
        ret(c, 0);
    }

    void Iop::clearEventFlag(CpuContext &c)
    {
        const auto found = m_eventFlags.find(static_cast<int32_t>(arg(c, 0)));
        if (found != m_eventFlags.end())
            found->second.bits &= arg(c, 1);
        traceEventFlag("clear", static_cast<int32_t>(arg(c, 0)), c.pc);
        ret(c, 0);
    }

    void Iop::waitEventFlag(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        const auto found = m_eventFlags.find(id);
        if (found == m_eventFlags.end())
        {
            ret(c, static_cast<uint32_t>(-409));
            return;
        }
        EventFlag &flag = found->second;
        const uint32_t bits = arg(c, 1), mode = arg(c, 2), result = arg(c, 3);
        const bool satisfied = (mode & 1u) ? (flag.bits & bits) != 0u : (flag.bits & bits) == bits;
        if (satisfied)
        {
            if (result != 0u)
                m_bus.write32(result, flag.bits);
            if (mode & 0x10u)
                flag.bits = 0;
            else if (mode & 0x20u)
                flag.bits &= ~bits;
            traceEventFlag("wait-ok", id, c.pc);
            ret(c, 0);
            return;
        }
        if (Thread *thread = current())
        {
            thread->waitBits = bits;
            thread->waitMode = mode;
            thread->waitResult = result;
        }
        traceEventFlag("wait-block", id, c.pc);
        ret(c, 0);
        block(Wait::EventFlag, id);
    }

    void Iop::pollEventFlag(CpuContext &c)
    {
        const auto found = m_eventFlags.find(static_cast<int32_t>(arg(c, 0)));
        if (found == m_eventFlags.end())
        {
            ret(c, static_cast<uint32_t>(-409));
            return;
        }
        EventFlag &flag = found->second;
        const uint32_t bits = arg(c, 1), mode = arg(c, 2), result = arg(c, 3);
        const bool satisfied = (mode & 1u) ? (flag.bits & bits) != 0u : (flag.bits & bits) == bits;
        if (!satisfied)
        {
            ret(c, static_cast<uint32_t>(-421)); // KE_EVF_COND
            return;
        }
        if (result != 0u)
            m_bus.write32(result, flag.bits);
        if (mode & 0x10u)
            flag.bits = 0;
        else if (mode & 0x20u)
            flag.bits &= ~bits;
        ret(c, 0);
    }

    // ---------------------------------------------------------------- message boxes

    void Iop::createMbx(CpuContext &c)
    {
        Mailbox mailbox;
        mailbox.attr = m_bus.read32(arg(c, 0));
        mailbox.option = m_bus.read32(arg(c, 0) + 4u);
        const int32_t id = m_nextId++;
        m_mailboxes[id] = mailbox;
        ret(c, static_cast<uint32_t>(id));
    }

    void Iop::deleteMbx(CpuContext &c)
    {
        m_mailboxes.erase(static_cast<int32_t>(arg(c, 0)));
        ret(c, 0);
    }

    void Iop::sendMbx(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 0));
        const auto found = m_mailboxes.find(id);
        if (found == m_mailboxes.end())
        {
            ret(c, static_cast<uint32_t>(-410));
            return;
        }
        for (auto &[threadId, thread] : m_threads)
            if (thread.wait == Wait::Mailbox && thread.waitId == id)
            {
                m_bus.write32(thread.waitResult, arg(c, 1));
                makeReady(thread, 0u);
                ret(c, 0);
                return;
            }
        found->second.messages.push_back(arg(c, 1));
        ret(c, 0);
    }

    void Iop::receiveMbx(CpuContext &c)
    {
        const int32_t id = static_cast<int32_t>(arg(c, 1));
        const auto found = m_mailboxes.find(id);
        if (found == m_mailboxes.end())
        {
            ret(c, static_cast<uint32_t>(-410));
            return;
        }
        if (!found->second.messages.empty())
        {
            m_bus.write32(arg(c, 0), found->second.messages.front());
            found->second.messages.pop_front();
            ret(c, 0);
            return;
        }
        if (Thread *thread = current())
            thread->waitResult = arg(c, 0);
        ret(c, 0);
        block(Wait::Mailbox, id);
    }

    void Iop::pollMbx(CpuContext &c)
    {
        const auto found = m_mailboxes.find(static_cast<int32_t>(arg(c, 1)));
        if (found == m_mailboxes.end() || found->second.messages.empty())
        {
            ret(c, static_cast<uint32_t>(-424)); // KE_MBOX_NOMSG
            return;
        }
        m_bus.write32(arg(c, 0), found->second.messages.front());
        found->second.messages.pop_front();
        ret(c, 0);
    }

    // ---------------------------------------------------------------- SIF

    void Iop::sifSetDma(CpuContext &c)
    {
        // Each descriptor: IOP source, EE destination, size, attributes.
        const uint32_t list = arg(c, 0), count = arg(c, 1);
        for (uint32_t index = 0; index < count; ++index)
        {
            const uint32_t entry = list + index * 16u;
            const uint32_t source = m_bus.read32(entry), destination = m_bus.read32(entry + 4u);
            const uint32_t size = m_bus.read32(entry + 8u);
            std::vector<uint8_t> data(size);
            readMemory(source, data.data(), size);
            m_ee.writeEe(destination, data.data(), size);
        }
        ret(c, ++m_sifDmaId);
    }

    void Iop::sifDmaStat(CpuContext &c) { ret(c, static_cast<uint32_t>(-1)); } // always complete

    void Iop::sifCheckInit(CpuContext &c) { ret(c, 1u); }

    void Iop::sifRegisterRpc(CpuContext &c)
    {
        Server server;
        server.record = arg(c, 0);
        server.sid = arg(c, 1);
        server.function = arg(c, 2);
        server.buffer = arg(c, 3);
        server.queue = arg(c, 6);
        bool queueKnown = false;
        for (const auto &[queue, owner] : m_queues)
            if (queue == server.queue)
            {
                server.thread = owner;
                queueKnown = true;
            }
        m_servers[server.sid] = server;
        if (std::getenv("TOL_TRACE_IOP_RPC") != nullptr)
        {
            std::fprintf(stderr,
                         "[sifrpc] register sid=0x%08X handler=0x%08X buff=0x%08X queue=0x%08X record=0x%08X"
                         " -> thread=%d queueKnown=%d\n",
                         server.sid, server.function, server.buffer, server.queue, server.record,
                         static_cast<int>(server.thread), queueKnown ? 1 : 0);
        }
        m_ee.log("[iop] RPC server " + std::to_string(server.sid) + " registered");
        ret(c, 0);
    }

    void Iop::sifSetRpcQueue(CpuContext &c)
    {
        m_queues[arg(c, 0)] = static_cast<int32_t>(arg(c, 1));
        if (std::getenv("TOL_TRACE_IOP_RPC") != nullptr)
        {
            std::fprintf(stderr, "[sifrpc] setQueue queue=0x%08X -> thread=%d\n", arg(c, 0),
                         static_cast<int>(arg(c, 1)));
        }
        ret(c, 0);
    }

    void Iop::sifRpcLoop(CpuContext &c)
    {
        // The loop never returns; requests are delivered to the waiting thread.
        (void)c;
        block(Wait::Rpc, static_cast<int32_t>(arg(c, 0)));
    }

    void Iop::sifRemoveRpc(CpuContext &c)
    {
        for (auto it = m_servers.begin(); it != m_servers.end();)
            it = it->second.record == arg(c, 0) ? m_servers.erase(it) : std::next(it);
        ret(c, 0);
    }

    void Iop::sifGetOtherData(CpuContext &c)
    {
        // (record, EE source, IOP destination, size, mode)
        const uint32_t source = arg(c, 1), destination = arg(c, 2), size = arg(c, 3);
        std::vector<uint8_t> data(size);
        m_ee.readEe(source, data.data(), size);
        writeMemory(destination, data.data(), size);
        ret(c, 0);
    }

    void Iop::sifBindRpc(CpuContext &c)
    {
        // Callers poll the server field until the EE has registered the id,
        // some in a busy loop, so the call has to wait like the real round
        // trip does or it starves every lower priority thread.
        const uint32_t client = arg(c, 0);
        for (uint32_t offset = 0; offset < 0x28u; offset += 4u)
            m_bus.write32(client + offset, 0u);
        // Only tested against zero here; it names EE memory the IOP never reads.
        if (m_ee.eeServer(arg(c, 1)))
            m_bus.write32(client + 0x24u, 1u);
        ret(c, 0);
        if (Thread *thread = current())
        {
            thread->wakeCycle = m_cycle + kSifRoundTrip;
            block(Wait::Delay, 0);
        }
    }

    void Iop::sifCallRpc(CpuContext &c) { ret(c, static_cast<uint32_t>(-1)); }

    // ---------------------------------------------------------------- hardware timers

    void Iop::allocHardTimer(CpuContext &c)
    {
        // Timers 4 and 5 are the 32-bit ones drivers ask for; hand out any free one.
        for (uint32_t index = 0; index < m_timers.size(); ++index)
            if (!m_timers[index].allocated)
            {
                m_timers[index] = {};
                m_timers[index].allocated = true;
                ret(c, index + 1u);
                return;
            }
        ret(c, static_cast<uint32_t>(-150));
    }

    void Iop::freeHardTimer(CpuContext &c)
    {
        const uint32_t index = arg(c, 0) - 1u;
        if (index < m_timers.size())
            m_timers[index] = {};
        ret(c, 0);
    }

    void Iop::setTimerHandler(CpuContext &c)
    {
        const uint32_t index = arg(c, 0) - 1u;
        if (index < m_timers.size())
        {
            m_timers[index].compare = arg(c, 1);
            m_timers[index].handler = arg(c, 2);
            m_timers[index].argument = arg(c, 3);
            m_timers[index].gp = c.gpr[28];
        }
        ret(c, 0);
    }

    void Iop::setupHardTimer(CpuContext &c)
    {
        // (timer, source, mode, prescale): only the system clock source is used by drivers.
        const uint32_t index = arg(c, 0) - 1u;
        if (index < m_timers.size())
        {
            m_timers[index].source = arg(c, 1);
            m_timers[index].prescale = std::max<uint32_t>(arg(c, 3), 1u);
        }
        ret(c, 0);
    }

    void Iop::startHardTimer(CpuContext &c)
    {
        const uint32_t index = arg(c, 0) - 1u;
        if (index < m_timers.size())
        {
            HardTimer &timer = m_timers[index];
            timer.running = true;
            timer.start = m_cycle;
            timer.next = m_cycle + static_cast<uint64_t>(std::max<uint32_t>(timer.compare, 1u)) * timer.prescale;
        }
        ret(c, 0);
    }

    void Iop::stopHardTimer(CpuContext &c)
    {
        const uint32_t index = arg(c, 0) - 1u;
        if (index < m_timers.size())
            m_timers[index].running = false;
        ret(c, 0);
    }

    void Iop::getTimerCounter(CpuContext &c)
    {
        const uint32_t index = arg(c, 0) - 1u;
        ret(c, index < m_timers.size() ? static_cast<uint32_t>((m_cycle - m_timers[index].start) /
                                                               std::max<uint32_t>(m_timers[index].prescale, 1u))
                                       : 0u);
    }
}
