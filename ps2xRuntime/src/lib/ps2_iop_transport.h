#pragma once

#include "ps2_runtime.h"
#include "ps2x/iop/iop_subsystem.h"

#include <utility>

class PS2IopTransport
{
public:
    static bool configureForTesting(
        PS2Runtime *runtime,
        const ps2x::iop::GameIdentity &identity,
        std::string *error = nullptr)
    {
        return runtime && runtime->m_iopSubsystem &&
               runtime->m_iopSubsystem->configure(identity, error);
    }

    [[nodiscard]] static ps2x::iop::RpcAbi selectRpcAbi(
        const PS2Runtime *runtime,
        const ps2x::iop::RpcAbiRequest &request)
    {
        return runtime
                   ? runtime->selectIopRpcAbi(request)
                   : ps2x::iop::RpcAbi::RuntimeDefault;
    }

    [[nodiscard]] static ps2x::iop::RpcResult handleRpc(
        PS2Runtime *runtime,
        uint8_t *rdram,
        R5900Context *context,
        ps2x::iop::RpcRequest request)
    {
        return runtime
                   ? runtime->handleIopRpc(rdram, context, std::move(request))
                   : ps2x::iop::RpcResult{};
    }

    [[nodiscard]] static ps2x::iop::NativeIop *native(PS2Runtime *runtime)
    {
        return runtime && runtime->m_iopSubsystem ? &runtime->m_iopSubsystem->native() : nullptr;
    }

    static void notifyTransfer(
        PS2Runtime *runtime,
        uint8_t *rdram,
        const ps2x::iop::SifTransfer &transfer)
    {
        if (runtime)
        {
            runtime->notifyIopSifTransfer(rdram, transfer);
        }
    }

    static void reset(PS2Runtime *runtime)
    {
        if (runtime)
        {
            runtime->resetIop();
        }
    }

    // Reads a whole guest file through the IOP-side opener (cdrom0:/host:/mc0:), i.e. the way the
    // emulated IOP would see it. SIF load-module commands carry a path rather than an RPC, so they have
    // no other way to reach the file layer. Defined in ps2_iop_host.cpp, where the adapter is complete.
    static bool readHostFile(PS2Runtime *runtime, std::string_view guestPath, std::vector<uint8_t> &out);

    // Loads an IOP boot image (IOPRP*.IMG): a romdir container whose 16 real modules are ELF files. The
    // modules the LLE kernel already provides as high-level services are skipped, because loading them would
    // register the same libraries twice. Returns the number of modules started, or -1 if it is not an image.
    static int bootIopImage(PS2Runtime *runtime, const std::vector<uint8_t> &image);
};
