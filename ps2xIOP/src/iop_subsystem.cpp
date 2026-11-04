#include "ps2x/iop/iop_subsystem.h"

#include "iop_service.h"
#include "plugin_loader.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace ps2x::iop
{
    namespace
    {
        bool equalsIgnoreCaseAscii(std::string_view lhs, std::string_view rhs)
        {
            if (lhs.size() != rhs.size())
            {
                return false;
            }

            for (size_t i = 0; i < lhs.size(); ++i)
            {
                const auto left = static_cast<unsigned char>(lhs[i]);
                const auto right = static_cast<unsigned char>(rhs[i]);
                if (std::tolower(left) != std::tolower(right))
                {
                    return false;
                }
            }
            return true;
        }

        int matchSpecificity(const GameMatcher &matcher, const GameIdentity &identity)
        {
            int specificity = 0;
            if (!matcher.elfName.empty())
            {
                if (!equalsIgnoreCaseAscii(matcher.elfName, identity.elfName))
                {
                    return -1;
                }
                ++specificity;
            }
            if (matcher.entryPoint != 0)
            {
                if (matcher.entryPoint != identity.entryPoint)
                {
                    return -1;
                }
                ++specificity;
            }
            if (matcher.crc32 != 0)
            {
                if (matcher.crc32 != identity.crc32)
                {
                    return -1;
                }
                ++specificity;
            }
            return specificity;
        }
    }

    class IopSubsystem::Impl
    {
    public:
        explicit Impl(IopHost &hostRef)
            : host(hostRef), pluginCatalog(hostRef), coreServices(detail::createCoreServices(hostRef)), profiles(detail::createBuiltinProfiles()),
              native(hostRef)
        {
            rebuildRoutes();
        }

        void rebuildRoutes()
        {
            routes.clear();
            auto addLayer = [&](detail::ServiceList &services, bool profileSpecific) -> bool
            {
                std::unordered_map<uint32_t, detail::IopService *> layer;
                for (const auto &service : services)
                {
                    if (!service)
                    {
                        continue;
                    }
                    for (const uint32_t sid : service->sids())
                    {
                        if (!layer.emplace(sid, service.get()).second)
                        {
                            std::ostringstream out;
                            out << "duplicate IOP SID 0x" << std::hex << sid << " in " << (profileSpecific ? "profile" : "core") << " layer";
                            lastError = out.str();
                            return false;
                        }
                    }
                }
                for (const auto &[sid, service] : layer)
                {
                    routes[sid] = service;
                }
                return true;
            };

            routesValid = addLayer(coreServices, false) && addLayer(profileServices, true);
        }

        IopHost &host;
        detail::PluginCatalog pluginCatalog;
        detail::ServiceList coreServices;
        detail::ServiceList profileServices;
        std::vector<detail::ProfileDefinition> profiles;
        std::unordered_map<uint32_t, detail::IopService *> routes;
        std::vector<std::filesystem::path> pluginSearchPaths;
        std::vector<std::string> diagnostics;
        std::string activeProfile;
        std::string activeProvider;
        std::string lastError;
        bool routesValid = true;
        NativeIop native;
    };

    IopSubsystem::IopSubsystem(IopHost &host)
        : m_impl(std::make_unique<Impl>(host))
    {
    }

    IopSubsystem::~IopSubsystem() = default;
    IopSubsystem::IopSubsystem(IopSubsystem &&) noexcept = default;
    IopSubsystem &IopSubsystem::operator=(IopSubsystem &&) noexcept = default;

    void IopSubsystem::setPluginSearchPaths(std::vector<std::filesystem::path> paths)
    {
        m_impl->pluginSearchPaths = std::move(paths);
    }

    bool IopSubsystem::loadPlugins(std::string *error)
    {
        return m_impl->pluginCatalog.load(m_impl->pluginSearchPaths, m_impl->profiles, m_impl->diagnostics, error);
    }

    bool IopSubsystem::configure(const GameIdentity &identity, std::string *error)
    {
        m_impl->profileServices.clear();
        m_impl->activeProfile.clear();
        m_impl->activeProvider.clear();
        m_impl->lastError.clear();

        const detail::ProfileDefinition *selected = nullptr;
        const detail::ProfileDefinition *selectedTie = nullptr;
        int selectedSpecificity = -1;
        for (const auto &profile : m_impl->profiles)
        {
            const int specificity = matchSpecificity(profile.matcher, identity);
            if (specificity < 0)
            {
                continue;
            }
            if (specificity > selectedSpecificity)
            {
                selected = &profile;
                selectedTie = nullptr;
                selectedSpecificity = specificity;
                continue;
            }
            if (specificity == selectedSpecificity && selected)
            {
                selectedTie = &profile;
            }
        }

        if (selected && selectedTie)
        {
            m_impl->lastError = "ambiguous IOP profiles '" + selected->provider + ":" +
                                selected->id + "' and '" + selectedTie->provider + ":" +
                                selectedTie->id + "'";
            if (error)
            {
                *error = m_impl->lastError;
            }
            m_impl->rebuildRoutes();
            return false;
        }

        if (selected)
        {
            try
            {
                m_impl->profileServices = selected->factory(m_impl->host, identity);
                m_impl->activeProfile = selected->id;
                m_impl->activeProvider = selected->provider;
            }
            catch (const std::exception &exception)
            {
                m_impl->lastError = "failed to create IOP profile '" + selected->id + "': " + exception.what();
                if (error)
                {
                    *error = m_impl->lastError;
                }
                m_impl->rebuildRoutes();
                return false;
            }
            catch (...)
            {
                m_impl->lastError = "failed to create IOP profile '" + selected->id + "': unknown plugin exception";
                if (error)
                {
                    *error = m_impl->lastError;
                }
                m_impl->rebuildRoutes();
                return false;
            }
        }

        m_impl->rebuildRoutes();
        if (!m_impl->routesValid)
        {
            const std::string routeError = m_impl->lastError;
            m_impl->profileServices.clear();
            m_impl->activeProfile.clear();
            m_impl->activeProvider.clear();
            m_impl->rebuildRoutes();
            m_impl->lastError = routeError;
            if (error)
            {
                *error = m_impl->lastError;
            }
            return false;
        }

        reset();
        return true;
    }

    void IopSubsystem::reset()
    {
        for (auto &service : m_impl->coreServices)
        {
            if (service)
            {
                service->reset();
            }
        }
        for (auto &service : m_impl->profileServices)
        {
            if (service)
            {
                service->reset();
            }
        }
    }

    RpcAbi IopSubsystem::selectRpcAbi(const RpcAbiRequest &request) const
    {
        for (const auto &service : m_impl->profileServices)
        {
            if (service)
            {
                const RpcAbi selected = service->selectRpcAbi(request);
                if (selected != RpcAbi::RuntimeDefault)
                {
                    return selected;
                }
            }
        }
        for (const auto &service : m_impl->coreServices)
        {
            if (service)
            {
                const RpcAbi selected = service->selectRpcAbi(request);
                if (selected != RpcAbi::RuntimeDefault)
                {
                    return selected;
                }
            }
        }
        return RpcAbi::RuntimeDefault;
    }

    RpcResult IopSubsystem::handleRpc(const RpcRequest &request)
    {
        // TOL_TRACE_IOP_RPC=1: which of the three rejections applies - no native server for the sid, the
        // native call itself declining, or no profile route. Without this the caller only sees "unhandled".
        const bool traceRpc = std::getenv("TOL_TRACE_IOP_RPC") != nullptr;
        // Where does an unanswered call spend its milliseconds? The native-server probe locks the same mutex
        // the IOP pump thread holds while it settles, so it can block even when nothing answers.
        const bool traceStage = std::getenv("TOL_TRACE_RPC_STAGE") != nullptr;
        const auto stageStart = std::chrono::steady_clock::now();

        // A server registered by a native module replaces any high-level one.
        uint32_t record = 0, buffer = 0;
        const bool nativeServer = m_impl->native.server(request.sid, record, buffer);
        const auto stageProbed = std::chrono::steady_clock::now();
        if (nativeServer)
        {
            RpcResult result;
            result.handled = m_impl->native.call(request.sid, request.function, request.send.address,
                                                 request.send.size, request.receive.address,
                                                 request.receive.size);
            result.resultAddress = request.receive.address;
            result.serverDispatchPolicy = ServerDispatchPolicy::Suppress;
            if (traceRpc)
            {
                std::fprintf(stderr,
                             "[iop-rpc] sid=0x%08X fn=0x%X send=0x%08X/%u recv=0x%08X/%u -> native server "
                             "record=0x%08X buffer=0x%08X handled=%d\n",
                             request.sid, request.function, request.send.address, request.send.size,
                             request.receive.address, request.receive.size, record, buffer,
                             result.handled ? 1 : 0);
            }
            return result;
        }
        const auto it = m_impl->routes.find(request.sid);
        if (it == m_impl->routes.end() || !it->second)
        {
            // A module can register its RPC server from a thread it starts, so a sid that is missing now
            // may appear after some IOP time - and the EE's call is the only thing driving that time.
            // Once a sid has been given that chance and still has no server, stop paying for it: the guest
            // retries these in loops.
            static std::unordered_set<uint32_t> sUnservedSids;
            if (m_impl->native.enabled() && sUnservedSids.count(request.sid) == 0u)
            {
                for (int attempt = 0; attempt < 8 && !m_impl->native.server(request.sid, record, buffer);
                     ++attempt)
                {
                    m_impl->native.pump(1024u);
                }
                if (m_impl->native.server(request.sid, record, buffer))
                {
                    RpcResult result;
                    result.handled = m_impl->native.call(request.sid, request.function, request.send.address,
                                                         request.send.size, request.receive.address,
                                                         request.receive.size);
                    result.resultAddress = request.receive.address;
                    result.serverDispatchPolicy = ServerDispatchPolicy::Suppress;
                    if (traceRpc)
                    {
                        std::fprintf(stderr,
                                     "[iop-rpc] sid=0x%08X fn=0x%X -> server appeared after pump, handled=%d\n",
                                     request.sid, request.function, result.handled ? 1 : 0);
                    }
                    return result;
                }
                sUnservedSids.insert(request.sid);
            }
            if (traceRpc)
            {
                std::fprintf(stderr,
                             "[iop-rpc] sid=0x%08X fn=0x%X -> NO native server and no route (unhandled)\n",
                             request.sid, request.function);
            }
            if (traceStage)
            {
                static uint32_t sStages = 0u;
                if (++sStages <= 40u)
                {
                    const auto now = std::chrono::steady_clock::now();
                    auto ms = [](auto from, auto to)
                    { return std::chrono::duration<double, std::milli>(to - from).count(); };
                    std::fprintf(stderr, "[iopstage] sid=0x%08X fn=0x%X probe=%.3f rest=%.3f\n", request.sid,
                                 request.function, ms(stageStart, stageProbed), ms(stageProbed, now));
                }
            }
            return {};
        }
        return it->second->handleRpc(request);
    }

    void IopSubsystem::onSifTransfer(const SifTransfer &transfer)
    {
        for (auto &service : m_impl->coreServices)
        {
            if (service)
            {
                service->onSifTransfer(transfer);
            }
        }
        for (auto &service : m_impl->profileServices)
        {
            if (service)
            {
                service->onSifTransfer(transfer);
            }
        }
    }

    NativeIop &IopSubsystem::native()
    {
        return m_impl->native;
    }

    DebugSnapshot IopSubsystem::debugSnapshot() const
    {
        DebugSnapshot snapshot;
        snapshot.activeProfile = m_impl->activeProfile;
        snapshot.activeProvider = m_impl->activeProvider;
        snapshot.diagnostics = m_impl->diagnostics;
        if (!m_impl->lastError.empty())
        {
            snapshot.diagnostics.push_back(m_impl->lastError);
        }

        auto append = [&](const detail::ServiceList &services, bool profileSpecific)
        {
            for (const auto &service : services)
            {
                if (!service)
                {
                    continue;
                }
                DebugService row;
                row.name = service->name();
                row.sids.assign(service->sids().begin(), service->sids().end());
                row.profileSpecific = profileSpecific;
                service->appendDebugMetrics(row.metrics);
                snapshot.services.push_back(std::move(row));
            }
        };
        append(m_impl->coreServices, false);
        append(m_impl->profileServices, true);
        return snapshot;
    }
}
