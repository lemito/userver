#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include <userver/chaotic/openapi/server/bearer_auth.hpp>
#include <userver/components/component_base.hpp>

namespace samples::auth {

/// [bearer checker factory]
/// @brief Creates `BearerAuthChecker` instances for the generated handlers.
///
/// Registered as a component and referenced from the handler static config:
/// @code{.yaml}
/// handler-bearer-get:
///   bearer_auth:
///     checker_component: bearer-auth-checker
/// @endcode
class BearerCheckerFactory final : public USERVER_NAMESPACE::components::ComponentBase,
                                   public USERVER_NAMESPACE::chaotic::openapi::server::BearerAuthCheckerFactory {
public:
    static constexpr std::string_view kName = "bearer-auth-checker";

    BearerCheckerFactory(
        const USERVER_NAMESPACE::components::ComponentConfig& config,
        const USERVER_NAMESPACE::components::ComponentContext& context
    );

    std::unique_ptr<USERVER_NAMESPACE::chaotic::openapi::server::BearerAuthChecker> Create(
        const USERVER_NAMESPACE::components::ComponentConfig& config,
        const USERVER_NAMESPACE::components::ComponentContext& context
    ) override;

private:
    const std::unordered_map<std::string, std::uint64_t> tokens_;
};
/// [bearer checker factory]

}  // namespace samples::auth