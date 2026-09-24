#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include <userver/chaotic/openapi/server/bearer_auth.hpp>
#include <userver/components/component_base.hpp>
#include <userver/utest/using_namespace_userver.hpp>

namespace samples::auth {

/// @brief Creates `BearerAuthChecker` instances for the generated handlers.
///
/// Registered as a component and referenced from the handler static config:
/// @code{.yaml}
/// handler-bearer-get:
///   bearer_auth:
///     checker_component: bearer-auth-checker
/// @endcode
class BearerCheckerFactory final : public components::ComponentBase,
                                   public chaotic::openapi::server::BearerAuthCheckerFactory {
public:
    static constexpr std::string_view kName = "bearer-auth-checker";

    BearerCheckerFactory(const components::ComponentConfig& config, const components::ComponentContext& context);

    std::unique_ptr<chaotic::openapi::server::BearerAuthChecker> Create(
        const components::ComponentConfig& config,
        const components::ComponentContext& context
    ) override;

private:
    std::unordered_map<std::string, std::uint64_t> tokens_;
};

}  // namespace samples::auth