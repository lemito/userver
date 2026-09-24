#include "bearer_checker.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <userver/storages/secdist/component.hpp>
#include <userver/utils/assert.hpp>

#include "auth_tokens.hpp"

namespace samples::auth {

namespace {

class AuthCheckerBearer final : public USERVER_NAMESPACE::chaotic::openapi::server::BearerAuthChecker {
public:
    explicit AuthCheckerBearer(std::unordered_map<std::string, std::uint64_t> tokens) : tokens_(std::move(tokens)) {}

    std::optional<USERVER_NAMESPACE::chaotic::openapi::server::BearerTokenData> VerifyToken(std::string_view token) const override {
        const auto it = tokens_.find(std::string{token});
        if (it == tokens_.end()) {
            return std::nullopt;
        }
        USERVER_NAMESPACE::chaotic::openapi::server::BearerTokenData data;
        data.subject = std::to_string(it->second);
        return data;
    }

private:
    const std::unordered_map<std::string, std::uint64_t> tokens_;
};

}  // namespace

BearerCheckerFactory::BearerCheckerFactory(
    const USERVER_NAMESPACE::components::ComponentConfig& config,
    const USERVER_NAMESPACE::components::ComponentContext& context
)
    : USERVER_NAMESPACE::components::ComponentBase(config, context),
      tokens_(context.FindComponent<USERVER_NAMESPACE::components::Secdist>().Get().Get<AuthTokens>().Get())
{
    UASSERT_MSG(
        !tokens_.empty(),
        "bearer-auth-checker: no bearer tokens found in secdist; every request would be rejected"
    );
}

std::unique_ptr<USERVER_NAMESPACE::chaotic::openapi::server::BearerAuthChecker> BearerCheckerFactory::Create(
    const USERVER_NAMESPACE::components::ComponentConfig& /*config*/,
    const USERVER_NAMESPACE::components::ComponentContext& /*context*/
) {
    return std::make_unique<AuthCheckerBearer>(tokens_);
}

}  // namespace samples::auth