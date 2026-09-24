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

class AuthCheckerBearer final : public chaotic::openapi::server::BearerAuthChecker {
public:
    explicit AuthCheckerBearer(std::unordered_map<std::string, std::uint64_t> tokens) : tokens_(std::move(tokens)) {}

    std::optional<chaotic::openapi::server::BearerTokenData> VerifyToken(std::string_view token) const override {
        const auto it = tokens_.find(std::string{token});
        if (it == tokens_.end()) {
            return std::nullopt;
        }
        chaotic::openapi::server::BearerTokenData data;
        data.subject = std::to_string(it->second);
        return data;
    }

private:
    const std::unordered_map<std::string, std::uint64_t> tokens_;
};

}  // namespace

BearerCheckerFactory::BearerCheckerFactory(
    const components::ComponentConfig& config,
    const components::ComponentContext& context
)
    : components::ComponentBase(config, context),
      tokens_(context.FindComponent<components::Secdist>().Get().Get<AuthTokens>().Get())
{
    UASSERT_MSG(
        !tokens_.empty(),
        "bearer-auth-checker: no bearer tokens found in secdist; every request would be rejected"
    );
}

std::unique_ptr<chaotic::openapi::server::BearerAuthChecker> BearerCheckerFactory::Create(
    const components::ComponentConfig& /*config*/,
    const components::ComponentContext& /*context*/
) {
    return std::make_unique<AuthCheckerBearer>(tokens_);
}

}  // namespace samples::auth