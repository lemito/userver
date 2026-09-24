#include "auth_bearer.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <userver/http/common_headers.hpp>
#include <userver/server/auth/user_auth_info.hpp>
#include <userver/server/handlers/exceptions.hpp>
#include <userver/storages/secdist/component.hpp>

#include "auth_tokens.hpp"

namespace samples::auth {

namespace {

class AuthCheckerBearer final : public server::handlers::auth::AuthCheckerBase {
public:
    using AuthCheckResult = server::handlers::auth::AuthCheckResult;

    explicit AuthCheckerBearer(std::unordered_map<std::string, std::uint64_t> tokens) : tokens_(std::move(tokens)) {}

    [[nodiscard]] AuthCheckResult CheckAuth(
        const server::http::HttpRequest& request,
        server::request::RequestContext& request_context
    ) const override;

    [[nodiscard]] bool SupportsUserAuth() const noexcept override { return true; }

private:
    const std::unordered_map<std::string, std::uint64_t> tokens_;
};

AuthCheckerBearer::AuthCheckResult AuthCheckerBearer::CheckAuth(
    const server::http::HttpRequest& request,
    server::request::RequestContext& request_context
) const {
    const auto& auth_value = request.GetHeader(http::headers::kAuthorization);
    constexpr std::string_view kBearerPrefix = "Bearer ";
    if (!auth_value.starts_with(kBearerPrefix)) {
        return AuthCheckResult{
            AuthCheckResult::Status::kTokenNotFound,
            {},
            "Bearer token is required",
            server::handlers::HandlerErrorCode::kUnauthorized,
        };
    }

    const std::string_view token{auth_value.data() + kBearerPrefix.size(), auth_value.size() - kBearerPrefix.size()};
    const auto it = tokens_.find(std::string{token});
    if (it == tokens_.end()) {
        return AuthCheckResult{
            AuthCheckResult::Status::kInvalidToken,
            {},
            "Unknown bearer token",
            server::handlers::HandlerErrorCode::kUnauthorized,
        };
    }

    SetUserAuthInfo(
        request_context,
        server::auth::UserAuthInfo{
            server::auth::UserId{it->second},
            server::auth::UserEnv::kProd,
            server::auth::UserProvider::kYandex,
        }
    );
    return {};
}

}  // namespace

CheckerFactory::CheckerFactory(const components::ComponentContext& context)
    : tokens_(context.FindComponent<components::Secdist>().Get().Get<AuthTokens>().Get()) {}

server::handlers::auth::AuthCheckerBasePtr
CheckerFactory::MakeAuthChecker(const server::handlers::auth::HandlerAuthConfig&) const {
    return std::make_shared<AuthCheckerBearer>(tokens_);
}

}  // namespace samples::auth
