#include <fmt/format.h>

#include <handlers/legacy_bearer/legacybearerget/handler.hpp>
#include <userver/server/auth/user_auth_info.hpp>

namespace handlers::legacy_bearer::legacybearerget {

Response View::Handle(
    Request&& /*request*/,
    Deps&& /*deps*/,
    RequestContext& context
) {
    const auto& auth_info = USERVER_NAMESPACE::server::auth::GetUserAuthInfo(context);
    const auto user_id = auth_info.GetDefaultUserId();
    Response response;
    response.body = fmt::format("legacy user {}", USERVER_NAMESPACE::server::auth::ToUInt64(user_id));
    return response;
}

}  // namespace handlers::legacy_bearer::legacybearerget