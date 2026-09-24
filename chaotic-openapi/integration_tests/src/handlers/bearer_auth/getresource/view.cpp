#include <handlers/bearer_auth/getresource/handler.hpp>

namespace handlers::bearer_auth::getresource {

Response View::Handle(
    Request&& /*request*/,
    Deps&& /*deps*/,
    RequestContext& context
) {
    const auto token_data = Handler::GetBearerTokenData(context);
    if (!token_data) {
        throw USERVER_NAMESPACE::server::handlers::Unauthorized(
            USERVER_NAMESPACE::server::handlers::ExternalBody{"No bearer token data"}
        );
    }
    Response response;
    response.body = token_data->subject;
    return response;
}

}  // namespace handlers::bearer_auth::getresource