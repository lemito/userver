#include "view.hpp"

#include <fmt/format.h>

#include <handlers/secure/bearerget/handler.hpp>
#include <userver/server/handlers/exceptions.hpp>

namespace handlers::secure::bearerget {

Response View::Handle(Request&& /*request*/, Deps&& /*deps*/, RequestContext& context) {
    const auto token_data = Handler::GetBearerTokenData(context);
    if (!token_data) {
        throw USERVER_NAMESPACE::server::handlers::Unauthorized(
            USERVER_NAMESPACE::server::handlers::ExternalBody{"No bearer token data"}
        );
    }
    return Response200{.body = {.greeting = fmt::format("Hello, bearer user {}!", token_data->subject)}};
}

}  // namespace handlers::secure::bearerget