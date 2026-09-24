#include "view.hpp"

#include <utility>

#include <clients/bearer/client.hpp>

namespace handlers::insecure::callbearerget {

Response View::Handle(Request&& /*request*/, Deps&& deps, RequestContext& /*context*/) {
    auto& client = deps[::clients::bearer::kDependency];

    // Credentials are not passed here: the generated client attaches the
    // `Authorization: Bearer <token>` header using credentials from secdist.
    auto response = client.BearerGet();

    return Response200{.body = std::move(response.body.greeting)};
}

}  // namespace handlers::insecure::callbearerget