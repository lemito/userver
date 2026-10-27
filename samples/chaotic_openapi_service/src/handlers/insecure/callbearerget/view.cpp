#include "view.hpp"

#include <utility>

#include <clients/bearer/client.hpp>

namespace handlers::insecure::callbearerget {

Response View::Handle(Request&& /*request*/, Deps&& deps, RequestContext& /*context*/) {
    /// [bearer-client-use]
    auto& client = deps[::clients::bearer::kDependency];

    auto response = client.BearerGet();
    /// [bearer-client-use]

    return Response200{.body = std::move(response.body.greeting)};
}

}  // namespace handlers::insecure::callbearerget