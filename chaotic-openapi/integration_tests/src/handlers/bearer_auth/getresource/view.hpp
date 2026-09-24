#pragma once

#include <handlers/bearer_auth/getresource/requests.hpp>
#include <handlers/bearer_auth/getresource/responses.hpp>
#include <string>
#include <userver/chaotic/openapi/server/dependencies.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/server/request/request_context.hpp>

namespace handlers::bearer_auth::getresource {

  struct HandlerTag;

  class View final {
   public:
    using Deps = USERVER_NAMESPACE::chaotic::openapi::server::dependencies::ForHandler<HandlerTag>;
    using RequestContext = USERVER_NAMESPACE::server::request::RequestContext;

    static Response Handle(Request&& request, Deps&& deps, RequestContext& context);
  };

}  // namespace handlers::bearer_auth::getresource