#pragma once

#include <handlers/legacy_bearer/legacybearerget/requests.hpp>
#include <handlers/legacy_bearer/legacybearerget/responses.hpp>
#include <string>
#include <userver/chaotic/openapi/server/dependencies.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/server/request/request_context.hpp>

namespace handlers::legacy_bearer::legacybearerget {

  struct HandlerTag;

  class View final {
   public:
    using Deps = USERVER_NAMESPACE::chaotic::openapi::server::dependencies::ForHandler<HandlerTag>;
    using RequestContext = USERVER_NAMESPACE::server::request::RequestContext;

    static Response Handle(Request&& request, Deps&& deps, RequestContext& context);
  };

}  // namespace handlers::legacy_bearer::legacybearerget