#include <userver/chaotic/openapi/server/bearer_auth.hpp>

#include <optional>
#include <string_view>

#include <userver/formats/json/value.hpp>
#include <userver/http/common_headers.hpp>
#include <userver/server/http/http_request.hpp>

USERVER_NAMESPACE_BEGIN

namespace chaotic::openapi::server {

BearerAuthCheckerConfig Parse(const formats::json::Value& value, formats::parse::To<BearerAuthCheckerConfig>) {
    BearerAuthCheckerConfig config;
    config.checker_component = value["checker_component"].As<std::string>("");
    config.bearer_format = value["bearer_format"].As<std::string>("");
    return config;
}

namespace impl {

std::optional<std::string_view> ExtractBearerToken(const ::USERVER_NAMESPACE::server::http::HttpRequest& request) {
    const auto& auth_header = request.GetHeader(http::headers::kAuthorization);
    constexpr std::string_view kBearerPrefix = "Bearer ";
    if (!auth_header.starts_with(kBearerPrefix)) {
        return std::nullopt;
    }
    return std::string_view{auth_header.data() + kBearerPrefix.size(), auth_header.size() - kBearerPrefix.size()};
}

}  // namespace impl

}  // namespace chaotic::openapi::server

USERVER_NAMESPACE_END