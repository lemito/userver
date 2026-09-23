#include <userver/chaotic/openapi/server/bearer_auth.hpp>

#include <optional>
#include <string_view>

#include <userver/http/common_headers.hpp>
#include <userver/server/http/http_request.hpp>

USERVER_NAMESPACE_BEGIN



namespace chaotic::openapi::server::impl {

std::optional<std::string_view> ExtractBearerToken(const ::USERVER_NAMESPACE::server::http::HttpRequest& request) {
    const auto& auth_header = request.GetHeader(http::headers::kAuthorization);
    constexpr std::string_view kBearerPrefix = "Bearer ";
    if (!auth_header.starts_with(kBearerPrefix)) {
        return std::nullopt;
    }
    return std::string_view{auth_header.data() + kBearerPrefix.size(), auth_header.size() - kBearerPrefix.size()};
}

} // namespace chaotic::openapi::server::impl



USERVER_NAMESPACE_END