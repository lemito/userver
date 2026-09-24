#include <userver/chaotic/openapi/server/bearer_auth.hpp>

#include <optional>
#include <string_view>

#include <userver/formats/json/value.hpp>
#include <userver/http/common_headers.hpp>
#include <userver/server/http/http_request.hpp>

USERVER_NAMESPACE_BEGIN

namespace chaotic::openapi::server {

BearerAuthCheckerDynamicConfig Parse(
    const formats::json::Value& value,
    formats::parse::To<BearerAuthCheckerDynamicConfig>
) {
    BearerAuthCheckerDynamicConfig config;
    config.bearer_format = value["bearer_format"].As<std::string>("");
    return config;
}

namespace impl {

namespace {

constexpr bool IsSpace(char c) { return c == ' ' || c == '\t'; }

constexpr char ToLowerAscii(char c) {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

}  // namespace

std::optional<std::string_view> ExtractBearerToken(const ::USERVER_NAMESPACE::server::http::HttpRequest& request) {
    const auto& auth_header = request.GetHeader(http::headers::kAuthorization);
    const std::string_view header{auth_header};
    constexpr std::string_view kBearerScheme = "bearer";

    if (header.size() < kBearerScheme.size()) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < kBearerScheme.size(); ++i) {
        if (ToLowerAscii(header[i]) != kBearerScheme[i]) {
            return std::nullopt;
        }
    }

    std::size_t pos = kBearerScheme.size();
    if (pos == header.size() || !IsSpace(header[pos])) {
        return std::nullopt;
    }
    while (pos < header.size() && IsSpace(header[pos])) {
        ++pos;
    }
    if (pos == header.size()) {
        return std::nullopt;
    }
    return header.substr(pos);
}

}  // namespace impl

}  // namespace chaotic::openapi::server

USERVER_NAMESPACE_END
