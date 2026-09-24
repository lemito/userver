#include <userver/chaotic/openapi/server/bearer_auth.hpp>

#include <optional>
#include <string>
#include <string_view>

#include <gtest/gtest.h>
#include <userver/formats/json/value.hpp>
#include <userver/http/common_headers.hpp>
#include <userver/server/http/http_request_builder.hpp>

USERVER_NAMESPACE_BEGIN

namespace {

namespace co_server = chaotic::openapi::server;

std::optional<std::string_view> ExtractFromHeader(std::string_view header_value) {
    auto request = server::http::HttpRequestBuilder{}
                       .AddHeader(std::string{http::headers::kAuthorization}, std::string{header_value})
                       .Build();
    return co_server::impl::ExtractBearerToken(*request);
}

TEST(ExtractBearerToken, ValidToken) {
    EXPECT_EQ(ExtractFromHeader("Bearer valid-token-123"), std::string_view{"valid-token-123"});
}

TEST(ExtractBearerToken, SchemeIsCaseInsensitive) {
    EXPECT_EQ(ExtractFromHeader("bearer valid-token-123"), std::string_view{"valid-token-123"});
    EXPECT_EQ(ExtractFromHeader("BEARER valid-token-123"), std::string_view{"valid-token-123"});
    EXPECT_EQ(ExtractFromHeader("BeArEr valid-token-123"), std::string_view{"valid-token-123"});
}

TEST(ExtractBearerToken, MultipleSpacesAfterScheme) {
    EXPECT_EQ(ExtractFromHeader("Bearer   valid-token-123"), std::string_view{"valid-token-123"});
}

TEST(ExtractBearerToken, TabAfterScheme) {
    EXPECT_EQ(ExtractFromHeader("Bearer\tvalid-token-123"), std::string_view{"valid-token-123"});
}

TEST(ExtractBearerToken, MissingHeader) {
    auto request = server::http::HttpRequestBuilder{}.Build();
    EXPECT_FALSE(co_server::impl::ExtractBearerToken(*request).has_value());
}

TEST(ExtractBearerToken, EmptyHeader) {
    EXPECT_FALSE(ExtractFromHeader("").has_value());
}

TEST(ExtractBearerToken, OtherScheme) {
    EXPECT_FALSE(ExtractFromHeader("Basic abc").has_value());
}

TEST(ExtractBearerToken, SchemeWithoutToken) {
    EXPECT_FALSE(ExtractFromHeader("Bearer").has_value());
    EXPECT_FALSE(ExtractFromHeader("Bearer ").has_value());
    EXPECT_FALSE(ExtractFromHeader("bearer").has_value());
}

TEST(ExtractBearerToken, SchemeNotFollowedBySpace) {
    EXPECT_FALSE(ExtractFromHeader("Bearerfoo").has_value());
    EXPECT_FALSE(ExtractFromHeader("Bearerfoo token").has_value());
}

}  // namespace

USERVER_NAMESPACE_END
