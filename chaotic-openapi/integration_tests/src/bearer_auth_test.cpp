#include <userver/utest/utest.hpp>

#include <string>
#include <string_view>

#include <userver/http/common_headers.hpp>
#include <userver/utest/http_client.hpp>
#include <userver/utest/http_server_mock.hpp>

#include <clients/bearer_auth/client_impl.hpp>

USERVER_NAMESPACE_BEGIN

namespace {

namespace client_ns = ::clients::bearer_auth;

// Verifies the full end-to-end bearer auth chain:
// - The generated client adds an `Authorization: Bearer <token>` header
//   on every request.
// - The header value matches the token from the client config (the raw token
//   from secdist, prefixed with "Bearer " by the generated code).
// - Multiple schemes are supported: each operation uses its own token.
UTEST(BearerAuth, CredentialsPassedAsAuthorizationHeader) {
    constexpr std::string_view kToken = "raw-token-123";
    constexpr std::string_view kAdminToken = "admin-token-456";

    int resource_count = 0;
    int admin_count = 0;

    const utest::HttpServerMock http_server{[&](const utest::HttpServerMock::HttpRequest& request) {
        const auto it = request.headers.find(http::headers::kAuthorization);
        if (it == request.headers.end()) {
            utest::HttpServerMock::HttpResponse response;
            response.response_status = 401;
            return response;
        }
        if (request.path == "/api/resource") {
            EXPECT_EQ(it->second, "Bearer " + std::string{kToken});
            ++resource_count;
        } else if (request.path == "/api/admin") {
            EXPECT_EQ(it->second, "Bearer " + std::string{kAdminToken});
            ++admin_count;
        } else {
            ADD_FAILURE() << "Unexpected path: " << request.path;
        }
        utest::HttpServerMock::HttpResponse response;
        response.response_status = 200;
        return response;
    }};

    chaotic::openapi::client::Config config;
    config.base_url = http_server.GetBaseUrl();
    config.bearer_auth_credentials["myBearerScheme"] = chaotic::openapi::client::BearerAuthCredentials{
        chaotic::openapi::client::BearerAuthCredentials::Token{std::string{kToken}},
    };
    config.bearer_auth_credentials["adminBearerScheme"] = chaotic::openapi::client::BearerAuthCredentials{
        chaotic::openapi::client::BearerAuthCredentials::Token{std::string{kAdminToken}},
    };

    auto http_client_ptr = utest::CreateHttpClient();
    client_ns::ClientImpl client(config, *http_client_ptr);

    client.GetResource();
    client.GetAdmin();

    EXPECT_EQ(resource_count, 1);
    EXPECT_EQ(admin_count, 1);
}

}  // namespace

USERVER_NAMESPACE_END