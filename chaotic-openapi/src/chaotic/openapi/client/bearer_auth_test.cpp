#include <userver/chaotic/openapi/client/bearer_auth.hpp>

#include <stdexcept>
#include <string>
#include <string_view>

#include <gtest/gtest.h>
#include <userver/formats/json/exception.hpp>
#include <userver/formats/json/serialize.hpp>
#include <userver/formats/json/value.hpp>
#include <userver/formats/parse/to.hpp>

USERVER_NAMESPACE_BEGIN

namespace {

namespace client_ns = chaotic::openapi::client;

formats::json::Value MakeDoc(std::string_view json) { return formats::json::FromString(json); }

TEST(BearerAuthSecdistConfig, EmptyDocumentHasNoCredentials) {
    const client_ns::BearerAuthSecdistConfig config{MakeDoc("{}")};

    EXPECT_THROW(config.GetCredentialsOrThrow("test", "scheme"), std::runtime_error);
}

TEST(BearerAuthSecdistConfig, MissingHttpBearerSection) {
    const client_ns::BearerAuthSecdistConfig config{MakeDoc(R"({"other": {}})")};

    EXPECT_THROW(config.GetCredentialsOrThrow("test", "scheme"), std::runtime_error);
}

TEST(BearerAuthSecdistConfig, MissingClientIsReportedWithKey) {
    const client_ns::BearerAuthSecdistConfig config{
        MakeDoc(R"({"http_bearer": {"other": {"scheme": {"token": "t"}}}})")
    };

    try {
        config.GetCredentialsOrThrow("test", "scheme");
        FAIL() << "expected std::runtime_error for a missing client";
    } catch (const std::runtime_error& ex) {
        const std::string message{ex.what()};
        EXPECT_NE(message.find("test"), std::string::npos) << message;
        EXPECT_NE(message.find("http_bearer.test"), std::string::npos) << message;
    }
}

TEST(BearerAuthSecdistConfig, MissingSchemeIsReportedWithKey) {
    const client_ns::BearerAuthSecdistConfig config{
        MakeDoc(R"({"http_bearer": {"test": {"other": {"token": "t"}}}})")
    };

    try {
        config.GetCredentialsOrThrow("test", "scheme");
        FAIL() << "expected std::runtime_error for a missing scheme";
    } catch (const std::runtime_error& ex) {
        const std::string message{ex.what()};
        EXPECT_NE(message.find("scheme"), std::string::npos) << message;
        EXPECT_NE(message.find("http_bearer.test.scheme"), std::string::npos) << message;
    }
}

TEST(BearerAuthSecdistConfig, ParsesCredentialsByClientAndScheme) {
    const client_ns::BearerAuthSecdistConfig config{MakeDoc(
        R"({"http_bearer": {"test": {"scheme": {"token": "raw-token"}}, "second": {"other": {"token": "t"}}}})"
    )};

    const auto& credentials = config.GetCredentialsOrThrow("test", "scheme");
    EXPECT_EQ(credentials.token.GetUnderlying(), "raw-token");
}

TEST(BearerAuthCredentials, ParseReadsToken) {
    const auto credentials = client_ns::Parse(
        MakeDoc(R"({"token": "raw-token"})"),
        formats::parse::To<client_ns::BearerAuthCredentials>{}
    );

    EXPECT_EQ(credentials.token.GetUnderlying(), "raw-token");
}

TEST(BearerAuthCredentials, ParseRejectsMissingToken) {
    EXPECT_THROW(
        client_ns::Parse(MakeDoc("{}"), formats::parse::To<client_ns::BearerAuthCredentials>{}),
        formats::json::MemberMissingException
    );
}

}  // namespace

USERVER_NAMESPACE_END
