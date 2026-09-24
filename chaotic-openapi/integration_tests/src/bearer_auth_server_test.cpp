#include <userver/utest/utest.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <fmt/format.h>

#include <userver/clients/http/client.hpp>
#include <userver/clients/http/response.hpp>
#include <userver/components/component.hpp>
#include <userver/components/component_base.hpp>
#include <userver/components/container.hpp>
#include <userver/components/minimal_server_component_list.hpp>
#include <userver/components/run.hpp>
#include <userver/engine/io/socket.hpp>
#include <userver/engine/io/sockaddr.hpp>
#include <userver/engine/run_standalone.hpp>
#include <userver/formats/json/serialize.hpp>
#include <userver/formats/json/value.hpp>
#include <userver/fs/blocking/file_descriptor.hpp>
#include <userver/http/common_headers.hpp>
#include <userver/server/auth/user_auth_info.hpp>
#include <userver/server/component.hpp>
#include <userver/server/handlers/auth/auth_checker_base.hpp>
#include <userver/server/handlers/auth/auth_checker_factory.hpp>
#include <userver/utest/http_client.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <handlers/bearer_auth/chaotic_handlers_list.hpp>
#include <handlers/legacy_bearer/chaotic_handlers_list.hpp>
#include <userver/chaotic/openapi/server/bearer_auth.hpp>
#include <userver/chaotic/openapi/server/dependencies.hpp>

USERVER_NAMESPACE_BEGIN

namespace {

namespace chaotic_server = USERVER_NAMESPACE::chaotic::openapi::server;

constexpr std::string_view kValidToken = "valid-token-123";
constexpr std::string_view kAdminToken = "admin-token-456";
constexpr std::string_view kSubject = "test-subject";
constexpr std::string_view kAdminSubject = "test-admin-subject";
constexpr std::string_view kExpectedBearerFormat = "JWT";
constexpr std::uint64_t kLegacyUserId = 42;

constexpr std::string_view kDefaultBearerAuth =
    "      bearer_auth:\n"
    "        checker_component: test-bearer-auth-checker\n"
    "        bearer_format: JWT\n";

struct ListenerReservation final {
    std::uint16_t port{};
    fs::blocking::FileDescriptor fd;
};

ListenerReservation ReserveListener() {
    ListenerReservation result;
    engine::RunStandalone([&result] {
        engine::io::Socket socket{engine::io::AddrDomain::kInet6, engine::io::SocketType::kStream};
        socket.Bind(engine::io::Sockaddr::MakeLoopbackAddress());
        socket.Listen();
        result.port = socket.Getsockname().Port();
        result.fd = fs::blocking::FileDescriptor::DupFd(socket.Fd());
    });
    return result;
}

class TestBearerAuthChecker final : public chaotic_server::BearerAuthChecker {
public:
    explicit TestBearerAuthChecker(std::string reported_bearer_format)
        : reported_bearer_format_(std::move(reported_bearer_format)) {}

    std::optional<chaotic_server::BearerTokenData> VerifyToken(std::string_view token) const override {
        if (token != kValidToken) {
            return std::nullopt;
        }
        chaotic_server::BearerTokenData data;
        data.subject = std::string{kSubject};
        if (!reported_bearer_format_.empty()) {
            data.bearer_format = reported_bearer_format_;
        }
        return data;
    }

private:
    const std::string reported_bearer_format_;
};

class TestBearerAuthCheckerFactory final
    : public components::ComponentBase,
      public chaotic_server::BearerAuthCheckerFactory {
public:
    static constexpr std::string_view kName = "test-bearer-auth-checker";

    TestBearerAuthCheckerFactory(const components::ComponentConfig& config, const components::ComponentContext& context)
        : ComponentBase(config, context),
          reported_bearer_format_(config["checker-reported-bearer-format"].As<std::string>("")) {}

    std::unique_ptr<chaotic_server::BearerAuthChecker> Create(
        const components::ComponentConfig& config,
        const components::ComponentContext& /*context*/
    ) override {
        bearer_format_ = config["bearer_auth"]["bearer_format"].As<std::string>("");
        return std::make_unique<TestBearerAuthChecker>(reported_bearer_format_);
    }

    const std::string& GetBearerFormat() const { return bearer_format_; }

    static yaml_config::Schema GetStaticConfigSchema() {
        return yaml_config::MergeSchemas<components::ComponentBase>(R"(
type: object
description: Creates test bearer auth checkers
additionalProperties: false
properties:
    checker-reported-bearer-format:
        type: string
        description: bearer format that checkers put into the verified token data
)");
    }

private:
    const std::string reported_bearer_format_;
    std::string bearer_format_;
};

class TestAdminBearerAuthChecker final : public chaotic_server::BearerAuthChecker {
public:
    std::optional<chaotic_server::BearerTokenData> VerifyToken(std::string_view token) const override {
        if (token != kAdminToken) {
            return std::nullopt;
        }
        chaotic_server::BearerTokenData data;
        data.subject = std::string{kAdminSubject};
        data.bearer_format = kExpectedBearerFormat;
        return data;
    }
};

class TestAdminBearerAuthCheckerFactory final
    : public components::ComponentBase,
      public chaotic_server::BearerAuthCheckerFactory {
public:
    static constexpr std::string_view kName = "test-admin-bearer-auth-checker";

    TestAdminBearerAuthCheckerFactory(
        const components::ComponentConfig& config,
        const components::ComponentContext& context
    )
        : ComponentBase(config, context) {}

    std::unique_ptr<chaotic_server::BearerAuthChecker> Create(
        const components::ComponentConfig& /*config*/,
        const components::ComponentContext& /*context*/
    ) override {
        return std::make_unique<TestAdminBearerAuthChecker>();
    }

    static yaml_config::Schema GetStaticConfigSchema() {
        return yaml_config::MergeSchemas<components::ComponentBase>(R"(
type: object
description: Creates test admin bearer auth checkers
additionalProperties: false
properties: {}
)");
    }
};

class LegacyAuthCheckerBearer final : public server::handlers::auth::AuthCheckerBase {
public:
    using AuthCheckResult = server::handlers::auth::AuthCheckResult;

    [[nodiscard]] AuthCheckResult CheckAuth(
        const server::http::HttpRequest& request,
        server::request::RequestContext& request_context
    ) const override {
        const auto& auth_value = request.GetHeader(http::headers::kAuthorization);
        constexpr std::string_view kBearerPrefix = "Bearer ";
        if (!auth_value.starts_with(kBearerPrefix)) {
            return AuthCheckResult{
                AuthCheckResult::Status::kTokenNotFound,
                {},
                "Bearer token is required",
                server::handlers::HandlerErrorCode::kUnauthorized,
            };
        }

        const std::string_view token{auth_value.data() + kBearerPrefix.size(), auth_value.size() - kBearerPrefix.size()};
        if (token != kValidToken) {
            return AuthCheckResult{
                AuthCheckResult::Status::kInvalidToken,
                {},
                "Unknown bearer token",
                server::handlers::HandlerErrorCode::kUnauthorized,
            };
        }

        SetUserAuthInfo(
            request_context,
            server::auth::UserAuthInfo{
                server::auth::UserId{kLegacyUserId},
                server::auth::UserEnv::kProd,
                server::auth::UserProvider::kYandex,
            }
        );
        return {};
    }

    [[nodiscard]] bool SupportsUserAuth() const noexcept override { return true; }
};

class LegacyAuthCheckerFactory final : public server::handlers::auth::AuthCheckerFactoryBase {
public:
    static constexpr std::string_view kAuthType = "bearer";

    explicit LegacyAuthCheckerFactory(const components::ComponentContext& /*context*/) {}

    server::handlers::auth::AuthCheckerBasePtr MakeAuthChecker(
        const server::handlers::auth::HandlerAuthConfig&
    ) const override {
        return std::make_shared<LegacyAuthCheckerBearer>();
    }
};

static std::string ParseJsonStringBody(const clients::http::Response& response) {
    return formats::json::FromString(response.body()).As<std::string>();
}

class BearerAuthServerTester final : public components::ComponentBase {
public:
    static constexpr std::string_view kName = "bearer-auth-server-tester";

    BearerAuthServerTester(const components::ComponentConfig& config, const components::ComponentContext& context)
        : ComponentBase(config, context),
          factory_(context.FindComponent<TestBearerAuthCheckerFactory>()),
          port_(config["port"].As<std::uint16_t>()),
          expected_bearer_format_(config["expected-bearer-format"].As<std::string>("")),
          expected_second_handler_bearer_format_(
              config["expected-second-handler-bearer-format"].As<std::string>(kExpectedBearerFormat)
          ) {
        context.FindComponent<components::Server>();
    }

    void OnAllComponentsLoaded() override { RunTests(); }

    static yaml_config::Schema GetStaticConfigSchema() {
        return yaml_config::MergeSchemas<components::ComponentBase>(R"(
type: object
description: Runs bearer auth checks against the local server
additionalProperties: false
properties:
    port:
        type: integer
        description: listener port of the server under test
    expected-bearer-format:
        type: string
        description: bearer format the /secure handler must report to the view
    expected-second-handler-bearer-format:
        type: string
        description: bearer format the /api/resource handler must report to the view
)");
    }

private:
    std::shared_ptr<clients::http::Response> Get(std::string_view path, std::string_view authorization) const {
        auto request = client_->CreateRequest()
                           .get(fmt::format("http://[::1]:{}{}", port_, path))
                           .timeout(utest::kMaxTestWaitTime)
                           .retry(1);
        if (!authorization.empty()) {
            request.headers({{http::headers::kAuthorization, std::string{authorization}}});
        }
        return request.perform();
    }

    void RunTests() {
        client_ = utest::CreateHttpClient();

        TestValidToken();
        TestMissingHeader();
        TestInvalidToken();
        TestLowercaseBearerPrefix();
        TestSecondHandler();
        TestAdminHandler();
        TestAdminHandlerRejectsUserToken();
        TestUserHandlerRejectsAdminToken();
        TestBearerFormatPropagation();
        TestLegacyValidToken();
        TestLegacyMissingHeader();
        TestLegacyInvalidToken();
    }

    void TestValidToken() {
        const auto response = Get("/secure", fmt::format("Bearer {}", kValidToken));
        EXPECT_EQ(response->status_code(), clients::http::Status::kOk);
        EXPECT_EQ(ParseJsonStringBody(*response), fmt::format("{}:{}", kSubject, expected_bearer_format_));
    }

    void TestMissingHeader() {
        const auto response = Get("/secure", {});
        EXPECT_EQ(response->status_code(), clients::http::Status::kUnauthorized);
    }

    void TestInvalidToken() {
        const auto response = Get("/secure", "Bearer invalid-token");
        EXPECT_EQ(response->status_code(), clients::http::Status::kUnauthorized);
    }

    void TestLowercaseBearerPrefix() {
        const auto response = Get("/secure", fmt::format("bearer {}", kValidToken));
        EXPECT_EQ(response->status_code(), clients::http::Status::kOk);
        EXPECT_EQ(ParseJsonStringBody(*response), fmt::format("{}:{}", kSubject, expected_bearer_format_));
    }

    void TestSecondHandler() {
        const auto response = Get("/api/resource", fmt::format("Bearer {}", kValidToken));
        EXPECT_EQ(response->status_code(), clients::http::Status::kOk);
        EXPECT_EQ(ParseJsonStringBody(*response), fmt::format("{}:{}", kSubject, expected_second_handler_bearer_format_));
    }

    void TestAdminHandler() {
        const auto response = Get("/api/admin", fmt::format("Bearer {}", kAdminToken));
        EXPECT_EQ(response->status_code(), clients::http::Status::kOk);
        EXPECT_EQ(ParseJsonStringBody(*response), fmt::format("{}:{}", kAdminSubject, kExpectedBearerFormat));
    }

    void TestAdminHandlerRejectsUserToken() {
        const auto response = Get("/api/admin", fmt::format("Bearer {}", kValidToken));
        EXPECT_EQ(response->status_code(), clients::http::Status::kUnauthorized);
    }

    void TestUserHandlerRejectsAdminToken() {
        const auto response = Get("/secure", fmt::format("Bearer {}", kAdminToken));
        EXPECT_EQ(response->status_code(), clients::http::Status::kUnauthorized);
    }

    void TestBearerFormatPropagation() {        EXPECT_EQ(factory_.GetBearerFormat(), kExpectedBearerFormat);
    }

    void TestLegacyValidToken() {
        const auto response = Get("/legacy-bearer", fmt::format("Bearer {}", kValidToken));
        EXPECT_EQ(response->status_code(), clients::http::Status::kOk);
        EXPECT_EQ(ParseJsonStringBody(*response), fmt::format("legacy user {}", kLegacyUserId));
    }

    void TestLegacyMissingHeader() {
        const auto response = Get("/legacy-bearer", {});
        EXPECT_EQ(response->status_code(), clients::http::Status::kUnauthorized);
    }

    void TestLegacyInvalidToken() {
        const auto response = Get("/legacy-bearer", "Bearer invalid-token");
        EXPECT_EQ(response->status_code(), clients::http::Status::kUnauthorized);
    }

    const TestBearerAuthCheckerFactory& factory_;
    const std::uint16_t port_;
    const std::string expected_bearer_format_;
    const std::string expected_second_handler_bearer_format_;
    std::shared_ptr<clients::http::Client> client_;
};

}  // namespace

template <>
inline constexpr bool components::kHasValidate<BearerAuthServerTester> = true;

template <>
inline constexpr bool components::kHasValidate<TestBearerAuthCheckerFactory> = true;

template <>
inline constexpr bool components::kHasValidate<TestAdminBearerAuthCheckerFactory> = true;

namespace {

std::string MakeConfig(
    const ListenerReservation& listener,
    std::string_view dynamic_config_defaults,
    std::string_view expected_bearer_format,
    std::string_view secure_bearer_auth = kDefaultBearerAuth,
    std::string_view checker_config = "{}\n",
    std::string_view expected_second_handler_bearer_format = kExpectedBearerFormat
) {
    return fmt::format(
        R"(
components_manager:
  coro_pool:
    initial_size: 5
    max_size: 50
    stack_usage_monitor_enabled: false
  default_task_processor: main-task-processor
  fs_task_processor: main-task-processor
  event_thread_pool:
    threads: 1
  task_processors:
    main-task-processor:
      worker_threads: 4
  components:
    logging:
      fs-task-processor: main-task-processor
      loggers:
        default:
          file_path: '@null'
          format: ltsv
    server:
      listener:
        listen-socket-fd: {0}
        task_processor: main-task-processor
    handler-secure-get:
      path: /secure
      method: GET
      task_processor: main-task-processor
{3}
    handler-get-resource:
      path: /api/resource
      method: GET
      task_processor: main-task-processor
      bearer_auth:
        checker_component: test-bearer-auth-checker
        bearer_format: JWT
    handler-legacy-bearer-get:
      path: /legacy-bearer
      method: GET
      task_processor: main-task-processor
      auth:
        types:
          - bearer
    handler-admin-get:
      path: /api/admin
      method: GET
      task_processor: main-task-processor
      bearer_auth:
        checker_component: test-admin-bearer-auth-checker
        bearer_format: JWT
    dynamic-config:
      defaults:
{2}
    test-bearer-auth-checker: {5}
    test-admin-bearer-auth-checker: {{}}
    bearer-auth-server-tester:
      port: {1}
      expected-bearer-format: {4}
      expected-second-handler-bearer-format: {6}
)",
        listener.fd.GetNative(),
        listener.port,
        dynamic_config_defaults,
        secure_bearer_auth,
        expected_bearer_format,
        checker_config,
        expected_second_handler_bearer_format
    );
}

components::ComponentList MakeComponentList() {
    return components::MinimalServerComponentList()
        .Append<components::Container<chaotic_server::dependencies::Factories>>()
        .AppendComponentList(handlers::bearer_auth::ChaoticHandlersList())
        .AppendComponentList(handlers::legacy_bearer::ChaoticHandlersList())
        .Append<TestBearerAuthCheckerFactory>()
        .Append<TestAdminBearerAuthCheckerFactory>()
        .Append<BearerAuthServerTester>();
}

void RunServer(
    std::string_view dynamic_config_defaults,
    std::string_view expected_bearer_format,
    std::string_view checker_config = "{}\n",
    std::string_view expected_second_handler_bearer_format = kExpectedBearerFormat
) {
    static const bool legacy_checker_registered = [] {
        server::handlers::auth::RegisterAuthCheckerFactory<LegacyAuthCheckerFactory>();
        return true;
    }();
    static_cast<void>(legacy_checker_registered);

    const auto listener = ReserveListener();
    const auto config = MakeConfig(
        listener,
        dynamic_config_defaults,
        expected_bearer_format,
        kDefaultBearerAuth,
        checker_config,
        expected_second_handler_bearer_format
    );

    components::RunOnce(components::InMemoryConfig{config}, MakeComponentList());
}

void ExpectStartupFails(std::string_view secure_bearer_auth, std::string_view expected_message) {
    const auto listener = ReserveListener();
    const auto config = MakeConfig(listener, "", kExpectedBearerFormat, secure_bearer_auth);

    try {
        components::RunOnce(components::InMemoryConfig{config}, MakeComponentList());
        FAIL() << "the service started with an invalid bearer_auth section";
    } catch (const std::exception& ex) {
        EXPECT_NE(std::string{ex.what()}.find(expected_message), std::string::npos)
            << "unexpected startup error: " << ex.what();
    }
}

}  // namespace

TEST(BearerAuthServer, EndToEnd) {
    RunServer("", kExpectedBearerFormat);
}

TEST(BearerAuthServer, FailsToStartWithoutCheckerComponent) {
    ExpectStartupFails(
        "      bearer_auth:\n"
        "        bearer_format: JWT\n",
        "static config validation"
    );
}

TEST(BearerAuthServer, FailsToStartWithEmptyCheckerComponent) {
    ExpectStartupFails(
        "      bearer_auth:\n"
        "        checker_component: ''\n"
        "        bearer_format: JWT\n",
        "is not set in its static config"
    );
}

TEST(BearerAuthServer, BearerFormatOverriddenByDynamicConfig) {
    constexpr std::string_view kDynamicBearerFormat = "JWT-DYNAMIC";
    RunServer(
        R"(        BEARER_AUTH_CHECKER_CONFIG:
          handler-secure-get:
            bearer_format: JWT-DYNAMIC
)",
        kDynamicBearerFormat
    );
}

TEST(BearerAuthServer, CheckerBearerFormatWinsOverHandlerState) {
    constexpr std::string_view kCheckerBearerFormat = "FROM-CHECKER";
    RunServer("", kCheckerBearerFormat, "{checker-reported-bearer-format: FROM-CHECKER}\n", kCheckerBearerFormat);
}

USERVER_NAMESPACE_END