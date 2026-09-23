#pragma once

/// @file userver/chaotic/openapi/server/bearer_auth.hpp
/// @brief Pluggable Bearer authentication for chaotic-openapi generated handlers.

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/dynamic_config/snapshot.hpp>
#include <userver/formats/parse/to.hpp>

USERVER_NAMESPACE_BEGIN

namespace server::http {
class HttpRequest;
}

namespace chaotic::openapi::server {

namespace impl {

/// @brief Extracts the raw token from the `Authorization: Bearer <token>`
/// header of a request. Returns `std::nullopt` if the header is absent or
/// does not start with the "Bearer " prefix.
std::optional<std::string_view> ExtractBearerToken(const ::USERVER_NAMESPACE::server::http::HttpRequest& request);

}  // namespace impl

/// @brief Runtime configuration of the bearer auth checker of a generated
/// handler, used by the dynamic config key `kBearerAuthCheckerConfig`.
struct BearerAuthCheckerConfig {
    /// Name of the `BearerAuthCheckerFactory` component that creates the
    /// checker. Empty means "no bearer auth" (or fall back to the static
    /// config of the handler).
    std::string checker_component;
    /// Value of the OpenAPI `bearerFormat` field (e.g. "JWT"), if declared.
    std::string bearer_format;

    bool operator==(const BearerAuthCheckerConfig&) const = default;
};

/// @brief Parses the checker config from JSON, used by dynamic config.
BearerAuthCheckerConfig Parse(const formats::json::Value& value, formats::parse::To<BearerAuthCheckerConfig>);

/// @brief Dynamic config key with the bearer auth checker configuration of
/// generated handlers.
///
/// Expected dynamic config JSON layout:
/// @code{.json}
/// {
///   "BEARER_AUTH_CHECKER_CONFIG": {
///     "checker_component": "my-jwt-checker",
///     "bearer_format": "JWT"
///   }
/// }
/// @endcode
inline const dynamic_config::Key<BearerAuthCheckerConfig> kBearerAuthCheckerConfig{
    "BEARER_AUTH_CHECKER_CONFIG", dynamic_config::DefaultAsJsonString{"{}"}
};

/// @brief Result of a successful bearer token verification.
///
/// The application's `BearerAuthChecker` fills this structure; the generated
/// handler stores it in the request context and exposes it via
/// `BaseHandler::GetBearerTokenData()`.
struct BearerTokenData {
    /// Subject of the token (e.g. the "sub" claim of a JWT).
    std::string subject;
    /// Arbitrary claims extracted from the token.
    std::unordered_map<std::string, std::string> claims;
    /// Token expiration time, if any.
    std::optional<std::chrono::system_clock::time_point> expires_at;
    /// Value of the OpenAPI `bearerFormat` field (e.g. "JWT"), if declared.
    std::string bearer_format;
};

/// @brief Verifies bearer tokens.
///
/// The application provides the implementation (e.g. using any JWT library or
/// custom logic). The generated handler calls `VerifyToken` for every request
/// that carries an `Authorization: Bearer <token>` header and rejects the
/// request with HTTP 401 if the token is missing or invalid.
class BearerAuthChecker {
public:
    virtual ~BearerAuthChecker() = default;

    /// @brief Returns token data if the token is valid, `std::nullopt`
    /// if it is invalid or expired.
    virtual std::optional<BearerTokenData> VerifyToken(std::string_view token) const = 0;
};

/// @brief Component interface for creating `BearerAuthChecker` instances.
///
/// Register a component that inherits from both `components::ComponentBase`
/// and `BearerAuthCheckerFactory`, then reference it in the handler static
/// config:
/// @code{.yaml}
/// handler-name:
///   bearer_auth:
///     checker_component: my-jwt-checker
/// @endcode
class BearerAuthCheckerFactory {
public:
    virtual ~BearerAuthCheckerFactory() = default;

    /// @brief Creates a checker.
    ///
    /// @param config the handler's static config (contains the `bearer_auth`
    ///        section, including `bearer_format` from the OpenAPI schema)
    /// @param context the component context
    virtual std::unique_ptr<BearerAuthChecker> Create(
        const components::ComponentConfig& config,
        const components::ComponentContext& context
    ) = 0;
};

}  // namespace chaotic::openapi::server

USERVER_NAMESPACE_END