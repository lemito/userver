#pragma once

/// @file userver/chaotic/openapi/client/bearer_auth.hpp
/// @brief Bearer authentication credentials for chaotic-openapi generated clients.

#include <string>
#include <unordered_map>

#include <userver/formats/json/value.hpp>
#include <userver/utils/strong_typedef.hpp>

USERVER_NAMESPACE_BEGIN

namespace chaotic::openapi::client {

/// @brief Bearer auth credentials for a single securityScheme.
struct BearerAuthCredentials {
    using Token = utils::NonLoggable<class BearerTokenTag, std::string>;

    /// Raw token, without the "Bearer " prefix.
    Token token;
};

/// @brief Map from securityScheme name to its bearer credentials.
using BearerAuthCredentialsByScheme = std::unordered_map<std::string, BearerAuthCredentials>;

/// @brief Secdist module that loads bearer auth credentials for all schemes
/// of a chaotic-openapi generated client.
///
/// Expected secdist JSON layout:
/// @code{.json}
/// {
///   "http_bearer": {
///     "<client-name>": {
///       "<scheme-name>": { "token": "raw-token" }
///     }
///   }
/// }
/// @endcode
class BearerAuthSecdistConfig {
public:
    explicit BearerAuthSecdistConfig(const formats::json::Value& doc);

    /// @brief Returns credentials for the given client and scheme name.
    /// @throws std::runtime_error if credentials are not found.
    const BearerAuthCredentials& GetCredentialsOrThrow(const std::string& client_name, const std::string& scheme_name)
        const;

private:
    // client_name -> scheme_name -> credentials
    std::unordered_map<std::string, BearerAuthCredentialsByScheme> credentials_;
};

}  // namespace chaotic::openapi::client

USERVER_NAMESPACE_END