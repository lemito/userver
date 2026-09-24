#include <userver/chaotic/openapi/client/bearer_auth.hpp>

#include <stdexcept>
#include <string>
#include <utility>

#include <fmt/format.h>

#include <userver/formats/json/serialize.hpp>
#include <userver/formats/json/value.hpp>
#include <userver/utils/algo.hpp>

USERVER_NAMESPACE_BEGIN

namespace chaotic::openapi::client {

BearerAuthCredentials Parse(const formats::json::Value& value, formats::parse::To<BearerAuthCredentials>) {
    return BearerAuthCredentials{
        BearerAuthCredentials::Token{value["token"].As<std::string>()},
    };
}

namespace {

BearerAuthCredentials ParseCredentials(const formats::json::Value& doc) {
    return Parse(doc, formats::parse::To<BearerAuthCredentials>{});
}

}  // namespace

BearerAuthSecdistConfig::BearerAuthSecdistConfig(const formats::json::Value& doc) {
    const auto& root = doc["http_bearer"];
    if (root.IsMissing() || root.IsNull()) {
        return;
    }
    for (const auto& [client_name, schemes_node] : Items(root)) {
        BearerAuthCredentialsByScheme by_scheme;
        for (const auto& [scheme_name, creds_node] : Items(schemes_node)) {
            by_scheme.emplace(scheme_name, ParseCredentials(creds_node));
        }
        credentials_.emplace(client_name, std::move(by_scheme));
    }
}

const BearerAuthCredentials& BearerAuthSecdistConfig::GetCredentialsOrThrow(
    const std::string& client_name,
    const std::string& scheme_name
) const {
    const auto* by_scheme = utils::FindOrNullptr(credentials_, client_name);
    if (by_scheme == nullptr) {
        throw std::runtime_error{fmt::format(
            "chaotic-openapi bearer auth: no secdist entry for client '{0}' "
            "(key: http_bearer.{0})",
            client_name
        )};
    }
    const auto* credentials = utils::FindOrNullptr(*by_scheme, scheme_name);
    if (credentials == nullptr) {
        throw std::runtime_error{fmt::format(
            "chaotic-openapi bearer auth: no secdist entry for client '{0}', "
            "scheme '{1}' "
            "(key: http_bearer.{0}.{1})",
            client_name,
            scheme_name
        )};
    }
    return *credentials;
}

}  // namespace chaotic::openapi::client

USERVER_NAMESPACE_END