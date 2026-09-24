#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include <userver/formats/common/items.hpp>
#include <userver/formats/json/value.hpp>

namespace samples::auth {

/// @brief Bearer tokens to user ids mapping from the 'tokens' section of the
/// secdist config.
class AuthTokens final {
public:
    explicit AuthTokens(const USERVER_NAMESPACE::formats::json::Value& data) {
        const auto tokens = data["tokens"];
        if (!tokens.IsObject()) {
            return;
        }
        for (const auto& [token, user_id] : USERVER_NAMESPACE::formats::common::Items(tokens)) {
            tokens_.emplace(token, user_id.As<std::uint64_t>());
        }
    }

    const std::unordered_map<std::string, std::uint64_t>& Get() const { return tokens_; }

private:
    std::unordered_map<std::string, std::uint64_t> tokens_;
};

}  // namespace samples::auth