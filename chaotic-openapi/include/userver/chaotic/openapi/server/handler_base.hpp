#pragma once

/// @file userver/chaotic/openapi/server/handler_base.hpp
/// @brief Base class template for chaotic-generated HTTP handlers

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

#include <userver/chaotic/openapi/parameters_read.hpp>
#include <userver/chaotic/openapi/server/bearer_auth.hpp>
#include <userver/chaotic/openapi/server/dependencies.hpp>
#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/components/container.hpp>
#include <userver/dynamic_config/snapshot.hpp>
#include <userver/dynamic_config/source.hpp>
#include <userver/dynamic_config/storage/component.hpp>
#include <userver/formats/common/type.hpp>
#include <userver/formats/json/serialize.hpp>
#include <userver/formats/json/value.hpp>
#include <userver/formats/yaml/value_builder.hpp>
#include <userver/server/handlers/exceptions.hpp>
#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/server/http/http_request.hpp>
#include <userver/server/request/request_context.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

USERVER_NAMESPACE_BEGIN

namespace chaotic::openapi::server {

namespace impl {

inline const utils::AnyStorageDataTag<USERVER_NAMESPACE::server::request::StorageContext, std::string> kResponseLog;
inline const utils::AnyStorageDataTag<USERVER_NAMESPACE::server::request::StorageContext, BearerTokenData> kBearerTokenData;

template <typename V>
concept ViewHasGetRequestBodyForLoggingJson = requires(const USERVER_NAMESPACE::formats::json::Value& body) {
    {
        V::GetRequestBodyForLogging(body)
    } -> std::convertible_to<std::string>;
};

template <typename V>
concept ViewHasGetRequestBodyForLoggingString = requires(const std::string& body) {
    {
        V::GetRequestBodyForLogging(body)
    } -> std::convertible_to<std::string>;
};

template <typename V>
concept ViewHasGetInvalidRequestBodyForLogging = requires(const USERVER_NAMESPACE::server::http::HttpRequest& req) {
    {
        V::GetInvalidRequestBodyForLogging(req)
    } -> std::convertible_to<std::string>;
};

template <typename V, typename R>
concept ViewHasGetResponseForLogging =
    requires(const R& resp, const std::string& s, USERVER_NAMESPACE::server::request::RequestContext& ctx) {
        {
            V::GetResponseForLogging(resp, s, ctx)
        } -> std::convertible_to<std::string>;
    };

}  // namespace impl

/// @brief Base class for generated HTTP handlers.
///
/// @tparam kName      Handler name, must be a `constexpr std::string_view`
///                    with static storage duration.
/// @tparam ErrorResponseBase  Base class of all throwable error responses for this
///                    operation, or `void` if there are none.
/// @tparam Request    Parsed request type for this operation.
/// @tparam Response   Response variant type for this operation.
/// @tparam HandlerTag Unique tag type for dependency injection keying.
///
/// The generated `Handler` subclass implements `Handle()`.
template <
    const std::string_view& Name,
    typename ErrorResponseBase,
    typename Request,
    typename Response,
    typename HandlerTag,
    typename View,
    typename HiddenArguments = void>
class BaseHandler final : public USERVER_NAMESPACE::server::handlers::HttpHandlerBase {
public:
    static constexpr std::string_view kName = Name;

    using Deps = chaotic::openapi::server::dependencies::ForHandler<HandlerTag>;

    /// @brief Compute the URL as it would appear in logs, masking hidden args.
    ///
    /// Exposed as a static method so tests can call it without instantiating
    /// the handler (which requires a full component context).
    static std::string MaskUrlForLogging(const USERVER_NAMESPACE::server::http::HttpRequest& request) {
        if constexpr (std::is_void_v<HiddenArguments>) {
            return request.GetUrl();
        } else {
            return request.GetMaskedUrl(HiddenArguments::Contains);
        }
    }

    /// @brief Returns a View-specific request body log string, or std::nullopt
    /// to signal that the default HttpHandlerBase behaviour should be used.
    ///
    /// For JSON-body Views, `FromString(request_body)` is called without a
    /// try/except: on invalid JSON the exception propagates to the caller.
    /// The virtual override below catches it and delegates to
    /// `View::GetInvalidRequestBodyForLogging` when present.
    ///
    /// Exposed as a static method so tests can call it without instantiating
    /// the handler (which requires a full component context).
    static std::optional<std::string> TryGetBodyForLogging(
        const USERVER_NAMESPACE::server::http::HttpRequest& /*request*/,
        const std::string& request_body
    ) {
        if constexpr (impl::ViewHasGetRequestBodyForLoggingJson<View>) {
            return View::GetRequestBodyForLogging(USERVER_NAMESPACE::formats::json::FromString(request_body));
        } else if constexpr (impl::ViewHasGetRequestBodyForLoggingString<View>) {
            return View::GetRequestBodyForLogging(request_body);
        }
        return std::nullopt;
    }

    BaseHandler(
        const USERVER_NAMESPACE::components::ComponentConfig& config,
        const USERVER_NAMESPACE::components::ComponentContext& context
    )
        : USERVER_NAMESPACE::server::handlers::HttpHandlerBase(config, context),
          factories_(context.FindComponent<FactoriesContainer>()),
          context_(context),
          config_source_(context.FindComponent<components::DynamicConfig>().GetSource()),
          static_checker_config_(ParseStaticCheckerConfig(config))
    {
        config_source_.UpdateAndListen(
            context.Scopes(), this, kName, &BaseHandler::OnBearerAuthConfigUpdate, kBearerAuthCheckerConfig
        );
    }

    ~BaseHandler() override = default;

    /// @brief Returns the verified bearer token data for the current request,
    /// or `std::nullopt` if the request was not authenticated with a valid
    /// bearer token (or no bearer auth checker is configured for this handler).
    ///
    /// The handler verifies the `Authorization: Bearer <token>` header with the
    /// configured `BearerAuthChecker` and stores the result in the request
    /// context before `View::Handle` is invoked.
    static std::optional<BearerTokenData> GetBearerTokenData(
        const USERVER_NAMESPACE::server::request::RequestContext& context
    ) {
        const auto* data = context.GetDataOptional(impl::kBearerTokenData);
        if (!data) {
            return std::nullopt;
        }
        return *data;
    }

    static USERVER_NAMESPACE::yaml_config::Schema GetStaticConfigSchema() {
        std::string base_schema = R"(
type: object
description: chaotic-openapi generated handler
additionalProperties: false
properties:
    bearer_auth:
        type: object
        description: Bearer authentication configuration
        additionalProperties: false
        properties:
            checker_component:
                type: string
                description: Name of the BearerAuthCheckerFactory component
            bearer_format:
                type: string
                description: Value of the OpenAPI bearerFormat field (e.g. JWT)
)";
        return USERVER_NAMESPACE::yaml_config::MergeSchemas<USERVER_NAMESPACE::server::handlers::HttpHandlerBase>(
            base_schema
        );
    }

private:
    // Guard against the old generated signature (const Request&) or other unexpected types.
    static_assert(
        !requires(const Request& r) { View::GetRequestBodyForLogging(r); },
        "View::GetRequestBodyForLogging(const Request&) is no longer supported. "
        "Use const formats::json::Value& (JSON body) or const std::string& (other body)."
    );
    static_assert(
        !(impl::ViewHasGetRequestBodyForLoggingJson<View> && impl::ViewHasGetRequestBodyForLoggingString<View>),
        "View must define at most one overload of GetRequestBodyForLogging."
    );
    static_assert(
        !impl::ViewHasGetInvalidRequestBodyForLogging<View> || impl::ViewHasGetRequestBodyForLoggingJson<View>,
        "View::GetInvalidRequestBodyForLogging requires "
        "View::GetRequestBodyForLogging(const formats::json::Value&)."
    );
    static_assert(
        requires(Request&& r, Deps&& d, USERVER_NAMESPACE::server::request::RequestContext& ctx) {
            {
                View::Handle(std::move(r), std::move(d), ctx)
            } -> std::convertible_to<Response>;
        },
        "View::Handle must accept server::request::RequestContext as the third parameter: "
        "static Response Handle(Request&& request, Deps&& deps, RequestContext& context). "
        "The legacy 2-argument Handle(Request&&, Deps&&) is no longer supported."
    );

    using Factories = chaotic::openapi::server::dependencies::Factories;
    using FactoriesContainer = USERVER_NAMESPACE::components::Container<Factories>;
    using HttpRequest = USERVER_NAMESPACE::server::http::HttpRequest;

    static Request ParseRequestOrThrow(const HttpRequest& http_request) {
        try {
            return ParseRequest(http_request, USERVER_NAMESPACE::chaotic::openapi::To<Request>{});
        } catch (const USERVER_NAMESPACE::server::handlers::ClientError&) {
            throw;
        } catch (const std::exception& e) {
            throw USERVER_NAMESPACE::server::handlers::ClientError(USERVER_NAMESPACE::server::handlers::ExternalBody{
                e.what()
            });
        }
    }

    std::string DoHandle(
        Request& request,
        HttpRequest& http_request,
        USERVER_NAMESPACE::server::request::RequestContext& context
    ) const {
        auto deps = factories_.Get().template Make<HandlerTag>();
        auto response = View::Handle(std::move(request), std::move(deps), context);
        auto serialized = SerializeResponse(response, http_request);
        if constexpr (impl::ViewHasGetResponseForLogging<View, Response>) {
            context.EmplaceData(impl::kResponseLog, View::GetResponseForLogging(response, serialized, context));
        }
        return serialized;
    }

    template <typename T>
    std::string HandleParsed(
        Request& request,
        HttpRequest& http_request,
        USERVER_NAMESPACE::server::request::RequestContext& context
    ) const {
        if constexpr (std::is_void_v<T>) {
            return DoHandle(request, http_request, context);
        } else {
            try {
                return DoHandle(request, http_request, context);
            } catch (ErrorResponseBase& e) {
                return SerializeResponse(std::move(e), http_request);
            }
        }
    }

    std::string HandleRequest(HttpRequest& http_request, USERVER_NAMESPACE::server::request::RequestContext& context)
        const final {
        if (bearer_checker_) {
            VerifyBearerToken(http_request, context);
        }
        auto request = ParseRequestOrThrow(http_request);
        return HandleParsed<ErrorResponseBase>(request, http_request, context);
    }

    std::string GetUrlForLogging(
        const HttpRequest& request,
        USERVER_NAMESPACE::server::request::RequestContext& context
    ) const override {
        if constexpr (std::is_void_v<HiddenArguments>) {
            return USERVER_NAMESPACE::server::handlers::HttpHandlerBase::GetUrlForLogging(request, context);
        } else {
            return MaskUrlForLogging(request);
        }
    }

    std::string GetRequestBodyForLogging(
        const HttpRequest& request,
        USERVER_NAMESPACE::server::request::RequestContext& context,
        const std::string& request_body
    ) const override {
        try {
            if (auto result = TryGetBodyForLogging(request, request_body)) {
                return std::move(*result);
            }
        } catch (...) {
            if constexpr (impl::ViewHasGetInvalidRequestBodyForLogging<View>) {
                return View::GetInvalidRequestBodyForLogging(request);
            }
        }
        return USERVER_NAMESPACE::server::handlers::HttpHandlerBase::GetRequestBodyForLogging(
            request,
            context,
            request_body
        );
    }

    std::string GetResponseDataForLogging(
        const HttpRequest& request,
        USERVER_NAMESPACE::server::request::RequestContext& context,
        const std::string& response_data
    ) const override {
        if constexpr (impl::ViewHasGetResponseForLogging<View, Response>) {
            if (auto* s = context.GetDataOptional(impl::kResponseLog)) {
                return *s;
            }
        }
        return USERVER_NAMESPACE::server::handlers::HttpHandlerBase::GetResponseDataForLogging(
            request,
            context,
            response_data
        );
    }


    static BearerAuthCheckerConfig ParseStaticCheckerConfig(
        const USERVER_NAMESPACE::components::ComponentConfig& config
    ) {
        BearerAuthCheckerConfig checker_config;
        checker_config.checker_component =
            config["bearer_auth"]["checker_component"].As<std::string>("");
        checker_config.bearer_format = config["bearer_auth"]["bearer_format"].As<std::string>("");
        return checker_config;
    }

    static USERVER_NAMESPACE::components::ComponentConfig MakeComponentConfig(
        const BearerAuthCheckerConfig& checker_config,
        std::string_view handler_name
    ) {
        auto builder = USERVER_NAMESPACE::formats::yaml::ValueBuilder{USERVER_NAMESPACE::formats::common::Type::kObject};
        builder["bearer_auth"]["checker_component"] = checker_config.checker_component;
        builder["bearer_auth"]["bearer_format"] = checker_config.bearer_format;
        USERVER_NAMESPACE::yaml_config::YamlConfig yaml_config{
            builder.ExtractValue(),
            USERVER_NAMESPACE::formats::yaml::Value{},
            USERVER_NAMESPACE::yaml_config::YamlConfig::Mode::kSecure
        };
        USERVER_NAMESPACE::components::ComponentConfig config{std::move(yaml_config)};
        config.SetName(std::string{handler_name});
        return config;
    }

    static std::unique_ptr<BearerAuthChecker> MakeBearerAuthChecker(
        const BearerAuthCheckerConfig& checker_config,
        const USERVER_NAMESPACE::components::ComponentContext& context
    ) {
        if (checker_config.checker_component.empty()) {
            return nullptr;
        }
        auto& factory = context.FindComponent<BearerAuthCheckerFactory>(checker_config.checker_component);
        return factory.Create(MakeComponentConfig(checker_config, kName), context);
    }

    void OnBearerAuthConfigUpdate(const USERVER_NAMESPACE::dynamic_config::Snapshot& config) {
        const auto& checker_config = config[kBearerAuthCheckerConfig];
        if (checker_config.checker_component.empty()) {
            // Dynamic config does not override the checker: fall back to the
            // static config of the handler.
            bearer_checker_ = MakeBearerAuthChecker(static_checker_config_, context_);
        } else {
            bearer_checker_ = MakeBearerAuthChecker(checker_config, context_);
        }
    }

    void VerifyBearerToken(
        const HttpRequest& http_request,
        USERVER_NAMESPACE::server::request::RequestContext& context
    ) const {
        const auto token = impl::ExtractBearerToken(http_request);
        if (!token) {
            throw USERVER_NAMESPACE::server::handlers::Unauthorized(
                USERVER_NAMESPACE::server::handlers::ExternalBody{"Bearer token is required"}
            );
        }
        auto token_data = bearer_checker_->VerifyToken(*token);
        if (!token_data) {
            throw USERVER_NAMESPACE::server::handlers::Unauthorized(
                USERVER_NAMESPACE::server::handlers::ExternalBody{"Invalid bearer token"}
            );
        }
        context.EmplaceData(impl::kBearerTokenData, std::move(*token_data));
    }

    FactoriesContainer& factories_;
    const USERVER_NAMESPACE::components::ComponentContext& context_;
    USERVER_NAMESPACE::dynamic_config::Source config_source_;
    BearerAuthCheckerConfig static_checker_config_;
    std::unique_ptr<BearerAuthChecker> bearer_checker_;
};

}  // namespace chaotic::openapi::server

USERVER_NAMESPACE_END
