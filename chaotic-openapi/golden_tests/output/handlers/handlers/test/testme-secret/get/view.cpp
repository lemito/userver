#include "view.hpp"

namespace handlers::test::testme_secret::get {

Response View::Handle(Request&& /*request*/, Deps&& /*deps*/, RequestContext& /*context*/) {
// Handle request using dependencies from Deps (clients, caches, configs, databases...)
return {};
}

/*

std::string View::GetResponseForLogging(
const Response& response,
const std::string& serialized_response,
RequestContext& context) {
(void)response;
(void)serialized_response;
(void)context;
return {};
}
*/

}  // namespace handlers::test::testme_secret::get
