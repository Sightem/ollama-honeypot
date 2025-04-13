#include "api/misc_handlers.hpp"
#include "utils/config.hpp"
#include "utils/logging.hpp"

#include <nlohmann/json.hpp>

namespace honeypot::api
{
	crow::response handle_version(const config::HoneypotConfig& config)
	{
		try
		{
			nlohmann::json response_json;
			response_json["version"] = config.api_behavior.ollama_version;

			crow::response res(crow::status::OK);
			res.set_header("Content-Type", "application/json");
			res.body = response_json.dump();
			return res;
		}
		catch (const std::exception& e)
		{
			const auto logger = utils::get_operational_logger();
			logger->error("Error creating /api/version response: {}", e.what());
			return {crow::status::INTERNAL_SERVER_ERROR, "Internal Server Error"};
		}
	}
} // namespace honeypot::api
