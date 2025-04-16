#include <memory>

#include <fmt/core.h>
#include <nlohmann/json.hpp>

#include "api/tags.hpp"
#include "state/honeypot_state.hpp"
#include "utils/fake_data.hpp"
#include "utils/logging.hpp"


namespace honeypot::api
{
	crow::response handle_tags(const std::shared_ptr<state::HoneypotState>& state)
	{
		const auto logger = utils::get_operational_logger();
		logger->debug("Handling GET /api/tags request.");

		try
		{
			const std::vector<config::TagModelInfo>& current_models = state->get_available_models();

			const nlohmann::ordered_json response_json = utils::fake_data::generate_model_list_json(current_models);

			crow::response res(crow::status::OK); // 200 OK
			res.set_header("Content-Type", "application/json");
			res.body = response_json.dump();
			return res;
		}
		catch (const std::exception& e)
		{
			logger->error("Error handling /api/tags: {}", e.what());
			return {crow::status::INTERNAL_SERVER_ERROR, "Internal Server Error"};
		}
	}
}