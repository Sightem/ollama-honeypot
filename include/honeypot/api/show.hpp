#pragma once
#include <memory>

#include "utils/logging.hpp"
#include "state/honeypot_state.hpp"
#include "utils/config.hpp"

namespace fs = std::filesystem;

namespace honeypot::api
{
	/**
	 * @brief Handles POST requests to /api/show.
	 * Loads model details from configured JSON file (with caching),
	 * optionally removes verbose fields, and returns the details.
	 * @param config_ptr Shared pointer to the HoneypotConfig (needed for base path).
	 * @param state_ptr Shared pointer to the global HoneypotState (for map & cache).
	 * @param req The incoming crow::request object containing the JSON body.
	 * @return A crow::response containing model details or an error.
	 */
	crow::response handle_show(
		const std::shared_ptr<config::HoneypotConfig>& config_ptr,
		const std::shared_ptr<state::HoneypotState>& state_ptr,
		const crow::request& req);
} // namespace honeypot::api
