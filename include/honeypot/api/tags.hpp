#pragma once

#include <crow.h>
#include <memory>

namespace honeypot::state
{
	class HoneypotState;
}

namespace crow
{
	struct request;
}

namespace honeypot::api
{
	/**
	 * @brief Handles GET requests to /api/tags.
	 * Retrieves the current list of available models from the state.
	 * @param state Shared pointer to the global HoneypotState.
	 * @return A crow::response containing the list of models as JSON.
	 */
	crow::response handle_tags(const std::shared_ptr<state::HoneypotState>& state);
} // namespace honeypot::api
