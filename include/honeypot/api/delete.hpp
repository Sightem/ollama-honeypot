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
	 * @brief Handles DELETE requests to /api/delete.
	 * Parses the model name from the request body and attempts to remove the model
	 * from the honeypot's state.
	 * @param state Shared pointer to the global HoneypotState.
	 * @param req The incoming crow::request object containing the JSON body.
	 * @return A crow::response indicating success (200 OK) or failure (400 Bad Request, 404 Not Found).
	 */
	crow::response handle_delete(const std::shared_ptr<state::HoneypotState>& state, const crow::request& req);
} // namespace honeypot::api
