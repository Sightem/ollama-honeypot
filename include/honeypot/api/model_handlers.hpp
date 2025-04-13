#pragma once

#include <crow.h>
#include <memory>

// Forward declare state and request types
namespace honeypot::state { class HoneypotState; }
namespace crow { struct request; }

namespace honeypot::api {

	/**
	 * @brief Handles GET requests to /api/tags.
	 * Retrieves the current list of available models from the state.
	 * @param state Shared pointer to the global HoneypotState.
	 * @return A crow::response containing the list of models as JSON.
	 */
	crow::response handle_tags(const std::shared_ptr<state::HoneypotState>& state);

	/**
	 * @brief Handles DELETE requests to /api/delete.
	 * Parses the model name from the request body and attempts to remove the model
	 * from the honeypot's state.
	 * @param state Shared pointer to the global HoneypotState.
	 * @param req The incoming crow::request object containing the JSON body.
	 * @return A crow::response indicating success (200 OK) or failure (400 Bad Request, 404 Not Found).
	 */
	crow::response handle_delete(const std::shared_ptr<state::HoneypotState>& state, const crow::request& req);

	// Add declarations for other model handlers here later (show, copy, pull, push, create, ps)

} // namespace honeypot::api