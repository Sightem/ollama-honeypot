#include <memory>

#include <fmt/core.h>
#include <nlohmann/json.hpp>

#include "state/honeypot_state.hpp"
#include "utils/fake_data.hpp"
#include "utils/logging.hpp"
#include "api/delete.hpp"

namespace honeypot::api
{
    crow::response handle_delete(const std::shared_ptr<state::HoneypotState>& state, const crow::request& req)
    {
        auto logger = utils::get_operational_logger();
        logger->debug("Handling DELETE /api/delete request.");

        nlohmann::ordered_json request_body;
        try
        {
            if (req.body.empty())
            {
                logger->warn("/api/delete request received with empty body.");
                return {
                    crow::status::BAD_REQUEST,
                    utils::fake_data::generate_error("missing request body").dump()
                };
            }
            request_body = nlohmann::ordered_json::parse(req.body);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            logger->warn("/api/delete request body failed JSON parsing: {}", e.what());
            // Return an error message closer to Ollama's *style*, but generic content
            // TODO: what can we do here?
            auto error_json = utils::fake_data::generate_error("invalid json request format");
            crow::response res(crow::status::BAD_REQUEST);
            res.set_header("Content-Type", "application/json; charset=utf-8");
            res.body = error_json.dump();
            return res;
        } catch (const nlohmann::json::exception& e)
        {
            logger->error("/api/delete encountered unexpected JSON library error: {}", e.what());
            return {crow::status::INTERNAL_SERVER_ERROR, "Internal Server Error processing JSON"};
        }

        if (!request_body.contains("model") || !request_body["model"].is_string())
        {
            logger->warn("/api/delete request JSON missing 'model' key or it's not a string.");
            auto error_json = utils::fake_data::generate_error("missing 'model' field in request");
            crow::response res(crow::status::BAD_REQUEST);
            res.set_header("Content-Type", "application/json; charset=utf-8");
            res.body = error_json.dump();
            return res;
        }

        std::string model_to_delete = request_body["model"];
        logger->info("Attempting to delete model: '{}'", model_to_delete);

        try
        {
            if (state->delete_model(model_to_delete))
            {
                logger->info("Successfully deleted model '{}' from state.", model_to_delete);
                return crow::response(crow::status::OK); // 200 OK, No body
            }
            logger->info("Model '{}' not found for deletion.", model_to_delete);
            auto error_json = utils::fake_data::generate_error(fmt::format("model '{}' not found", model_to_delete));
            crow::response res(crow::status::NOT_FOUND); // 404 Not Found
            res.set_header("Content-Type", "application/json; charset=utf-8");
            res.body = error_json.dump();
            return res;
        }
        catch (const std::exception& e)
        {
            logger->error("Error during model deletion for '{}': {}", model_to_delete, e.what());
            return {crow::status::INTERNAL_SERVER_ERROR, "Internal Server Error"};
        }
    }
}
