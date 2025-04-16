#include <memory>
#include <fstream>
#include <filesystem>
#include <string>
#include <string_view>
#include <optional>


#include <nlohmann/json.hpp>

#include "api/show.hpp"
#include "state/honeypot_state.hpp"
#include "utils/config.hpp"
#include "utils/fake_data.hpp"
#include "utils/logging.hpp"

namespace fs = std::filesystem;

namespace honeypot::api
{
    crow::response handle_show(
        const std::shared_ptr<config::HoneypotConfig>& config_ptr,
        const std::shared_ptr<state::HoneypotState>& state_ptr,
        const crow::request& req)
    {
        auto logger = utils::get_operational_logger();
        logger->debug("Handling POST /api/show request.");

        nlohmann::ordered_json request_body;
        try
        {
            if (req.body.empty())
            {
                logger->warn("/api/show request received with empty body.");
                return {crow::status::BAD_REQUEST, utils::fake_data::generate_error("missing request body").dump()};
            }
            request_body = nlohmann::ordered_json::parse(req.body);
        }
        catch (const nlohmann::ordered_json::parse_error& e)
        {
            logger->warn("/api/show failed to parse request body: {}", e.what());
            return {
                crow::status::BAD_REQUEST,
                utils::fake_data::generate_error("invalid json request format").dump()
            };
        }

        if (!request_body.contains("model") || !request_body["model"].is_string())
        {
            logger->warn("/api/show request body missing 'model' key or it's not a string.");
            return {
                crow::status::BAD_REQUEST,
                utils::fake_data::generate_error("missing 'model' field in request body").dump()
            };
        }

        const std::string& model_name = request_body["model"];

        bool verbose = false;
        if (request_body.contains("verbose") && request_body["verbose"].is_boolean())
        {
            verbose = request_body["verbose"];
        }
        logger->debug("/api/show request for model: '{}', verbose: {}", model_name, verbose);

        std::optional<std::string> relative_detail_path_opt = state_ptr->get_detail_file_path(model_name);

        if (!relative_detail_path_opt)
        {
            logger->info("Model '{}' not found in show_file_map for /api/show request.", model_name);
            auto error_json = utils::fake_data::generate_error(fmt::format("model '{}' not found", model_name));
            return {crow::status::NOT_FOUND, error_json.dump()};
        }
        const std::string& relative_detail_path = *relative_detail_path_opt;

        fs::path full_detail_path = "config" / fs::path(relative_detail_path);

        std::optional<nlohmann::ordered_json> cached_json_opt = state_ptr->get_cached_detail(full_detail_path.string());
        nlohmann::ordered_json model_details_json;

        if (cached_json_opt)
        {
            logger->debug("Cache hit for /api/show detail file: {}", full_detail_path.string());
            model_details_json = *cached_json_opt;
        }
        else
        {
            logger->debug("Cache miss for /api/show detail file: {}. Loading from disk.", full_detail_path.string());
            std::ifstream detail_file(full_detail_path);
            if (!detail_file.is_open())
            {
                logger->error("Failed to open detail file '{}' for model '{}'", full_detail_path.string(), model_name);
                return {
                    crow::status::INTERNAL_SERVER_ERROR,
                    utils::fake_data::generate_error(
                        fmt::format("internal error: detail file for model '{}' missing or unreadable",
                                    model_name)).dump()
                };
            }

            try
            {
                model_details_json = nlohmann::ordered_json::parse(detail_file);
                state_ptr->cache_detail(full_detail_path.string(), model_details_json);
                logger->debug("Successfully loaded and cached detail file: {}", full_detail_path.string());
            }
            catch (const nlohmann::ordered_json::parse_error& e)
            {
                logger->error("Failed to parse JSON detail file '{}' for model '{}': {}", full_detail_path.string(),
                              model_name, e.what());
                return {
                    crow::status::INTERNAL_SERVER_ERROR,
                    utils::fake_data::generate_error(
                        fmt::format("internal error: detail file for model '{}' is invalid JSON", model_name)).dump()
                };
            } catch (const std::exception& e)
            {
                logger->error("Error reading detail file '{}' for model '{}': {}", full_detail_path.string(),
                              model_name, e.what());
                return {crow::status::INTERNAL_SERVER_ERROR, "Internal Server Error reading details"};
            }
        }


        // handle 'verbose' Flag
        if (!verbose)
        {
            logger->debug("Verbose flag is false, removing verbose fields from response.");
            if (model_details_json.contains("model_info") && model_details_json["model_info"].is_object())
            {
                auto& model_info = model_details_json["model_info"];

                model_info["tokenizer.ggml.merges"] = nullptr;
                model_info["tokenizer.ggml.token_type"] = nullptr;
                model_info["tokenizer.ggml.tokens"] = nullptr;
            }
            else
            {
                logger->warn("'/api/show' response JSON for '{}' unexpectedly missing 'model_info' object.",
                             model_name);
            }
        }

        crow::response res(crow::status::OK);
        res.set_header("Content-Type", "application/json");
        res.body = model_details_json.dump();
        return res;
    }
} // namespace honeypot::api
