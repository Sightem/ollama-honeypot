#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <string_view>

#include <crow.h>

#include "utils/config.hpp"
#include "utils/logging.hpp"
#include "state/honeypot_state.hpp"
#include "api/version.hpp"
#include "api/delete.hpp"
#include "api/tags.hpp"

namespace
{
    // Anonymous namespace for Middleware
    struct RequestLoggingMiddleware
    {
        struct context
        {
        };

        void before_handle(crow::request&, crow::response&, context&)
        {
        }

        void after_handle(crow::request& req, crow::response& res, context&)
        {
            honeypot::utils::log_request(req, res);
        }
    };
} // end anonymous namespace

int main(int argc, char* argv[])
{
    std::string config_path = "config/honeypot.json";

    std::vector<std::string_view> args(argv, argv + argc);
    for (size_t i = 1; i < args.size(); ++i)
    {
        if ((args[i] == "-c" || args[i] == "--config") && (i + 1 < args.size()))
        {
            config_path = args[i + 1];
            std::cout << "[INFO] Using configuration path from command line: " << config_path << std::endl;
            break;
        }
        if (args[i] == "-h" || args[i] == "--help")
        {
            std::cout << "Usage: " << argv[0] << " [-c|--config <path_to_config.json>]" << std::endl;
            return 0;
        }
    }

    std::shared_ptr<honeypot::config::HoneypotConfig> config_ptr;
    try
    {
        config_ptr = std::make_shared<honeypot::config::HoneypotConfig>(
            honeypot::config::load_config(config_path)
        );
    }
    catch (const std::exception& e)
    {
        std::cerr << "FATAL: Failed to load configuration '" << config_path << "': " << e.what() << std::endl;
        return 1;
    }

    try
    {
        honeypot::utils::init_logging(*config_ptr);
    }
    catch (const std::exception& e)
    {
        std::cerr << "FATAL: Failed to initialize logging: " << e.what() << std::endl;
        return 1;
    }

    const auto logger = honeypot::utils::get_operational_logger();
    logger->info("Configuration loaded successfully from '{}'", config_path);
    logger->info("Logging initialized.");

    std::shared_ptr<honeypot::state::HoneypotState> state_ptr;
    try
    {
        state_ptr = std::make_shared<honeypot::state::HoneypotState>(*config_ptr);
    }
    catch (const std::exception& e)
    {
        logger->critical("FATAL: Failed to initialize honeypot state: {}", e.what());
        return 1;
    }
    logger->info("Honeypot state initialized.");

    crow::App<RequestLoggingMiddleware> app;
    logger->info("Request logging middleware registered globally.");
    app.server_name("");


    // GET /api/version
    CROW_ROUTE(app, "/api/version")
            .methods(crow::HTTPMethod::Get)
            ([config_ptr] {
                // Only capture config needed
                return honeypot::api::handle_version(*config_ptr);
            });

    // GET /api/tags
    CROW_ROUTE(app, "/api/tags")
            .methods(crow::HTTPMethod::Get)
            ([state_ptr] {
                // Capture state
                return honeypot::api::handle_tags(state_ptr);
            });

    // DELETE /api/delete
    CROW_ROUTE(app, "/api/delete")
            .methods(crow::HTTPMethod::Delete)
            ([state_ptr] (const crow::request& req) {
                return honeypot::api::handle_delete(state_ptr, req);
            });


    logger->info("API routes registered.");

    const auto& [listen_address, listen_port] = config_ptr->server;
    logger->warn("Starting Honeypot server on {}:{}", listen_address, listen_port);

    app.bindaddr(listen_address)
            .port(listen_port)
            .multithreaded()
            .run();

    logger->warn("Honeypot server shutting down.");
    spdlog::shutdown();
}
