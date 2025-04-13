#include <crow.h>
#include <iostream>
#include <string>
#include <memory>
#include <vector>

#include "utils/config.hpp"
#include "utils/logging.hpp"
#include "api/misc_handlers.hpp"

namespace
{
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
        /* whatever idc */
    }

    std::shared_ptr<honeypot::config::HoneypotConfig> config;
    try
    {
        config = std::make_shared<honeypot::config::HoneypotConfig>(
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
        honeypot::utils::init_logging(*config);
    }
    catch (const std::exception& e)
    {
        std::cerr << "FATAL: Failed to initialize logging: " << e.what() << std::endl;
        return 1;
    }

    auto logger = honeypot::utils::get_operational_logger();
    logger->info("Configuration loaded successfully from '{}'", config_path);
    logger->info("Logging initialized.");

    crow::App<RequestLoggingMiddleware> app;
    logger->info("Request logging middleware registered globally.");

    auto cfg_capture = config;

    CROW_ROUTE(app, "/api/version")
            .methods(crow::HTTPMethod::Get)
            ([cfg_capture] {
                return honeypot::api::handle_version(*cfg_capture);
            });

    // TODO: Add all other routes here later

    logger->info("API routes registered.");

    const auto& server_cfg = config->server;
    logger->warn("Starting Honeypot server on {}:{}", server_cfg.listen_address, server_cfg.listen_port);

    app.bindaddr(server_cfg.listen_address)
            .port(server_cfg.listen_port)
            .multithreaded()
            .run();

    logger->warn("Honeypot server shutting down.");
    spdlog::shutdown();
}
