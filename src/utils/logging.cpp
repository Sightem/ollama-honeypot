#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <vector>
#include <memory>
#include <stdexcept>
#include <chrono>
#include <fmt/core.h>
#include <fmt/chrono.h>
#include <nlohmann/json.hpp>
#include <crow.h>

#include "utils/logging.hpp"
#include "utils/config.hpp"

namespace honeypot::config
{
    struct HoneypotConfig;
}

namespace honeypot::utils
{
    namespace
    {
        std::shared_ptr<spdlog::logger> operational_logger_instance;
        std::shared_ptr<spdlog::logger> request_logger_instance;
        bool logging_initialized = false;
    }

    void init_logging(const config::HoneypotConfig& config)
    {
        if (logging_initialized)
        {
            if (operational_logger_instance)
            {
                operational_logger_instance->warn("Attempted to initialize logging more than once.");
            }
            return;
        }

        try
        {
            const auto& [log_level,
                log_outputs,
                log_file_path,
                log_pattern,
                request_log_path] = config.logging;

            std::vector<spdlog::sink_ptr> operational_sinks;

            if (log_outputs.empty())
            {
                operational_sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
                std::cerr << "[WARN] No log outputs specified in config, defaulting to stdout for operational logs." <<
                        std::endl;
            }
            else
            {
                for (const auto& output_type : log_outputs)
                {
                    if (output_type == "stdout")
                    {
                        operational_sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
                    }
                    else if (output_type == "stderr")
                    {
                        operational_sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
                    }
                    else if (output_type == "file")
                    {
                        if (log_file_path.empty())
                        {
                            throw std::runtime_error(
                                "Logging config error: 'file' output specified but 'log_file_path' is empty.");
                        }
                        operational_sinks.push_back(
                            std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file_path, true));
                    }
                    else
                    {
                        throw std::runtime_error(fmt::format("Logging config error: Unknown log_output type '{}'",
                                                             output_type));
                    }
                }
            }

            operational_logger_instance = std::make_shared<spdlog::logger>(
                "honeypot_ops", operational_sinks.begin(), operational_sinks.end());

            operational_logger_instance->set_level(spdlog::level::from_str(log_level));
            operational_logger_instance->set_pattern(log_pattern);
            operational_logger_instance->flush_on(spdlog::level::warn);
            spdlog::register_logger(operational_logger_instance);

            spdlog::set_default_logger(operational_logger_instance);

            operational_logger_instance->info("Operational logging initialized.");


            if (request_log_path.empty())
            {
                operational_logger_instance->warn("'request_log_path' is empty, request logging disabled.");
                request_logger_instance = nullptr;
            }
            else
            {
                auto request_file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                    request_log_path, true);

                request_logger_instance = std::make_shared<spdlog::logger>("honeypot_req", request_file_sink);

                request_logger_instance->set_pattern("%v");
                request_logger_instance->set_level(spdlog::level::info);
                request_logger_instance->flush_on(spdlog::level::info);
                spdlog::register_logger(request_logger_instance);

                operational_logger_instance->info("Request logging initialized to file: {}", request_log_path);
            }

            logging_initialized = true; // Set flag
        }
        catch (const spdlog::spdlog_ex& ex)
        {
            throw std::runtime_error(fmt::format("Logger initialization failed (spdlog error): {}", ex.what()));
        } catch (const std::exception& ex)
        {
            throw std::runtime_error(fmt::format("General logging initialization failed: {}", ex.what()));
        }
    }

    std::shared_ptr<spdlog::logger> get_operational_logger()
    {
        if (!logging_initialized || !operational_logger_instance)
        {
            throw std::runtime_error("Operational logger requested before successful initialization.");
        }
        return operational_logger_instance;
    }

    void log_request(const crow::request& req, const crow::response& res)
    {
        if (!request_logger_instance)
        {
            return;
        }

        try
        {
            nlohmann::json log_entry;

            log_entry["timestamp"] = fmt::format("{:%Y-%m-%dT%H:%M:%S}Z",
                                                 fmt::gmtime(
                                                     std::chrono::system_clock::to_time_t(
                                                         std::chrono::system_clock::now())));
            log_entry["source_ip"] = req.remote_ip_address;
            // log_entry["source_port"] = req.remote_port; // Placeholder

            log_entry["method"] = crow::method_name(req.method);
            log_entry["url"] = req.url;

            nlohmann::json headers_json = nlohmann::json::object();
            for (const auto& [fst, snd] : req.headers)
            {
                headers_json[fst] = snd;
            }
            log_entry["headers"] = std::move(headers_json);
            if (req.headers.contains("User-Agent"))
            {
                log_entry["user_agent"] = req.get_header_value("User-Agent");
            }

            log_entry["body"] = req.body;
            constexpr size_t max_body_log_size = 4096;
            if (req.body.length() > max_body_log_size)
            {
                log_entry["body_truncated"] = true;
                log_entry["body"] = req.body.substr(0, max_body_log_size);
            }

            log_entry["response_status"] = res.code;

            log_entry["_future_fields"] = nlohmann::json::object();

            request_logger_instance->info(log_entry.dump());
        }
        catch (const std::exception& e)
        {
            if (operational_logger_instance)
            {
                operational_logger_instance->error("Failed to create or write request log entry: {}", e.what());
            }
        }
    }
} // namespace honeypot::utils
