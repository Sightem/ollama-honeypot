#include <fstream>
#include <stdexcept>
#include <string_view>
#include <filesystem>
#include <vector>
#include <optional>

#include <fmt/ranges.h>
#include <nlohmann/json.hpp>
#include <tsl/robin_map.h>

#include "utils/config.hpp"

namespace fs = std::filesystem;
using ordered_json = nlohmann::ordered_json;

namespace honeypot::config
{
    void to_json(ordered_json& j, const ModelDetails& p)
    {
        j["parent_model"] = p.parent_model;
        j["format"] = p.format;
        j["family"] = p.family;
        j["families"] = p.families.has_value() ? ordered_json(p.families.value()) : nullptr;
        j["parameter_size"] = p.parameter_size;
        j["quantization_level"] = p.quantization_level;
    }

    void from_json(const ordered_json& j, ModelDetails& p)
    {
        ModelDetails defaults;
        p.parent_model = j.value("parent_model", defaults.parent_model);
        p.format = j.value("format", defaults.format);
        p.family = j.value("family", defaults.family);
        p.parameter_size = j.value("parameter_size", defaults.parameter_size);
        p.quantization_level = j.value("quantization_level", defaults.quantization_level);


        if (j.contains("families") && !j.at("families").is_null())
        {
            p.families = j.at("families").get<std::vector<std::string>>();
        }
        else
        {
            p.families = std::nullopt;
        }
    }

    void to_json(ordered_json& j, const TagModelInfo& p)
    {
        j["name"] = p.name;
        j["model"] = p.model;
        j["modified_at"] = p.modified_at;
        j["size"] = p.size;
        j["digest"] = p.digest;
        // (will use the ordered_json to_json for ModelDetails)
        j["details"] = p.details;
    }

    void from_json(const ordered_json& j, TagModelInfo& p)
    {
        TagModelInfo defaults;
        p.name = j.value("name", defaults.name);
        p.model = j.value("model", defaults.model);
        p.modified_at = j.value("modified_at", defaults.modified_at);
        p.size = j.value("size", defaults.size);
        p.digest = j.value("digest", defaults.digest);
        p.details = j.value("details", defaults.details); // delegate details deserialization
    }

    void to_json(ordered_json& j, const ServerConfig& p)
    {
        j["listen_address"] = p.listen_address;
        j["listen_port"] = p.listen_port;
    }

    void from_json(const ordered_json& j, ServerConfig& p)
    {
        ServerConfig defaults;
        p.listen_address = j.value("listen_address", defaults.listen_address);
        p.listen_port = j.value("listen_port", defaults.listen_port);
    }

    void to_json(ordered_json& j, const LoggingConfig& p)
    {
        j["log_level"] = p.log_level;
        j["log_outputs"] = p.log_outputs;
        j["log_file_path"] = p.log_file_path;
        j["log_pattern"] = p.log_pattern;
        j["request_log_path"] = p.request_log_path;
    }

    void from_json(const ordered_json& j, LoggingConfig& p)
    {
        LoggingConfig defaults;
        p.log_level = j.value("log_level", defaults.log_level);
        p.log_outputs = j.value("log_outputs", defaults.log_outputs);
        p.log_file_path = j.value("log_file_path", defaults.log_file_path);
        p.log_pattern = j.value("log_pattern", defaults.log_pattern);
        p.request_log_path = j.value("request_log_path", defaults.request_log_path);
    }

    void to_json(ordered_json& j, const ApiBehaviorConfig& p)
    {
        j["ollama_version"] = p.ollama_version;
        j["tag_models"] = p.tag_models;

        ordered_json show_map_json = ordered_json::object();
        for (const auto& [key, val] : p.show_file_map)
        {
            show_map_json[key] = val;
        }
        j["show_file_map"] = std::move(show_map_json);
    }

    void from_json(const ordered_json& j, ApiBehaviorConfig& p)
    {
        ApiBehaviorConfig defaults;
        p.ollama_version = j.value("ollama_version", defaults.ollama_version);
        p.tag_models = j.value("tag_models", defaults.tag_models);

        for (auto& model_info : p.tag_models)
        {
            if (model_info.model.empty() || model_info.model == "default:latest")
            {
                model_info.model = model_info.name;
            }
        }

        p.show_file_map.clear();
        if (j.contains("show_file_map") && j.at("show_file_map").is_object())
        {
            const auto& show_map_json = j.at("show_file_map");
            p.show_file_map.reserve(show_map_json.size());
            for (auto it = show_map_json.begin(); it != show_map_json.end(); ++it)
            {
                if (it.value().is_string())
                {
                    p.show_file_map.emplace(it.key(), it.value().get<std::string>());
                }
                else
                {
                    throw nlohmann::json::type_error::create(302,
                                                             fmt::format(
                                                                 "Type error in 'show_file_map': value for key '{}' is not a string.",
                                                                 it.key()), &it.value());
                }
            }
        }
    }

    void to_json(ordered_json& j, const HoneypotConfig& p)
    {
        j["server"] = p.server; // delegates to ServerConfig's to_json
        j["logging"] = p.logging; // delegates to LoggingConfig's to_json
        j["api_behavior"] = p.api_behavior; // delegates to ApiBehaviorConfig's to_json
    }

    void from_json(const ordered_json& j, HoneypotConfig& p)
    {
        HoneypotConfig defaults;
        p.server = j.value("server", defaults.server);
        p.logging = j.value("logging", defaults.logging);
        p.api_behavior = j.value("api_behavior", defaults.api_behavior);
    }


    HoneypotConfig load_config(std::string_view config_path)
    {
        std::ifstream config_file(config_path.data());
        if (!config_file.is_open())
        {
            throw std::runtime_error(fmt::format("Failed to open configuration file: {}", config_path));
        }

        HoneypotConfig loaded_config;

        try
        {
            ordered_json config_json;
            config_file >> config_json;
            loaded_config = config_json.get<HoneypotConfig>();
        }
        catch (const nlohmann::json::parse_error& e)
        {
            throw std::runtime_error(fmt::format("Failed to parse configuration file '{}': JSON syntax error - {}",
                                                 config_path, e.what()));
        } catch (const nlohmann::json::exception& e)
        {
            throw std::runtime_error(fmt::format("Failed to process configuration file '{}': JSON error - {}",
                                                 config_path, e.what()));
        } catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format(
                "An unexpected error occurred while reading configuration file '{}': {}",
                config_path, e.what()));
        }

        if (loaded_config.server.listen_port == 0)
        {
            throw std::runtime_error("Configuration error: 'server.listen_port' cannot be 0.");
        }

        fs::path config_dir = fs::path(config_path).parent_path();
        std::vector<std::string> missing_files;
        for (const auto& val : loaded_config.api_behavior.show_file_map | std::views::values)
        {
            fs::path detail_path = config_dir / val;
            std::error_code ec;
            if (!fs::exists(detail_path, ec) || ec)
            {
                missing_files.push_back(val);
            }
        }

        if (!missing_files.empty())
        {
            throw std::runtime_error(fmt::format(
                "Configuration error: The following files listed in 'show_file_map' were not found relative to '{}': {}",
                config_path, fmt::join(missing_files, ", ")));
        }

        return loaded_config;
    }
} // namespace honeypot::config
