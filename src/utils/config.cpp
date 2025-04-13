#include <fstream>
#include <stdexcept>
#include <string_view>

#include <fmt/core.h>
#include <fmt/ranges.h>
#include <nlohmann/json.hpp>

#include "utils/config.hpp"
namespace fs = std::filesystem; // Alias for convenience

namespace honeypot::config
{
    // --- Manual JSON Serialization for ModelDetails (from previous step) ---
    void to_json(json& j, const ModelDetails& p)
    {
        j = json{
            {"format", p.format},
            {"family", p.family},
            {"families", p.families.has_value() ? json(p.families.value()) : nullptr},
            {"parameter_size", p.parameter_size},
            {"quantization_level", p.quantization_level}
        };
    }

    void from_json(const json& j, ModelDetails& p)
    {
        ModelDetails defaults; // For default values
        p.format = j.value("format", defaults.format);
        p.family = j.value("family", defaults.family);
        p.parameter_size = j.value("parameter_size", defaults.parameter_size);
        p.quantization_level = j.value("quantization_level", defaults.quantization_level);

        if (j.contains("families") && !j.at("families").is_null())
        {
            p.families = j.at("families").get<std::vector<std::string> >();
        }
        else
        {
            p.families = std::nullopt;
        }
    }

    void to_json(json& j, const ApiBehaviorConfig& p)
    {
        j = json{
            {"ollama_version", p.ollama_version},
            {"tag_models", p.tag_models}
        };

        json show_map_json = json::object();
        for (const auto& [fst, snd] : p.show_file_map)
        {
            show_map_json[fst] = snd;
        }
        j["show_file_map"] = std::move(show_map_json);
    }

    void from_json(const json& j, ApiBehaviorConfig& p)
    {
        ApiBehaviorConfig defaults;

        p.ollama_version = j.value("ollama_version", defaults.ollama_version);
        p.tag_models = j.value("tag_models", defaults.tag_models);

        p.show_file_map.clear();

        if (j.contains("show_file_map") && j.at("show_file_map").is_object())
        {
            const auto& show_map_json = j.at("show_file_map");
            p.show_file_map.reserve(show_map_json.size()); // Optional: reserve

            for (auto it = show_map_json.begin(); it != show_map_json.end(); ++it)
            {
                if (it.value().is_string())
                {
                    p.show_file_map.emplace(it.key(), it.value().get<std::string>());
                }
                else
                {
                    throw json::type_error::create(302,
                                                   fmt::format(
                                                       "Type error in 'show_file_map': value for key '{}' is not a string.",
                                                       it.key()), &it.value());
                }
            }
        }
        else
        {
            p.show_file_map = defaults.show_file_map;
        }
    }

    void to_json(json& j, const HoneypotConfig& p)
    {
        j = json{
            {"server", p.server},
            {"logging", p.logging},
            {"api_behavior", p.api_behavior}
        };
    }

    void from_json(const json& j, HoneypotConfig& p)
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
            json config_json;
            config_file >> config_json;

            loaded_config = config_json.get<HoneypotConfig>();
        }
        catch (const json::parse_error& e)
        {
            throw std::runtime_error(fmt::format("Failed to parse configuration file '{}': JSON syntax error - {}",
                                                 config_path, e.what()));
        } catch (const json::exception& e)
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
