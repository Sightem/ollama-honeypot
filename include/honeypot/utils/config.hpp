#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <filesystem> // Used in config.cpp

#include <nlohmann/json.hpp>
#include <tsl/robin_map.h>

namespace honeypot::config
{
    struct ModelDetails
    {
        std::string format = "gguf";
        std::string family = "unknown";
        std::string parent_model{};
        std::optional<std::vector<std::string> > families = std::nullopt;
        std::string parameter_size = "N/A";
        std::string quantization_level = "unknown";
    };
    void to_json(nlohmann::ordered_json& j, const ModelDetails& p);
    void from_json(const nlohmann::ordered_json& j, ModelDetails& p);

    struct TagModelInfo
    {
        std::string name = "default:latest";
        std::string model = "default:latest";
        std::string modified_at = "1970-01-01T00:00:00.000000Z";
        uint64_t size = 0;
        std::string digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        ModelDetails details{};
    };
    void to_json(nlohmann::ordered_json& j, const TagModelInfo& p);
    void from_json(const nlohmann::ordered_json& j, TagModelInfo& p);

    struct ServerConfig
    {
        std::string listen_address = "0.0.0.0";
        uint16_t listen_port = 11434;
    };
    void to_json(nlohmann::ordered_json& j, const ServerConfig& p);
    void from_json(const nlohmann::ordered_json& j, ServerConfig& p);

    struct LoggingConfig
    {
        std::string log_level = "info";
        std::vector<std::string> log_outputs = {"stdout"};
        std::string log_file_path = "honeypot_operational.log";
        std::string log_pattern = "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v";
        std::string request_log_path = "honeypot_requests.jsonl";
    };
    void to_json(nlohmann::ordered_json& j, const LoggingConfig& p);
    void from_json(const nlohmann::ordered_json& j, LoggingConfig& p);

    struct ApiBehaviorConfig
    {
        std::string ollama_version = "0.6.0";
        std::vector<TagModelInfo> tag_models{};
        tsl::robin_map<std::string, std::string> show_file_map{};
    };
    void to_json(nlohmann::ordered_json& j, const ApiBehaviorConfig& p);
    void from_json(const nlohmann::ordered_json& j, ApiBehaviorConfig& p);

    struct HoneypotConfig
    {
        ServerConfig server{};
        LoggingConfig logging{};
        ApiBehaviorConfig api_behavior{};
    };
    void to_json(nlohmann::ordered_json& j, const HoneypotConfig& p);
    void from_json(const nlohmann::ordered_json& j, HoneypotConfig& p);

    HoneypotConfig load_config(std::string_view config_path);
} // namespace honeypot::config
