#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

#include <nlohmann/json.hpp>
#include <tsl/robin_map.h>

using json = nlohmann::json;

namespace honeypot::config
{
    struct ModelDetails
    {
        std::string format = "gguf";
        std::string family = "unknown";
        std::optional<std::vector<std::string>> families = std::nullopt;
        std::string parameter_size = "N/A";
        std::string quantization_level = "unknown";
    };
    void to_json(json& j, const ModelDetails& p);
    void from_json(const json& j, ModelDetails& p);

    struct TagModelInfo
    {
        std::string name = "default:latest";
        std::string modified_at = "1970-01-01T00:00:00.000000Z";
        uint64_t size = 0;
        std::string digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        ModelDetails details{};
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(TagModelInfo,
                                                    name,
                                                    modified_at,
                                                    size,
                                                    digest,
                                                    details)

    struct ServerConfig
    {
        std::string listen_address = "0.0.0.0";
        uint16_t listen_port = 11434;
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(ServerConfig,
                                                    listen_address,
                                                    listen_port)

    struct LoggingConfig
    {
        std::string log_level = "info";
        std::vector<std::string> log_outputs = {"stdout"};
        std::string log_file_path = "honeypot_operational.log";
        std::string log_pattern = "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v";
        std::string request_log_path = "honeypot_requests.jsonl";
    };

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LoggingConfig,
                                                    log_level,
                                                    log_outputs,
                                                    log_file_path,
                                                    log_pattern,
                                                    request_log_path)

    struct ApiBehaviorConfig
    {
        std::string ollama_version = "0.6.0";
        std::vector<TagModelInfo> tag_models{};
        tsl::robin_map<std::string, std::string> show_file_map{};
    };
    void to_json(json& j, const ApiBehaviorConfig& p);
    void from_json(const json& j, ApiBehaviorConfig& p);


    struct HoneypotConfig
    {
        ServerConfig server{};
        LoggingConfig logging{};
        ApiBehaviorConfig api_behavior{};
    };
    void to_json(json& j, const HoneypotConfig& p);
    void from_json(const json& j, HoneypotConfig& p);


    HoneypotConfig load_config(std::string_view config_path);
} // namespace honeypot::config
