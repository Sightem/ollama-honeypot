#pragma once

#include "utils/config.hpp"
#include <nlohmann/json_fwd.hpp>
#include <tsl/robin_map.h>
#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <memory>
#include <shared_mutex>
#include <mutex>
#include <chrono>

namespace honeypot::state {

	struct LoadedModelInfo
	{
		config::TagModelInfo base_info;
		std::chrono::steady_clock::time_point expires_at;
		uint64_t size_vram = 0;
	};


	class HoneypotState {
	public:
		explicit HoneypotState(const config::HoneypotConfig& config);

		std::vector<config::TagModelInfo> get_available_models();
		std::vector<LoadedModelInfo> get_loaded_models();
		std::optional<std::string> get_detail_file_path(std::string_view model_name);
		std::optional<nlohmann::ordered_json> get_cached_detail(std::string_view file_path);

		void cache_detail(std::string_view file_path, nlohmann::ordered_json detail);
		bool delete_model(std::string_view model_name);
		bool load_or_update_model(std::string_view model_name, std::chrono::seconds keep_alive);

		// bool pull_model(...);

	private:
		std::vector<config::TagModelInfo> available_models_;
		std::vector<LoadedModelInfo> loaded_models_;
		tsl::robin_map<std::string, std::string> show_file_map_;
		tsl::robin_map<std::string, nlohmann::ordered_json> show_cache_;

		mutable std::shared_mutex state_mutex_; // protects available_models_, show_file_map_, loaded_models_
		std::mutex cache_mutex_;                // protects show_cache_
	};

} // namespace honeypot::state