#pragma once

#include "utils/config.hpp" // Includes TagModelInfo
#include <nlohmann/json_fwd.hpp>
#include <tsl/robin_map.h> // Keep for show_file_map_ and show_cache_
#include <vector>          // Use vector
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
		// Note: Consider storing only needed fields instead of the whole TagModelInfo
		// if memory becomes a concern, but copying is simpler initially.
		config::TagModelInfo base_info;
		std::chrono::steady_clock::time_point expires_at;
		uint64_t size_vram = 0; // Often matches base_info.size in Ollama
	};


	class HoneypotState {
	public:
		explicit HoneypotState(const config::HoneypotConfig& config);

		// --- Read Operations ---
		std::vector<config::TagModelInfo> get_available_models();
		std::vector<LoadedModelInfo> get_loaded_models();
		std::optional<std::string> get_detail_file_path(std::string_view model_name);
		std::optional<nlohmann::json> get_cached_detail(std::string_view file_path);

		// --- Write Operations ---
		void cache_detail(std::string_view file_path, nlohmann::json detail);
		bool delete_model(std::string_view model_name);
		bool load_or_update_model(std::string_view model_name, std::chrono::seconds keep_alive);

		// --- Future Write Operations ---
		// bool pull_model(...);

	private:
		// --- State Data ---
		// *** Use std::vector for these ***
		std::vector<config::TagModelInfo> available_models_;
		std::vector<LoadedModelInfo> loaded_models_;
		// *** Keep robin_map for these as key-based lookup is primary ***
		tsl::robin_map<std::string, std::string> show_file_map_;
		tsl::robin_map<std::string, nlohmann::json> show_cache_;

		// --- Synchronization ---
		mutable std::shared_mutex state_mutex_; // Protects available_models_, show_file_map_, loaded_models_
		std::mutex cache_mutex_;                // Protects show_cache_
	};

} // namespace honeypot::state