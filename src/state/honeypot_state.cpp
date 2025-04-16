#include <vector>
#include <string>
#include <string_view>
#include <chrono>
#include <shared_mutex>
#include <mutex>
#include <optional>
#include <algorithm>
#include <ranges>

#include <nlohmann/json.hpp>

#include "state/honeypot_state.hpp"
#include "utils/logging.hpp"

namespace honeypot::state
{

    HoneypotState::HoneypotState(const config::HoneypotConfig& config) : available_models_(config.api_behavior.tag_models),
                                                                         show_file_map_(config.api_behavior.show_file_map)
    {
        const auto logger = utils::get_operational_logger();
        logger->debug("HoneypotState initialized with {} available models and {} detail file mappings.",
                      available_models_.size(), show_file_map_.size());
    }


    std::vector<config::TagModelInfo> HoneypotState::get_available_models()
    {
        std::shared_lock lock(state_mutex_);
        return available_models_;
    }

    std::vector<LoadedModelInfo> HoneypotState::get_loaded_models()
    {
        std::shared_lock lock(state_mutex_);

        std::vector<LoadedModelInfo> loaded_vector;
        const auto now = std::chrono::steady_clock::now();

        loaded_vector.reserve(loaded_models_.size());

        auto non_expired_view = loaded_models_ | std::views::filter([&now](const auto& lm){ return lm.expires_at > now; });
        std::ranges::copy(non_expired_view, std::back_inserter(loaded_vector));

        return loaded_vector;
    }

    std::optional<std::string> HoneypotState::get_detail_file_path(const std::string_view model_name)
    {
        std::shared_lock lock(state_mutex_);

        const auto it = show_file_map_.find(model_name.data());

        if (it != show_file_map_.end())
        {
            return it->second;
        }
        else
        {
            return std::nullopt;
        }
    }

    std::optional<nlohmann::ordered_json> HoneypotState::get_cached_detail(const std::string_view file_path)
    {
        std::scoped_lock lock(cache_mutex_);

        const auto it = show_cache_.find(file_path.data());
        if (it != show_cache_.end())
        {
            return it->second;
        }
        else
        {
            return std::nullopt;
        }
    }

    void HoneypotState::cache_detail(const std::string_view file_path, nlohmann::ordered_json detail)
    {
        std::scoped_lock lock(cache_mutex_);
        show_cache_[file_path.data()] = std::move(detail);
    }

    bool HoneypotState::delete_model(const std::string_view model_name)
    {
        std::scoped_lock lock(state_mutex_);

        bool deleted_from_available = false;
        bool deleted_from_loaded = false;

        const auto new_end_available = std::ranges::remove_if(available_models_,
                                                              [&] (const config::TagModelInfo& m) {
                                                                  return m.name == model_name;
                                                              }).begin();
        if (new_end_available != available_models_.end())
        {
            available_models_.erase(new_end_available, available_models_.end());
            deleted_from_available = true;
        }

        const auto new_end_loaded = std::ranges::remove_if(loaded_models_,
                                                           [&] (const LoadedModelInfo& lm) {
                                                               return lm.base_info.name == model_name;
                                                           }).begin();
        if (new_end_loaded != loaded_models_.end())
        {
            loaded_models_.erase(new_end_loaded, loaded_models_.end());
            deleted_from_loaded = true;
        }

        show_file_map_.erase(model_name.data());


        const bool actually_deleted = deleted_from_available || deleted_from_loaded;
        if (actually_deleted)
        {
            const auto logger = utils::get_operational_logger();
            logger->info("Simulated delete for model '{}'", model_name);
        }

        return actually_deleted;
    }

    bool HoneypotState::load_or_update_model(const std::string_view model_name,
                                             const std::chrono::seconds keep_alive)
    {
        std::scoped_lock lock(state_mutex_);

        const auto available_it = std::ranges::find_if(available_models_,
                                                 [&] (const config::TagModelInfo& m) {
                                                     return m.name == model_name;
                                                 });

        if (available_it == available_models_.end())
        {
            const auto logger = utils::get_operational_logger();
            logger->warn("Attempted to load unknown model '{}' (not in available models)", model_name);
            return false; // Model not configured
        }

        const auto expires_at = std::chrono::steady_clock::now() + keep_alive;

        const auto loaded_it = std::ranges::find_if(loaded_models_,
                                              [&] (const LoadedModelInfo& lm) {
                                                  return lm.base_info.name == model_name;
                                              });

        if (loaded_it != loaded_models_.end())
        {
            loaded_it->expires_at = expires_at;
            const auto logger = utils::get_operational_logger();
            logger->debug("Updated keep_alive for loaded model '{}'", model_name);
        }
        else
        {
            const config::TagModelInfo& base_info = *available_it;
            LoadedModelInfo new_loaded_info;
            new_loaded_info.base_info = base_info;
            new_loaded_info.expires_at = expires_at;
            new_loaded_info.size_vram = base_info.size;

            loaded_models_.push_back(std::move(new_loaded_info));
            const auto logger = utils::get_operational_logger();
            logger->info("Simulated load for model '{}', expires in {}s", model_name, keep_alive.count());
        }

        return true;
    }
} // namespace honeypot::state
