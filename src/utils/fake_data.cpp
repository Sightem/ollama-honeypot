#include <algorithm>

#include <nlohmann/json.hpp>

#include "utils/fake_data.hpp"
#include "utils/config.hpp"


namespace honeypot::utils::fake_data
{
	nlohmann::json generate_error(std::string_view message)
	{
		return {{"error", message.data()}};
	}

	nlohmann::json generate_ok_status()
	{
		return nlohmann::json{{"status", "success"}};
	}

	const config::TagModelInfo* find_model_info(
		const std::string_view model_name,
		const std::vector<config::TagModelInfo>& models
	)
	{
		const auto it = std::ranges::find_if(models,
		                                     [&] (const config::TagModelInfo& m) {
			                                     return m.name == model_name;
		                                     });

		return (it != models.end()) ? &(*it) : nullptr;
	}

	nlohmann::json generate_model_list_json(
		const std::vector<config::TagModelInfo>& tag_models
	)
	{
		return {"models", tag_models};
	}
} // namespace honeypot::utils::fake_data
