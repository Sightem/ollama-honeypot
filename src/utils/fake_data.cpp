#include <algorithm>

#include <nlohmann/json.hpp>

#include "utils/fake_data.hpp"
#include "utils/config.hpp"


namespace honeypot::utils::fake_data
{
	nlohmann::ordered_json generate_error(std::string_view message)
	{
		return{{"error", message}};
	}

	nlohmann::ordered_json generate_ok_status()
	{
		return {{"status", "success"}};
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

	nlohmann::ordered_json generate_model_list_json(
		const std::vector<config::TagModelInfo>& tag_models
	)
	{
		nlohmann::ordered_json root = nlohmann::ordered_json::object();
		nlohmann::ordered_json models_array = nlohmann::ordered_json::array();

		for (const auto& model_info : tag_models)
		{
			models_array.push_back(model_info);
		}

		root["models"] = std::move(models_array);
		return root;
	}
} // namespace honeypot::utils::fake_data
