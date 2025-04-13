#pragma once
#include <nlohmann/json_fwd.hpp>
#include <string_view>
#include <vector>

namespace honeypot::config
{
	struct TagModelInfo;
}

namespace honeypot::utils::fake_data
{
	nlohmann::ordered_json generate_error(std::string_view message);

	nlohmann::ordered_json generate_ok_status();

	const config::TagModelInfo* find_model_info(
		std::string_view model_name,
		const std::vector<config::TagModelInfo>& models
	);

	nlohmann::ordered_json generate_model_list_json(
		const std::vector<config::TagModelInfo>& tag_models
	);

	// TODO: generate_ps_list_json
	// TODO: generate_embedding_response
	// TODO: generate_completion_chunk
	// TODO: generate_chat_chunk
	// TODO: generate_final_stats
	// TODO: generate_pull_progress_chunk
	// TODO: generate_push_progress_chunk
	// TODO: generate_create_status_chunk
	// TODO: generate_timestamp_iso8601
} // namespace honeypot::utils::fake_data
