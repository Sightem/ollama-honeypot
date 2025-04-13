#pragma once

#include <crow.h>
#include <nlohmann/json_fwd.hpp>

namespace honeypot::config
{
	struct HoneypotConfig;
}

namespace honeypot::api
{
	crow::response handle_version(const config::HoneypotConfig& config);
} // namespace honeypot::api
