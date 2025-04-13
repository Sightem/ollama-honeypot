#pragma once

#include <spdlog/spdlog.h>
#include <crow.h>

#include <memory> // For std::shared_ptr

#include "utils/config.hpp"


namespace honeypot::utils
{
	void init_logging(const config::HoneypotConfig& config);

	std::shared_ptr<spdlog::logger> get_operational_logger();

	void log_request(const crow::request& req, const crow::response& res);
} // namespace honeypot::utils