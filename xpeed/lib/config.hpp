#pragma once

#include <chrono>
#include <cstddef>

namespace xpeed
{
/**
 * Network variants with different genesis blocks and network parameters
 * @warning Enum values are used for comparison; do not change.
 */
enum class xpd_networks
{
	// Low work parameters, publicly known genesis key, test IP ports
	xpd_test_network = 0,
	
	// Normal work parameters, secret beta genesis key, beta IP ports
	xpd_beta_network = 1,
	
	// Normal work parameters, secret live key, live IP ports
	xpd_live_network = 2,
	
};
xpeed::xpd_networks constexpr xpd_network = xpd_networks::ACTIVE_NETWORK;
bool constexpr is_live_network = xpd_network == xpd_networks::xpd_live_network;
bool constexpr is_beta_network = xpd_network == xpd_networks::xpd_beta_network;
bool constexpr is_test_network = xpd_network == xpd_networks::xpd_test_network;

std::chrono::milliseconds const transaction_timeout = std::chrono::milliseconds (1000);
}
