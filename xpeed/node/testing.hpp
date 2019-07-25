#pragma once

#include <chrono>
#include <xpeed/lib/errors.hpp>
#include <xpeed/node/node.hpp>

namespace xpeed
{
/** Test-system related error codes */
enum class error_system
{
	generic = 1,
	deadline_expired
};
class system
{
public:
	system (uint16_t, uint16_t);
	~system ();
	void generate_activity (xpeed::node &, std::vector<xpeed::account> &);
	void generate_mass_activity (uint32_t, xpeed::node &);
	void generate_usage_traffic (uint32_t, uint32_t, size_t);
	void generate_usage_traffic (uint32_t, uint32_t);
	xpeed::account get_random_account (std::vector<xpeed::account> &);
	xpeed::uint128_t get_random_amount (xpeed::transaction const &, xpeed::node &, xpeed::account const &);
	void generate_rollback (xpeed::node &, std::vector<xpeed::account> &);
	void generate_change_known (xpeed::node &, std::vector<xpeed::account> &);
	void generate_change_unknown (xpeed::node &, std::vector<xpeed::account> &);
	void generate_receive (xpeed::node &);
	void generate_send_new (xpeed::node &, std::vector<xpeed::account> &);
	void generate_send_existing (xpeed::node &, std::vector<xpeed::account> &);
	std::shared_ptr<xpeed::wallet> wallet (size_t);
	xpeed::account account (xpeed::transaction const &, size_t);
	/**
	 * Polls, sleep if there's no work to be done (default 50ms), then check the deadline
	 * @returns 0 or xpeed::deadline_expired
	 */
	std::error_code poll (const std::chrono::nanoseconds & sleep_time = std::chrono::milliseconds (50));
	void stop ();
	void deadline_set (const std::chrono::duration<double, std::nano> & delta);
	boost::asio::io_context io_ctx;
	xpeed::alarm alarm;
	std::vector<std::shared_ptr<xpeed::node>> nodes;
	xpeed::logging logging;
	xpeed::work_pool work;
	std::chrono::time_point<std::chrono::steady_clock, std::chrono::duration<double>> deadline{ std::chrono::steady_clock::time_point::max () };
	double deadline_scaling_factor{ 1.0 };
};
class landing_store
{
public:
	landing_store ();
	landing_store (xpeed::account const &, xpeed::account const &, uint64_t, uint64_t);
	landing_store (bool &, std::istream &);
	xpeed::account source;
	xpeed::account destination;
	uint64_t start;
	uint64_t last;
	void serialize (std::ostream &) const;
	bool deserialize (std::istream &);
	bool operator== (xpeed::landing_store const &) const;
};
class landing
{
public:
	landing (xpeed::node &, std::shared_ptr<xpeed::wallet>, xpeed::landing_store &, boost::filesystem::path const &);
	void write_store ();
	xpeed::uint128_t distribution_amount (uint64_t);
	void distribute_one ();
	void distribute_ongoing ();
	boost::filesystem::path path;
	xpeed::landing_store & store;
	std::shared_ptr<xpeed::wallet> wallet;
	xpeed::node & node;
	static int constexpr interval_exponent = 10;
	static std::chrono::seconds constexpr distribution_interval = std::chrono::seconds (1 << interval_exponent); // 1024 seconds
	static std::chrono::seconds constexpr sleep_seconds = std::chrono::seconds (7);
};
}
REGISTER_ERROR_CODES (xpeed, error_system);
