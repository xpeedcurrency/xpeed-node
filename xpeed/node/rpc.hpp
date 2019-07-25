#pragma once

#include <atomic>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <xpeed/lib/blocks.hpp>
#include <xpeed/lib/errors.hpp>
#include <xpeed/lib/jsonconfig.hpp>
#include <xpeed/secure/blockstore.hpp>
#include <xpeed/secure/utility.hpp>
#include <unordered_map>

namespace xpeed
{
void error_response (std::function<void(boost::property_tree::ptree const &)> response_a, std::string const & message_a);
class node;
/** Configuration options for RPC TLS */
class rpc_secure_config
{
public:
	rpc_secure_config ();
	xpeed::error serialize_json (xpeed::jsonconfig &) const;
	xpeed::error deserialize_json (xpeed::jsonconfig &);

	/** If true, enable TLS */
	bool enable;
	/** If true, log certificate verification details */
	bool verbose_logging;
	/** Must be set if the private key PEM is password protected */
	std::string server_key_passphrase;
	/** Path to certificate- or chain file. Must be PEM formatted. */
	std::string server_cert_path;
	/** Path to private key file. Must be PEM formatted.*/
	std::string server_key_path;
	/** Path to dhparam file */
	std::string server_dh_path;
	/** Optional path to directory containing client certificates */
	std::string client_certs_path;
};
class rpc_config
{
public:
	rpc_config (bool = false);
	xpeed::error serialize_json (xpeed::jsonconfig &) const;
	xpeed::error deserialize_json (xpeed::jsonconfig &);
	boost::asio::ip::address_v6 address;
	uint16_t port;
	bool enable_control;
	uint64_t frontier_request_limit;
	uint64_t chain_request_limit;
	rpc_secure_config secure;
	uint8_t max_json_depth;
	bool enable_sign_hash;
};
enum class payment_status
{
	not_a_status,
	unknown,
	nothing, // Timeout and nothing was received
	//insufficient, // Timeout and not enough was received
	//over, // More than requested received
	//success_fork, // Amount received but it involved a fork
	success // Amount received
};
class wallet;
class payment_observer;
class rpc
{
public:
	rpc (boost::asio::io_context &, xpeed::node &, xpeed::rpc_config const &);
	virtual ~rpc () = default;

	/**
	 * Start serving RPC requests if \p rpc_enabled_a, otherwise this will only
	 * add a block observer since requests may still arrive via IPC.
	 */
	void start (bool rpc_enabled_a = true);
	void add_block_observer ();
	virtual void accept ();
	void stop ();
	void observer_action (xpeed::account const &);
	boost::asio::ip::tcp::acceptor acceptor;
	std::mutex mutex;
	std::unordered_map<xpeed::account, std::shared_ptr<xpeed::payment_observer>> payment_observers;
	xpeed::rpc_config config;
	xpeed::node & node;
	bool on;
	static uint16_t const rpc_port = xpeed::is_live_network ? 7076 : 55000;
};
class rpc_connection : public std::enable_shared_from_this<xpeed::rpc_connection>
{
public:
	rpc_connection (xpeed::node &, xpeed::rpc &);
	virtual ~rpc_connection () = default;
	virtual void parse_connection ();
	virtual void read ();
	virtual void prepare_head (unsigned version, boost::beast::http::status status = boost::beast::http::status::ok);
	virtual void write_result (std::string body, unsigned version, boost::beast::http::status status = boost::beast::http::status::ok);
	std::shared_ptr<xpeed::node> node;
	xpeed::rpc & rpc;
	boost::asio::ip::tcp::socket socket;
	boost::beast::flat_buffer buffer;
	boost::beast::http::request<boost::beast::http::string_body> request;
	boost::beast::http::response<boost::beast::http::string_body> res;
	std::atomic_flag responded;
};
class payment_observer : public std::enable_shared_from_this<xpeed::payment_observer>
{
public:
	payment_observer (std::function<void(boost::property_tree::ptree const &)> const &, xpeed::rpc &, xpeed::account const &, xpeed::amount const &);
	~payment_observer ();
	void start (uint64_t);
	void observe ();
	void timeout ();
	void complete (xpeed::payment_status);
	std::mutex mutex;
	std::condition_variable condition;
	xpeed::rpc & rpc;
	xpeed::account account;
	xpeed::amount amount;
	std::function<void(boost::property_tree::ptree const &)> response;
	std::atomic_flag completed;
};
class rpc_handler : public std::enable_shared_from_this<xpeed::rpc_handler>
{
public:
	rpc_handler (xpeed::node &, xpeed::rpc &, std::string const &, std::string const &, std::function<void(boost::property_tree::ptree const &)> const &);
	void process_request ();
	void account_balance ();
	void account_block_count ();
	void account_count ();
	void account_create ();
	void account_get ();
	void account_history ();
	void account_info ();
	void account_key ();
	void account_list ();
	void account_move ();
	void account_remove ();
	void account_representative ();
	void account_representative_set ();
	void account_weight ();
	void accounts_balances ();
	void accounts_create ();
	void accounts_frontiers ();
	void accounts_pending ();
	void available_supply ();
	void block_info ();
	void block_confirm ();
	void blocks ();
	void blocks_info ();
	void block_account ();
	void block_count ();
	void block_count_type ();
	void block_create ();
	void block_hash ();
	void bootstrap ();
	void bootstrap_any ();
	void bootstrap_lazy ();
	void bootstrap_status ();
	void chain (bool = false);
	void confirmation_active ();
	void confirmation_history ();
	void confirmation_info ();
	void confirmation_quorum ();
	void delegators ();
	void delegators_count ();
	void deterministic_key ();
	void frontiers ();
	void history ();
	void keepalive ();
	void key_create ();
	void key_expand ();
	void ledger ();
	void mxpd_to_raw (xpeed::uint128_t = xpeed::Mxpd_ratio);
	void mxpd_from_raw (xpeed::uint128_t = xpeed::Mxpd_ratio);
	void node_id ();
	void node_id_delete ();
	void password_change ();
	void password_enter ();
	void password_valid (bool = false);
	void payment_begin ();
	void payment_init ();
	void payment_end ();
	void payment_wait ();
	void peers ();
	void pending ();
	void pending_exists ();
	void process ();
	void receive ();
	void receive_minimum ();
	void receive_minimum_set ();
	void representatives ();
	void representatives_online ();
	void republish ();
	void search_pending ();
	void search_pending_all ();
	void send ();
	void sign ();
	void stats ();
	void stats_clear ();
	void stop ();
	void unchecked ();
	void unchecked_clear ();
	void unchecked_get ();
	void unchecked_keys ();
	void uptime ();
	void validate_account_number ();
	void version ();
	void wallet_add ();
	void wallet_add_watch ();
	void wallet_balances ();
	void wallet_change_seed ();
	void wallet_contains ();
	void wallet_create ();
	void wallet_destroy ();
	void wallet_export ();
	void wallet_frontiers ();
	void wallet_history ();
	void wallet_info ();
	void wallet_key_valid ();
	void wallet_ledger ();
	void wallet_lock ();
	void wallet_pending ();
	void wallet_representative ();
	void wallet_representative_set ();
	void wallet_republish ();
	void wallet_work_get ();
	void work_generate ();
	void work_cancel ();
	void work_get ();
	void work_set ();
	void work_validate ();
	void work_peer_add ();
	void work_peers ();
	void work_peers_clear ();
	std::string body;
	std::string request_id;
	xpeed::node & node;
	xpeed::rpc & rpc;
	boost::property_tree::ptree request;
	std::function<void(boost::property_tree::ptree const &)> response;
	void response_errors ();
	std::error_code ec;
	boost::property_tree::ptree response_l;
	std::shared_ptr<xpeed::wallet> wallet_impl ();
	bool wallet_locked_impl (xpeed::transaction const &, std::shared_ptr<xpeed::wallet>);
	bool wallet_account_impl (xpeed::transaction const &, std::shared_ptr<xpeed::wallet>, xpeed::account const &);
	xpeed::account account_impl (std::string = "");
	xpeed::amount amount_impl ();
	std::shared_ptr<xpeed::block> block_impl (bool = true);
	xpeed::block_hash hash_impl (std::string = "hash");
	xpeed::amount threshold_optional_impl ();
	uint64_t work_optional_impl ();
	uint64_t count_impl ();
	uint64_t count_optional_impl (uint64_t = std::numeric_limits<uint64_t>::max ());
	uint64_t offset_optional_impl (uint64_t = 0);
	bool rpc_control_impl ();
};
/** Returns the correct RPC implementation based on TLS configuration */
std::unique_ptr<xpeed::rpc> get_rpc (boost::asio::io_context & io_ctx_a, xpeed::node & node_a, xpeed::rpc_config const & config_a);
}
