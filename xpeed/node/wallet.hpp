#pragma once

#include <boost/thread/thread.hpp>
#include <xpeed/node/lmdb.hpp>
#include <xpeed/node/openclwork.hpp>
#include <xpeed/secure/blockstore.hpp>
#include <xpeed/secure/common.hpp>

#include <mutex>
#include <unordered_set>

namespace xpeed
{
// The fan spreads a key out over the heap to decrease the likelihood of it being recovered by memory inspection
class fan
{
public:
	fan (xpeed::uint256_union const &, size_t);
	void value (xpeed::raw_key &);
	void value_set (xpeed::raw_key const &);
	std::vector<std::unique_ptr<xpeed::uint256_union>> values;

private:
	std::mutex mutex;
	void value_get (xpeed::raw_key &);
};
class node_config;
class kdf
{
public:
	void phs (xpeed::raw_key &, std::string const &, xpeed::uint256_union const &);
	std::mutex mutex;
};
enum class key_type
{
	not_a_type,
	unknown,
	adhoc,
	deterministic
};
class wallet_store
{
public:
	wallet_store (bool &, xpeed::kdf &, xpeed::transaction &, xpeed::account, unsigned, std::string const &);
	wallet_store (bool &, xpeed::kdf &, xpeed::transaction &, xpeed::account, unsigned, std::string const &, std::string const &);
	std::vector<xpeed::account> accounts (xpeed::transaction const &);
	void initialize (xpeed::transaction const &, bool &, std::string const &);
	xpeed::uint256_union check (xpeed::transaction const &);
	bool rekey (xpeed::transaction const &, std::string const &);
	bool valid_password (xpeed::transaction const &);
	bool attempt_password (xpeed::transaction const &, std::string const &);
	void wallet_key (xpeed::raw_key &, xpeed::transaction const &);
	void seed (xpeed::raw_key &, xpeed::transaction const &);
	void seed_set (xpeed::transaction const &, xpeed::raw_key const &);
	xpeed::key_type key_type (xpeed::wallet_value const &);
	xpeed::public_key deterministic_insert (xpeed::transaction const &);
	xpeed::public_key deterministic_insert (xpeed::transaction const &, uint32_t const);
	void deterministic_key (xpeed::raw_key &, xpeed::transaction const &, uint32_t);
	uint32_t deterministic_index_get (xpeed::transaction const &);
	void deterministic_index_set (xpeed::transaction const &, uint32_t);
	void deterministic_clear (xpeed::transaction const &);
	xpeed::uint256_union salt (xpeed::transaction const &);
	bool is_representative (xpeed::transaction const &);
	xpeed::account representative (xpeed::transaction const &);
	void representative_set (xpeed::transaction const &, xpeed::account const &);
	xpeed::public_key insert_adhoc (xpeed::transaction const &, xpeed::raw_key const &);
	void insert_watch (xpeed::transaction const &, xpeed::public_key const &);
	void erase (xpeed::transaction const &, xpeed::public_key const &);
	xpeed::wallet_value entry_get_raw (xpeed::transaction const &, xpeed::public_key const &);
	void entry_put_raw (xpeed::transaction const &, xpeed::public_key const &, xpeed::wallet_value const &);
	bool fetch (xpeed::transaction const &, xpeed::public_key const &, xpeed::raw_key &);
	bool exists (xpeed::transaction const &, xpeed::public_key const &);
	void destroy (xpeed::transaction const &);
	xpeed::store_iterator<xpeed::uint256_union, xpeed::wallet_value> find (xpeed::transaction const &, xpeed::uint256_union const &);
	xpeed::store_iterator<xpeed::uint256_union, xpeed::wallet_value> begin (xpeed::transaction const &, xpeed::uint256_union const &);
	xpeed::store_iterator<xpeed::uint256_union, xpeed::wallet_value> begin (xpeed::transaction const &);
	xpeed::store_iterator<xpeed::uint256_union, xpeed::wallet_value> end ();
	void derive_key (xpeed::raw_key &, xpeed::transaction const &, std::string const &);
	void serialize_json (xpeed::transaction const &, std::string &);
	void write_backup (xpeed::transaction const &, boost::filesystem::path const &);
	bool move (xpeed::transaction const &, xpeed::wallet_store &, std::vector<xpeed::public_key> const &);
	bool import (xpeed::transaction const &, xpeed::wallet_store &);
	bool work_get (xpeed::transaction const &, xpeed::public_key const &, uint64_t &);
	void work_put (xpeed::transaction const &, xpeed::public_key const &, uint64_t);
	unsigned version (xpeed::transaction const &);
	void version_put (xpeed::transaction const &, unsigned);
	void upgrade_v1_v2 (xpeed::transaction const &);
	void upgrade_v2_v3 (xpeed::transaction const &);
	void upgrade_v3_v4 (xpeed::transaction const &);
	xpeed::fan password;
	xpeed::fan wallet_key_mem;
	static unsigned const version_1 = 1;
	static unsigned const version_2 = 2;
	static unsigned const version_3 = 3;
	static unsigned const version_4 = 4;
	unsigned const version_current = version_4;
	static xpeed::uint256_union const version_special;
	static xpeed::uint256_union const wallet_key_special;
	static xpeed::uint256_union const salt_special;
	static xpeed::uint256_union const check_special;
	static xpeed::uint256_union const representative_special;
	static xpeed::uint256_union const seed_special;
	static xpeed::uint256_union const deterministic_index_special;
	static size_t const check_iv_index;
	static size_t const seed_iv_index;
	static int const special_count;
	static unsigned const kdf_full_work = 64 * 1024;
	static unsigned const kdf_test_work = 8;
	static unsigned const kdf_work = xpeed::is_test_network ? kdf_test_work : kdf_full_work;
	xpeed::kdf & kdf;
	MDB_dbi handle;
	std::recursive_mutex mutex;

private:
	MDB_txn * tx (xpeed::transaction const &) const;
};
class wallets;
// A wallet is a set of account keys encrypted by a common encryption key
class wallet : public std::enable_shared_from_this<xpeed::wallet>
{
public:
	std::shared_ptr<xpeed::block> change_action (xpeed::account const &, xpeed::account const &, uint64_t = 0, bool = true);
	std::shared_ptr<xpeed::block> receive_action (xpeed::block const &, xpeed::account const &, xpeed::uint128_union const &, uint64_t = 0, bool = true);
	std::shared_ptr<xpeed::block> send_action (xpeed::account const &, xpeed::account const &, xpeed::uint128_t const &, uint64_t = 0, bool = true, boost::optional<std::string> = {});
	wallet (bool &, xpeed::transaction &, xpeed::wallets &, std::string const &);
	wallet (bool &, xpeed::transaction &, xpeed::wallets &, std::string const &, std::string const &);
	void enter_initial_password ();
	bool enter_password (xpeed::transaction const &, std::string const &);
	xpeed::public_key insert_adhoc (xpeed::raw_key const &, bool = true);
	xpeed::public_key insert_adhoc (xpeed::transaction const &, xpeed::raw_key const &, bool = true);
	void insert_watch (xpeed::transaction const &, xpeed::public_key const &);
	xpeed::public_key deterministic_insert (xpeed::transaction const &, bool = true);
	xpeed::public_key deterministic_insert (uint32_t, bool = true);
	xpeed::public_key deterministic_insert (bool = true);
	bool exists (xpeed::public_key const &);
	bool import (std::string const &, std::string const &);
	void serialize (std::string &);
	bool change_sync (xpeed::account const &, xpeed::account const &);
	void change_async (xpeed::account const &, xpeed::account const &, std::function<void(std::shared_ptr<xpeed::block>)> const &, uint64_t = 0, bool = true);
	bool receive_sync (std::shared_ptr<xpeed::block>, xpeed::account const &, xpeed::uint128_t const &);
	void receive_async (std::shared_ptr<xpeed::block>, xpeed::account const &, xpeed::uint128_t const &, std::function<void(std::shared_ptr<xpeed::block>)> const &, uint64_t = 0, bool = true);
	xpeed::block_hash send_sync (xpeed::account const &, xpeed::account const &, xpeed::uint128_t const &);
	void send_async (xpeed::account const &, xpeed::account const &, xpeed::uint128_t const &, std::function<void(std::shared_ptr<xpeed::block>)> const &, uint64_t = 0, bool = true, boost::optional<std::string> = {});
	void work_apply (xpeed::account const &, std::function<void(uint64_t)>);
	void work_cache_blocking (xpeed::account const &, xpeed::block_hash const &);
	void work_update (xpeed::transaction const &, xpeed::account const &, xpeed::block_hash const &, uint64_t);
	void work_ensure (xpeed::account const &, xpeed::block_hash const &);
	bool search_pending ();
	void init_free_accounts (xpeed::transaction const &);
	uint32_t deterministic_check (xpeed::transaction const & transaction_a, uint32_t index);
	/** Changes the wallet seed and returns the first account */
	xpeed::public_key change_seed (xpeed::transaction const & transaction_a, xpeed::raw_key const & prv_a, uint32_t count = 0);
	void deterministic_restore (xpeed::transaction const & transaction_a);
	bool live ();
	std::unordered_set<xpeed::account> free_accounts;
	std::function<void(bool, bool)> lock_observer;
	xpeed::wallet_store store;
	xpeed::wallets & wallets;
	std::mutex representatives_mutex;
	std::unordered_set<xpeed::account> representatives;
};
class node;

/**
 * The wallets set is all the wallets a node controls.
 * A node may contain multiple wallets independently encrypted and operated.
 */
class wallets
{
public:
	wallets (bool &, xpeed::node &);
	~wallets ();
	std::shared_ptr<xpeed::wallet> open (xpeed::uint256_union const &);
	std::shared_ptr<xpeed::wallet> create (xpeed::uint256_union const &);
	bool search_pending (xpeed::uint256_union const &);
	void search_pending_all ();
	void destroy (xpeed::uint256_union const &);
	void reload ();
	void do_wallet_actions ();
	void queue_wallet_action (xpeed::uint128_t const &, std::shared_ptr<xpeed::wallet>, std::function<void(xpeed::wallet &)> const &);
	void foreach_representative (xpeed::transaction const &, std::function<void(xpeed::public_key const &, xpeed::raw_key const &)> const &);
	bool exists (xpeed::transaction const &, xpeed::public_key const &);
	void stop ();
	void clear_send_ids (xpeed::transaction const &);
	void compute_reps ();
	void ongoing_compute_reps ();
	void split_if_needed (xpeed::transaction &, xpeed::block_store &);
	void move_table (std::string const &, MDB_txn *, MDB_txn *);
	std::function<void(bool)> observer;
	std::unordered_map<xpeed::uint256_union, std::shared_ptr<xpeed::wallet>> items;
	std::multimap<xpeed::uint128_t, std::pair<std::shared_ptr<xpeed::wallet>, std::function<void(xpeed::wallet &)>>, std::greater<xpeed::uint128_t>> actions;
	std::mutex mutex;
	std::mutex action_mutex;
	std::condition_variable condition;
	xpeed::kdf kdf;
	MDB_dbi handle;
	MDB_dbi send_action_ids;
	xpeed::node & node;
	xpeed::mdb_env & env;
	std::atomic<bool> stopped;
	boost::thread thread;
	static xpeed::uint128_t const generate_priority;
	static xpeed::uint128_t const high_priority;
	std::atomic<uint64_t> reps_count{ 0 };

	/** Start read-write transaction */
	xpeed::transaction tx_begin_write ();

	/** Start read-only transaction */
	xpeed::transaction tx_begin_read ();

	/**
	 * Start a read-only or read-write transaction
	 * @param write If true, start a read-write transaction
	 */
	xpeed::transaction tx_begin (bool write = false);
};

std::unique_ptr<seq_con_info_component> collect_seq_con_info (wallets & wallets, const std::string & name);

class wallets_store
{
public:
	virtual ~wallets_store () = default;
};
class mdb_wallets_store : public wallets_store
{
public:
	mdb_wallets_store (bool &, boost::filesystem::path const &, int lmdb_max_dbs = 128);
	xpeed::mdb_env environment;
};
}
