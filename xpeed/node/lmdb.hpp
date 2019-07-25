#pragma once

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <lmdb/libraries/liblmdb/lmdb.h>

#include <xpeed/lib/numbers.hpp>
#include <xpeed/node/logging.hpp>
#include <xpeed/secure/blockstore.hpp>
#include <xpeed/secure/common.hpp>

#include <thread>

namespace xpeed
{
class mdb_env;
class mdb_txn : public transaction_impl
{
public:
	mdb_txn (xpeed::mdb_env const &, bool = false);
	mdb_txn (xpeed::mdb_txn const &) = delete;
	mdb_txn (xpeed::mdb_txn &&) = default;
	~mdb_txn ();
	xpeed::mdb_txn & operator= (xpeed::mdb_txn const &) = delete;
	xpeed::mdb_txn & operator= (xpeed::mdb_txn &&) = default;
	operator MDB_txn * () const;
	MDB_txn * handle;
};
/**
 * RAII wrapper for MDB_env
 */
class mdb_env
{
public:
	mdb_env (bool &, boost::filesystem::path const &, int max_dbs = 128, size_t map_size = 128ULL * 1024 * 1024 * 1024);
	~mdb_env ();
	operator MDB_env * () const;
	xpeed::transaction tx_begin (bool = false) const;
	MDB_txn * tx (xpeed::transaction const &) const;
	MDB_env * environment;
};

/**
 * Encapsulates MDB_val and provides uint256_union conversion of the data.
 */
class mdb_val
{
public:
	mdb_val (xpeed::epoch = xpeed::epoch::unspecified);
	mdb_val (xpeed::account_info const &);
	mdb_val (xpeed::block_info const &);
	mdb_val (MDB_val const &, xpeed::epoch = xpeed::epoch::unspecified);
	mdb_val (xpeed::pending_info const &);
	mdb_val (xpeed::pending_key const &);
	mdb_val (xpeed::unchecked_info const &);
	mdb_val (size_t, void *);
	mdb_val (xpeed::uint128_union const &);
	mdb_val (xpeed::uint256_union const &);
	mdb_val (xpeed::endpoint_key const &);
	mdb_val (std::shared_ptr<xpeed::block> const &);
	mdb_val (std::shared_ptr<xpeed::vote> const &);
	mdb_val (uint64_t);
	void * data () const;
	size_t size () const;
	explicit operator xpeed::account_info () const;
	explicit operator xpeed::block_info () const;
	explicit operator xpeed::pending_info () const;
	explicit operator xpeed::pending_key () const;
	explicit operator xpeed::unchecked_info () const;
	explicit operator xpeed::uint128_union () const;
	explicit operator xpeed::uint256_union () const;
	explicit operator std::array<char, 64> () const;
	explicit operator xpeed::endpoint_key () const;
	explicit operator xpeed::no_value () const;
	explicit operator std::shared_ptr<xpeed::block> () const;
	explicit operator std::shared_ptr<xpeed::send_block> () const;
	explicit operator std::shared_ptr<xpeed::receive_block> () const;
	explicit operator std::shared_ptr<xpeed::open_block> () const;
	explicit operator std::shared_ptr<xpeed::change_block> () const;
	explicit operator std::shared_ptr<xpeed::state_block> () const;
	explicit operator std::shared_ptr<xpeed::vote> () const;
	explicit operator uint64_t () const;
	operator MDB_val * () const;
	operator MDB_val const & () const;
	MDB_val value;
	std::shared_ptr<std::vector<uint8_t>> buffer;
	xpeed::epoch epoch{ xpeed::epoch::unspecified };
};
class block_store;

template <typename T, typename U>
class mdb_iterator : public store_iterator_impl<T, U>
{
public:
	mdb_iterator (xpeed::transaction const & transaction_a, MDB_dbi db_a, xpeed::epoch = xpeed::epoch::unspecified);
	mdb_iterator (std::nullptr_t, xpeed::epoch = xpeed::epoch::unspecified);
	mdb_iterator (xpeed::transaction const & transaction_a, MDB_dbi db_a, MDB_val const & val_a, xpeed::epoch = xpeed::epoch::unspecified);
	mdb_iterator (xpeed::mdb_iterator<T, U> && other_a);
	mdb_iterator (xpeed::mdb_iterator<T, U> const &) = delete;
	~mdb_iterator ();
	xpeed::store_iterator_impl<T, U> & operator++ () override;
	std::pair<xpeed::mdb_val, xpeed::mdb_val> * operator-> ();
	bool operator== (xpeed::store_iterator_impl<T, U> const & other_a) const override;
	bool is_end_sentinal () const override;
	void fill (std::pair<T, U> &) const override;
	void clear ();
	xpeed::mdb_iterator<T, U> & operator= (xpeed::mdb_iterator<T, U> && other_a);
	xpeed::store_iterator_impl<T, U> & operator= (xpeed::store_iterator_impl<T, U> const &) = delete;
	MDB_cursor * cursor;
	std::pair<xpeed::mdb_val, xpeed::mdb_val> current;

private:
	MDB_txn * tx (xpeed::transaction const &) const;
};

/**
 * Iterates the key/value pairs of two stores merged together
 */
template <typename T, typename U>
class mdb_merge_iterator : public store_iterator_impl<T, U>
{
public:
	mdb_merge_iterator (xpeed::transaction const &, MDB_dbi, MDB_dbi);
	mdb_merge_iterator (std::nullptr_t);
	mdb_merge_iterator (xpeed::transaction const &, MDB_dbi, MDB_dbi, MDB_val const &);
	mdb_merge_iterator (xpeed::mdb_merge_iterator<T, U> &&);
	mdb_merge_iterator (xpeed::mdb_merge_iterator<T, U> const &) = delete;
	~mdb_merge_iterator ();
	xpeed::store_iterator_impl<T, U> & operator++ () override;
	std::pair<xpeed::mdb_val, xpeed::mdb_val> * operator-> ();
	bool operator== (xpeed::store_iterator_impl<T, U> const &) const override;
	bool is_end_sentinal () const override;
	void fill (std::pair<T, U> &) const override;
	void clear ();
	xpeed::mdb_merge_iterator<T, U> & operator= (xpeed::mdb_merge_iterator<T, U> &&) = default;
	xpeed::mdb_merge_iterator<T, U> & operator= (xpeed::mdb_merge_iterator<T, U> const &) = delete;

private:
	xpeed::mdb_iterator<T, U> & least_iterator () const;
	std::unique_ptr<xpeed::mdb_iterator<T, U>> impl1;
	std::unique_ptr<xpeed::mdb_iterator<T, U>> impl2;
};

class logging;
/**
 * mdb implementation of the block store
 */
class mdb_store : public block_store
{
	friend class xpeed::block_predecessor_set;

public:
	mdb_store (bool &, xpeed::logging &, boost::filesystem::path const &, int lmdb_max_dbs = 128, bool drop_unchecked = false, size_t batch_size = 512);
	~mdb_store ();

	xpeed::transaction tx_begin_write () override;
	xpeed::transaction tx_begin_read () override;
	xpeed::transaction tx_begin (bool write = false) override;

	void initialize (xpeed::transaction const &, xpeed::genesis const &) override;
	void block_put (xpeed::transaction const &, xpeed::block_hash const &, xpeed::block const &, xpeed::block_sideband const &, xpeed::epoch version = xpeed::epoch::epoch_0) override;
	size_t block_successor_offset (xpeed::transaction const &, MDB_val, xpeed::block_type);
	xpeed::block_hash block_successor (xpeed::transaction const &, xpeed::block_hash const &) override;
	void block_successor_clear (xpeed::transaction const &, xpeed::block_hash const &) override;
	std::shared_ptr<xpeed::block> block_get (xpeed::transaction const &, xpeed::block_hash const &, xpeed::block_sideband * = nullptr) override;
	std::shared_ptr<xpeed::block> block_random (xpeed::transaction const &) override;
	void block_del (xpeed::transaction const &, xpeed::block_hash const &) override;
	bool block_exists (xpeed::transaction const &, xpeed::block_hash const &) override;
	bool block_exists (xpeed::transaction const &, xpeed::block_type, xpeed::block_hash const &) override;
	xpeed::block_counts block_count (xpeed::transaction const &) override;
	bool root_exists (xpeed::transaction const &, xpeed::uint256_union const &) override;
	bool source_exists (xpeed::transaction const &, xpeed::block_hash const &) override;
	xpeed::account block_account (xpeed::transaction const &, xpeed::block_hash const &) override;

	void frontier_put (xpeed::transaction const &, xpeed::block_hash const &, xpeed::account const &) override;
	xpeed::account frontier_get (xpeed::transaction const &, xpeed::block_hash const &) override;
	void frontier_del (xpeed::transaction const &, xpeed::block_hash const &) override;

	void account_put (xpeed::transaction const &, xpeed::account const &, xpeed::account_info const &) override;
	bool account_get (xpeed::transaction const &, xpeed::account const &, xpeed::account_info &) override;
	void account_del (xpeed::transaction const &, xpeed::account const &) override;
	bool account_exists (xpeed::transaction const &, xpeed::account const &) override;
	size_t account_count (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v0_begin (xpeed::transaction const &, xpeed::account const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v0_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v0_end () override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v1_begin (xpeed::transaction const &, xpeed::account const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v1_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v1_end () override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_begin (xpeed::transaction const &, xpeed::account const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_end () override;

	void pending_put (xpeed::transaction const &, xpeed::pending_key const &, xpeed::pending_info const &) override;
	void pending_del (xpeed::transaction const &, xpeed::pending_key const &) override;
	bool pending_get (xpeed::transaction const &, xpeed::pending_key const &, xpeed::pending_info &) override;
	bool pending_exists (xpeed::transaction const &, xpeed::pending_key const &) override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v0_begin (xpeed::transaction const &, xpeed::pending_key const &) override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v0_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v0_end () override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v1_begin (xpeed::transaction const &, xpeed::pending_key const &) override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v1_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v1_end () override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_begin (xpeed::transaction const &, xpeed::pending_key const &) override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_end () override;

	bool block_info_get (xpeed::transaction const &, xpeed::block_hash const &, xpeed::block_info &) override;
	xpeed::uint128_t block_balance (xpeed::transaction const &, xpeed::block_hash const &) override;
	xpeed::epoch block_version (xpeed::transaction const &, xpeed::block_hash const &) override;

	xpeed::uint128_t representation_get (xpeed::transaction const &, xpeed::account const &) override;
	void representation_put (xpeed::transaction const &, xpeed::account const &, xpeed::uint128_t const &) override;
	void representation_add (xpeed::transaction const &, xpeed::account const &, xpeed::uint128_t const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::uint128_union> representation_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::account, xpeed::uint128_union> representation_end () override;

	void unchecked_clear (xpeed::transaction const &) override;
	void unchecked_put (xpeed::transaction const &, xpeed::unchecked_key const &, xpeed::unchecked_info const &) override;
	void unchecked_put (xpeed::transaction const &, xpeed::block_hash const &, std::shared_ptr<xpeed::block> const &) override;
	std::vector<xpeed::unchecked_info> unchecked_get (xpeed::transaction const &, xpeed::block_hash const &) override;
	bool unchecked_exists (xpeed::transaction const &, xpeed::unchecked_key const &) override;
	void unchecked_del (xpeed::transaction const &, xpeed::unchecked_key const &) override;
	xpeed::store_iterator<xpeed::unchecked_key, xpeed::unchecked_info> unchecked_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::unchecked_key, xpeed::unchecked_info> unchecked_begin (xpeed::transaction const &, xpeed::unchecked_key const &) override;
	xpeed::store_iterator<xpeed::unchecked_key, xpeed::unchecked_info> unchecked_end () override;
	size_t unchecked_count (xpeed::transaction const &) override;

	// Return latest vote for an account from store
	std::shared_ptr<xpeed::vote> vote_get (xpeed::transaction const &, xpeed::account const &) override;
	// Populate vote with the next sequence number
	std::shared_ptr<xpeed::vote> vote_generate (xpeed::transaction const &, xpeed::account const &, xpeed::raw_key const &, std::shared_ptr<xpeed::block>) override;
	std::shared_ptr<xpeed::vote> vote_generate (xpeed::transaction const &, xpeed::account const &, xpeed::raw_key const &, std::vector<xpeed::block_hash>) override;
	// Return either vote or the stored vote with a higher sequence number
	std::shared_ptr<xpeed::vote> vote_max (xpeed::transaction const &, std::shared_ptr<xpeed::vote>) override;
	// Return latest vote for an account considering the vote cache
	std::shared_ptr<xpeed::vote> vote_current (xpeed::transaction const &, xpeed::account const &) override;
	void flush (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::account, std::shared_ptr<xpeed::vote>> vote_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<xpeed::account, std::shared_ptr<xpeed::vote>> vote_end () override;

	void online_weight_put (xpeed::transaction const &, uint64_t, xpeed::amount const &) override;
	void online_weight_del (xpeed::transaction const &, uint64_t) override;
	xpeed::store_iterator<uint64_t, xpeed::amount> online_weight_begin (xpeed::transaction const &) override;
	xpeed::store_iterator<uint64_t, xpeed::amount> online_weight_end () override;
	size_t online_weight_count (xpeed::transaction const &) const override;
	void online_weight_clear (xpeed::transaction const &) override;

	std::mutex cache_mutex;
	std::unordered_map<xpeed::account, std::shared_ptr<xpeed::vote>> vote_cache_l1;
	std::unordered_map<xpeed::account, std::shared_ptr<xpeed::vote>> vote_cache_l2;

	void version_put (xpeed::transaction const &, int) override;
	int version_get (xpeed::transaction const &) override;
	void do_upgrades (xpeed::transaction const &, bool &);
	void upgrade_v1_to_v2 (xpeed::transaction const &);
	void upgrade_v2_to_v3 (xpeed::transaction const &);
	void upgrade_v3_to_v4 (xpeed::transaction const &);
	void upgrade_v4_to_v5 (xpeed::transaction const &);
	void upgrade_v5_to_v6 (xpeed::transaction const &);
	void upgrade_v6_to_v7 (xpeed::transaction const &);
	void upgrade_v7_to_v8 (xpeed::transaction const &);
	void upgrade_v8_to_v9 (xpeed::transaction const &);
	void upgrade_v9_to_v10 (xpeed::transaction const &);
	void upgrade_v10_to_v11 (xpeed::transaction const &);
	void upgrade_v11_to_v12 (xpeed::transaction const &);
	void do_slow_upgrades (size_t const);
	void upgrade_v12_to_v13 (size_t const);
	bool full_sideband (xpeed::transaction const &);

	// Requires a write transaction
	xpeed::raw_key get_node_id (xpeed::transaction const &) override;

	/** Deletes the node ID from the store */
	void delete_node_id (xpeed::transaction const &) override;

	void peer_put (xpeed::transaction const & transaction_a, xpeed::endpoint_key const & endpoint_a) override;
	bool peer_exists (xpeed::transaction const & transaction_a, xpeed::endpoint_key const & endpoint_a) const override;
	void peer_del (xpeed::transaction const & transaction_a, xpeed::endpoint_key const & endpoint_a) override;
	size_t peer_count (xpeed::transaction const & transaction_a) const override;
	void peer_clear (xpeed::transaction const & transaction_a) override;

	xpeed::store_iterator<xpeed::endpoint_key, xpeed::no_value> peers_begin (xpeed::transaction const & transaction_a) override;
	xpeed::store_iterator<xpeed::endpoint_key, xpeed::no_value> peers_end () override;

	void stop ();

	xpeed::logging & logging;

	xpeed::mdb_env env;

	/**
	 * Maps head block to owning account
	 * xpeed::block_hash -> xpeed::account
	 */
	MDB_dbi frontiers{ 0 };

	/**
	 * Maps account v1 to account information, head, rep, open, balance, timestamp and block count.
	 * xpeed::account -> xpeed::block_hash, xpeed::block_hash, xpeed::block_hash, xpeed::amount, uint64_t, uint64_t
	 */
	MDB_dbi accounts_v0{ 0 };

	/**
	 * Maps account v0 to account information, head, rep, open, balance, timestamp and block count.
	 * xpeed::account -> xpeed::block_hash, xpeed::block_hash, xpeed::block_hash, xpeed::amount, uint64_t, uint64_t
	 */
	MDB_dbi accounts_v1{ 0 };

	/**
	 * Maps block hash to send block.
	 * xpeed::block_hash -> xpeed::send_block
	 */
	MDB_dbi send_blocks{ 0 };

	/**
	 * Maps block hash to receive block.
	 * xpeed::block_hash -> xpeed::receive_block
	 */
	MDB_dbi receive_blocks{ 0 };

	/**
	 * Maps block hash to open block.
	 * xpeed::block_hash -> xpeed::open_block
	 */
	MDB_dbi open_blocks{ 0 };

	/**
	 * Maps block hash to change block.
	 * xpeed::block_hash -> xpeed::change_block
	 */
	MDB_dbi change_blocks{ 0 };

	/**
	 * Maps block hash to v0 state block.
	 * xpeed::block_hash -> xpeed::state_block
	 */
	MDB_dbi state_blocks_v0{ 0 };

	/**
	 * Maps block hash to v1 state block.
	 * xpeed::block_hash -> xpeed::state_block
	 */
	MDB_dbi state_blocks_v1{ 0 };

	/**
	 * Maps min_version 0 (destination account, pending block) to (source account, amount).
	 * xpeed::account, xpeed::block_hash -> xpeed::account, xpeed::amount
	 */
	MDB_dbi pending_v0{ 0 };

	/**
	 * Maps min_version 1 (destination account, pending block) to (source account, amount).
	 * xpeed::account, xpeed::block_hash -> xpeed::account, xpeed::amount
	 */
	MDB_dbi pending_v1{ 0 };

	/**
	 * Maps block hash to account and balance.
	 * block_hash -> xpeed::account, xpeed::amount
	 */
	MDB_dbi blocks_info{ 0 };

	/**
	 * Representative weights.
	 * xpeed::account -> xpeed::uint128_t
	 */
	MDB_dbi representation{ 0 };

	/**
	 * Unchecked bootstrap blocks info.
	 * xpeed::block_hash -> xpeed::unchecked_info
	 */
	MDB_dbi unchecked{ 0 };

	/**
	 * Highest vote observed for account.
	 * xpeed::account -> uint64_t
	 */
	MDB_dbi vote{ 0 };

	/**
	 * Samples of online vote weight
	 * uint64_t -> xpeed::amount
	 */
	MDB_dbi online_weight{ 0 };

	/**
	 * Meta information about block store, such as versions.
	 * xpeed::uint256_union (arbitrary key) -> blob
	 */
	MDB_dbi meta{ 0 };

	/*
	 * Endpoints for peers
	 * xpeed::endpoint_key -> no_value
	*/
	MDB_dbi peers{ 0 };

private:
	bool entry_has_sideband (MDB_val, xpeed::block_type);
	xpeed::account block_account_computed (xpeed::transaction const &, xpeed::block_hash const &);
	xpeed::uint128_t block_balance_computed (xpeed::transaction const &, xpeed::block_hash const &);
	MDB_dbi block_database (xpeed::block_type, xpeed::epoch);
	template <typename T>
	std::shared_ptr<xpeed::block> block_random (xpeed::transaction const &, MDB_dbi);
	MDB_val block_raw_get (xpeed::transaction const &, xpeed::block_hash const &, xpeed::block_type &);
	boost::optional<MDB_val> block_raw_get_by_type (xpeed::transaction const &, xpeed::block_hash const &, xpeed::block_type &);
	void block_raw_put (xpeed::transaction const &, MDB_dbi, xpeed::block_hash const &, MDB_val);
	void clear (MDB_dbi);
	std::atomic<bool> stopped{ false };
	std::thread upgrades;
};
class wallet_value
{
public:
	wallet_value () = default;
	wallet_value (xpeed::mdb_val const &);
	wallet_value (xpeed::uint256_union const &, uint64_t);
	xpeed::mdb_val val () const;
	xpeed::private_key key;
	uint64_t work;
};
}
