#pragma once

#include <xpeed/secure/common.hpp>
#include <stack>

namespace xpeed
{
class block_sideband
{
public:
	block_sideband () = default;
	block_sideband (xpeed::block_type, xpeed::account const &, xpeed::block_hash const &, xpeed::amount const &, uint64_t, uint64_t);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	static size_t size (xpeed::block_type);
	xpeed::block_type type;
	xpeed::block_hash successor;
	xpeed::account account;
	xpeed::amount balance;
	uint64_t height;
	uint64_t timestamp;
};
class transaction;
class block_store;

/**
 * Summation visitor for blocks, supporting amount and balance computations. These
 * computations are mutually dependant. The natural solution is to use mutual recursion
 * between balance and amount visitors, but this leads to very deep stacks. Hence, the
 * summation visitor uses an iterative approach.
 */
class summation_visitor : public xpeed::block_visitor
{
	enum summation_type
	{
		invalid = 0,
		balance = 1,
		amount = 2
	};

	/** Represents an invocation frame */
	class frame
	{
	public:
		frame (summation_type type_a, xpeed::block_hash balance_hash_a, xpeed::block_hash amount_hash_a) :
		type (type_a), balance_hash (balance_hash_a), amount_hash (amount_hash_a)
		{
		}

		/** The summation type guides the block visitor handlers */
		summation_type type{ invalid };
		/** Accumulated balance or amount */
		xpeed::uint128_t sum{ 0 };
		/** The current balance hash */
		xpeed::block_hash balance_hash{ 0 };
		/** The current amount hash */
		xpeed::block_hash amount_hash{ 0 };
		/** If true, this frame is awaiting an invocation result */
		bool awaiting_result{ false };
		/** Set by the invoked frame, representing the return value */
		xpeed::uint128_t incoming_result{ 0 };
	};

public:
	summation_visitor (xpeed::transaction const &, xpeed::block_store &);
	virtual ~summation_visitor () = default;
	/** Computes the balance as of \p block_hash */
	xpeed::uint128_t compute_balance (xpeed::block_hash const & block_hash);
	/** Computes the amount delta between \p block_hash and its predecessor */
	xpeed::uint128_t compute_amount (xpeed::block_hash const & block_hash);

protected:
	xpeed::transaction const & transaction;
	xpeed::block_store & store;

	/** The final result */
	xpeed::uint128_t result{ 0 };
	/** The current invocation frame */
	frame * current{ nullptr };
	/** Invocation frames */
	std::stack<frame> frames;
	/** Push a copy of \p hash of the given summation \p type */
	xpeed::summation_visitor::frame push (xpeed::summation_visitor::summation_type type, xpeed::block_hash const & hash);
	void sum_add (xpeed::uint128_t addend_a);
	void sum_set (xpeed::uint128_t value_a);
	/** The epilogue yields the result to previous frame, if any */
	void epilogue ();

	xpeed::uint128_t compute_internal (xpeed::summation_visitor::summation_type type, xpeed::block_hash const &);
	void send_block (xpeed::send_block const &) override;
	void receive_block (xpeed::receive_block const &) override;
	void open_block (xpeed::open_block const &) override;
	void change_block (xpeed::change_block const &) override;
	void state_block (xpeed::state_block const &) override;
};

/**
 * Determine the representative for this block
 */
class representative_visitor : public xpeed::block_visitor
{
public:
	representative_visitor (xpeed::transaction const & transaction_a, xpeed::block_store & store_a);
	virtual ~representative_visitor () = default;
	void compute (xpeed::block_hash const & hash_a);
	void send_block (xpeed::send_block const & block_a) override;
	void receive_block (xpeed::receive_block const & block_a) override;
	void open_block (xpeed::open_block const & block_a) override;
	void change_block (xpeed::change_block const & block_a) override;
	void state_block (xpeed::state_block const & block_a) override;
	xpeed::transaction const & transaction;
	xpeed::block_store & store;
	xpeed::block_hash current;
	xpeed::block_hash result;
};
template <typename T, typename U>
class store_iterator_impl
{
public:
	virtual ~store_iterator_impl () = default;
	virtual xpeed::store_iterator_impl<T, U> & operator++ () = 0;
	virtual bool operator== (xpeed::store_iterator_impl<T, U> const & other_a) const = 0;
	virtual bool is_end_sentinal () const = 0;
	virtual void fill (std::pair<T, U> &) const = 0;
	xpeed::store_iterator_impl<T, U> & operator= (xpeed::store_iterator_impl<T, U> const &) = delete;
	bool operator== (xpeed::store_iterator_impl<T, U> const * other_a) const
	{
		return (other_a != nullptr && *this == *other_a) || (other_a == nullptr && is_end_sentinal ());
	}
	bool operator!= (xpeed::store_iterator_impl<T, U> const & other_a) const
	{
		return !(*this == other_a);
	}
};
/**
 * Iterates the key/value pairs of a transaction
 */
template <typename T, typename U>
class store_iterator
{
public:
	store_iterator (std::nullptr_t)
	{
	}
	store_iterator (std::unique_ptr<xpeed::store_iterator_impl<T, U>> impl_a) :
	impl (std::move (impl_a))
	{
		impl->fill (current);
	}
	store_iterator (xpeed::store_iterator<T, U> && other_a) :
	current (std::move (other_a.current)),
	impl (std::move (other_a.impl))
	{
	}
	xpeed::store_iterator<T, U> & operator++ ()
	{
		++*impl;
		impl->fill (current);
		return *this;
	}
	xpeed::store_iterator<T, U> & operator= (xpeed::store_iterator<T, U> && other_a)
	{
		impl = std::move (other_a.impl);
		current = std::move (other_a.current);
		return *this;
	}
	xpeed::store_iterator<T, U> & operator= (xpeed::store_iterator<T, U> const &) = delete;
	std::pair<T, U> * operator-> ()
	{
		return &current;
	}
	bool operator== (xpeed::store_iterator<T, U> const & other_a) const
	{
		return (impl == nullptr && other_a.impl == nullptr) || (impl != nullptr && *impl == other_a.impl.get ()) || (other_a.impl != nullptr && *other_a.impl == impl.get ());
	}
	bool operator!= (xpeed::store_iterator<T, U> const & other_a) const
	{
		return !(*this == other_a);
	}

private:
	std::pair<T, U> current;
	std::unique_ptr<xpeed::store_iterator_impl<T, U>> impl;
};

class block_predecessor_set;

class transaction_impl
{
public:
	virtual ~transaction_impl () = default;
};
/**
 * RAII wrapper of MDB_txn where the constructor starts the transaction
 * and the destructor commits it.
 */
class transaction
{
public:
	std::unique_ptr<xpeed::transaction_impl> impl;
};

/**
 * Manages block storage and iteration
 */
class block_store
{
public:
	virtual ~block_store () = default;
	virtual void initialize (xpeed::transaction const &, xpeed::genesis const &) = 0;
	virtual void block_put (xpeed::transaction const &, xpeed::block_hash const &, xpeed::block const &, xpeed::block_sideband const &, xpeed::epoch version = xpeed::epoch::epoch_0) = 0;
	virtual xpeed::block_hash block_successor (xpeed::transaction const &, xpeed::block_hash const &) = 0;
	virtual void block_successor_clear (xpeed::transaction const &, xpeed::block_hash const &) = 0;
	virtual std::shared_ptr<xpeed::block> block_get (xpeed::transaction const &, xpeed::block_hash const &, xpeed::block_sideband * = nullptr) = 0;
	virtual std::shared_ptr<xpeed::block> block_random (xpeed::transaction const &) = 0;
	virtual void block_del (xpeed::transaction const &, xpeed::block_hash const &) = 0;
	virtual bool block_exists (xpeed::transaction const &, xpeed::block_hash const &) = 0;
	virtual bool block_exists (xpeed::transaction const &, xpeed::block_type, xpeed::block_hash const &) = 0;
	virtual xpeed::block_counts block_count (xpeed::transaction const &) = 0;
	virtual bool root_exists (xpeed::transaction const &, xpeed::uint256_union const &) = 0;
	virtual bool source_exists (xpeed::transaction const &, xpeed::block_hash const &) = 0;
	virtual xpeed::account block_account (xpeed::transaction const &, xpeed::block_hash const &) = 0;

	virtual void frontier_put (xpeed::transaction const &, xpeed::block_hash const &, xpeed::account const &) = 0;
	virtual xpeed::account frontier_get (xpeed::transaction const &, xpeed::block_hash const &) = 0;
	virtual void frontier_del (xpeed::transaction const &, xpeed::block_hash const &) = 0;

	virtual void account_put (xpeed::transaction const &, xpeed::account const &, xpeed::account_info const &) = 0;
	virtual bool account_get (xpeed::transaction const &, xpeed::account const &, xpeed::account_info &) = 0;
	virtual void account_del (xpeed::transaction const &, xpeed::account const &) = 0;
	virtual bool account_exists (xpeed::transaction const &, xpeed::account const &) = 0;
	virtual size_t account_count (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v0_begin (xpeed::transaction const &, xpeed::account const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v0_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v0_end () = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v1_begin (xpeed::transaction const &, xpeed::account const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v1_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_v1_end () = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_begin (xpeed::transaction const &, xpeed::account const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::account_info> latest_end () = 0;

	virtual void pending_put (xpeed::transaction const &, xpeed::pending_key const &, xpeed::pending_info const &) = 0;
	virtual void pending_del (xpeed::transaction const &, xpeed::pending_key const &) = 0;
	virtual bool pending_get (xpeed::transaction const &, xpeed::pending_key const &, xpeed::pending_info &) = 0;
	virtual bool pending_exists (xpeed::transaction const &, xpeed::pending_key const &) = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v0_begin (xpeed::transaction const &, xpeed::pending_key const &) = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v0_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v0_end () = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v1_begin (xpeed::transaction const &, xpeed::pending_key const &) = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v1_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_v1_end () = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_begin (xpeed::transaction const &, xpeed::pending_key const &) = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::pending_key, xpeed::pending_info> pending_end () = 0;

	virtual bool block_info_get (xpeed::transaction const &, xpeed::block_hash const &, xpeed::block_info &) = 0;
	virtual xpeed::uint128_t block_balance (xpeed::transaction const &, xpeed::block_hash const &) = 0;
	virtual xpeed::epoch block_version (xpeed::transaction const &, xpeed::block_hash const &) = 0;

	virtual xpeed::uint128_t representation_get (xpeed::transaction const &, xpeed::account const &) = 0;
	virtual void representation_put (xpeed::transaction const &, xpeed::account const &, xpeed::uint128_t const &) = 0;
	virtual void representation_add (xpeed::transaction const &, xpeed::account const &, xpeed::uint128_t const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::uint128_union> representation_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, xpeed::uint128_union> representation_end () = 0;

	virtual void unchecked_clear (xpeed::transaction const &) = 0;
	virtual void unchecked_put (xpeed::transaction const &, xpeed::unchecked_key const &, xpeed::unchecked_info const &) = 0;
	virtual void unchecked_put (xpeed::transaction const &, xpeed::block_hash const &, std::shared_ptr<xpeed::block> const &) = 0;
	virtual std::vector<xpeed::unchecked_info> unchecked_get (xpeed::transaction const &, xpeed::block_hash const &) = 0;
	virtual bool unchecked_exists (xpeed::transaction const &, xpeed::unchecked_key const &) = 0;
	virtual void unchecked_del (xpeed::transaction const &, xpeed::unchecked_key const &) = 0;
	virtual xpeed::store_iterator<xpeed::unchecked_key, xpeed::unchecked_info> unchecked_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::unchecked_key, xpeed::unchecked_info> unchecked_begin (xpeed::transaction const &, xpeed::unchecked_key const &) = 0;
	virtual xpeed::store_iterator<xpeed::unchecked_key, xpeed::unchecked_info> unchecked_end () = 0;
	virtual size_t unchecked_count (xpeed::transaction const &) = 0;

	// Return latest vote for an account from store
	virtual std::shared_ptr<xpeed::vote> vote_get (xpeed::transaction const &, xpeed::account const &) = 0;
	// Populate vote with the next sequence number
	virtual std::shared_ptr<xpeed::vote> vote_generate (xpeed::transaction const &, xpeed::account const &, xpeed::raw_key const &, std::shared_ptr<xpeed::block>) = 0;
	virtual std::shared_ptr<xpeed::vote> vote_generate (xpeed::transaction const &, xpeed::account const &, xpeed::raw_key const &, std::vector<xpeed::block_hash>) = 0;
	// Return either vote or the stored vote with a higher sequence number
	virtual std::shared_ptr<xpeed::vote> vote_max (xpeed::transaction const &, std::shared_ptr<xpeed::vote>) = 0;
	// Return latest vote for an account considering the vote cache
	virtual std::shared_ptr<xpeed::vote> vote_current (xpeed::transaction const &, xpeed::account const &) = 0;
	virtual void flush (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, std::shared_ptr<xpeed::vote>> vote_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<xpeed::account, std::shared_ptr<xpeed::vote>> vote_end () = 0;

	virtual void online_weight_put (xpeed::transaction const &, uint64_t, xpeed::amount const &) = 0;
	virtual void online_weight_del (xpeed::transaction const &, uint64_t) = 0;
	virtual xpeed::store_iterator<uint64_t, xpeed::amount> online_weight_begin (xpeed::transaction const &) = 0;
	virtual xpeed::store_iterator<uint64_t, xpeed::amount> online_weight_end () = 0;
	virtual size_t online_weight_count (xpeed::transaction const &) const = 0;
	virtual void online_weight_clear (xpeed::transaction const &) = 0;

	virtual void version_put (xpeed::transaction const &, int) = 0;
	virtual int version_get (xpeed::transaction const &) = 0;

	virtual void peer_put (xpeed::transaction const & transaction_a, xpeed::endpoint_key const & endpoint_a) = 0;
	virtual void peer_del (xpeed::transaction const & transaction_a, xpeed::endpoint_key const & endpoint_a) = 0;
	virtual bool peer_exists (xpeed::transaction const & transaction_a, xpeed::endpoint_key const & endpoint_a) const = 0;
	virtual size_t peer_count (xpeed::transaction const & transaction_a) const = 0;
	virtual void peer_clear (xpeed::transaction const & transaction_a) = 0;
	virtual xpeed::store_iterator<xpeed::endpoint_key, xpeed::no_value> peers_begin (xpeed::transaction const & transaction_a) = 0;
	virtual xpeed::store_iterator<xpeed::endpoint_key, xpeed::no_value> peers_end () = 0;

	// Requires a write transaction
	virtual xpeed::raw_key get_node_id (xpeed::transaction const &) = 0;

	/** Deletes the node ID from the store */
	virtual void delete_node_id (xpeed::transaction const &) = 0;

	/** Start read-write transaction */
	virtual xpeed::transaction tx_begin_write () = 0;

	/** Start read-only transaction */
	virtual xpeed::transaction tx_begin_read () = 0;

	/**
	 * Start a read-only or read-write transaction
	 * @param write If true, start a read-write transaction
	 */
	virtual xpeed::transaction tx_begin (bool write = false) = 0;
};
}
