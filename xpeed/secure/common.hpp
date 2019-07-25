#pragma once

#include <xpeed/lib/blockbuilders.hpp>
#include <xpeed/lib/blocks.hpp>
#include <xpeed/lib/utility.hpp>
#include <xpeed/secure/utility.hpp>

#include <boost/iterator/transform_iterator.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/variant.hpp>

#include <unordered_map>

#include <crypto/blake2/blake2.h>

namespace boost
{
template <>
struct hash<::xpeed::uint256_union>
{
	size_t operator() (::xpeed::uint256_union const & value_a) const
	{
		std::hash<::xpeed::uint256_union> hash;
		return hash (value_a);
	}
};
template <>
struct hash<::xpeed::uint512_union>
{
	size_t operator() (::xpeed::uint512_union const & value_a) const
	{
		std::hash<::xpeed::uint512_union> hash;
		return hash (value_a);
	}
};
}
namespace xpeed
{
const uint8_t protocol_version = 0x10;
const uint8_t protocol_version_min = 0x0d;
const uint8_t node_id_version = 0x0c;

/*
 * Do not bootstrap from nodes older than this version.
 * Also, on the beta network do not process messages from
 * nodes older than this version.
 */
const uint8_t protocol_version_reasonable_min = 0x0d;

/**
 * A key pair. The private key is generated from the random pool, or passed in
 * as a hex string. The public key is derived using ed25519.
 */
class keypair
{
public:
	keypair ();
	keypair (std::string const &);
	keypair (xpeed::raw_key &&);
	xpeed::public_key pub;
	xpeed::raw_key prv;
};

/**
 * Tag for which epoch an entry belongs to
 */
enum class epoch : uint8_t
{
	invalid = 0,
	unspecified = 1,
	epoch_0 = 2,
	epoch_1 = 3
};

/**
 * Latest information about an account
 */
class account_info
{
public:
	account_info ();
	account_info (xpeed::account_info const &) = default;
	account_info (xpeed::block_hash const &, xpeed::block_hash const &, xpeed::block_hash const &, xpeed::amount const &, uint64_t, uint64_t, epoch);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	bool operator== (xpeed::account_info const &) const;
	bool operator!= (xpeed::account_info const &) const;
	size_t db_size () const;
	xpeed::block_hash head;
	xpeed::block_hash rep_block;
	xpeed::block_hash open_block;
	xpeed::amount balance;
	/** Seconds since posix epoch */
	uint64_t modified;
	uint64_t block_count;
	xpeed::epoch epoch;
};

/**
 * Information on an uncollected send
 */
class pending_info
{
public:
	pending_info ();
	pending_info (xpeed::account const &, xpeed::amount const &, epoch);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	bool operator== (xpeed::pending_info const &) const;
	xpeed::account source;
	xpeed::amount amount;
	xpeed::epoch epoch;
};
class pending_key
{
public:
	pending_key ();
	pending_key (xpeed::account const &, xpeed::block_hash const &);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	bool operator== (xpeed::pending_key const &) const;
	xpeed::account account;
	xpeed::block_hash hash;
	xpeed::block_hash key () const;
};

class endpoint_key
{
public:
	endpoint_key () = default;

	/*
	 * @param address_a This should be in network byte order
	 * @param port_a This should be in host byte order
	 */
	endpoint_key (const std::array<uint8_t, 16> & address_a, uint16_t port_a);

	/*
	 * @return The ipv6 address in network byte order
	 */
	const std::array<uint8_t, 16> & address_bytes () const;

	/*
	 * @return The port in host byte order
	 */
	uint16_t port () const;

private:
	// Both stored internally in network byte order
	std::array<uint8_t, 16> address;
	uint16_t network_port{ 0 };
};

enum class no_value
{
	dummy
};

// Internally unchecked_key is equal to pending_key (2x uint256_union)
using unchecked_key = pending_key;

/**
 * Tag for block signature verification result
 */
enum class signature_verification : uint8_t
{
	unknown = 0,
	invalid = 1,
	valid = 2,
	valid_epoch = 3 // Valid for epoch blocks
};

/**
 * Information on an unchecked block
 */
class unchecked_info
{
public:
	unchecked_info ();
	unchecked_info (std::shared_ptr<xpeed::block>, xpeed::account const &, uint64_t, xpeed::signature_verification = xpeed::signature_verification::unknown);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	bool operator== (xpeed::unchecked_info const &) const;
	std::shared_ptr<xpeed::block> block;
	xpeed::account account;
	/** Seconds since posix epoch */
	uint64_t modified;
	xpeed::signature_verification verified;
};

class block_info
{
public:
	block_info ();
	block_info (xpeed::account const &, xpeed::amount const &);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	bool operator== (xpeed::block_info const &) const;
	xpeed::account account;
	xpeed::amount balance;
};
class block_counts
{
public:
	block_counts ();
	size_t sum ();
	size_t send;
	size_t receive;
	size_t open;
	size_t change;
	size_t state_v0;
	size_t state_v1;
};
typedef std::vector<boost::variant<std::shared_ptr<xpeed::block>, xpeed::block_hash>>::const_iterator vote_blocks_vec_iter;
class iterate_vote_blocks_as_hash
{
public:
	iterate_vote_blocks_as_hash () = default;
	xpeed::block_hash operator() (boost::variant<std::shared_ptr<xpeed::block>, xpeed::block_hash> const & item) const;
};
class vote
{
public:
	vote () = default;
	vote (xpeed::vote const &);
	vote (bool &, xpeed::stream &, xpeed::block_uniquer * = nullptr);
	vote (bool &, xpeed::stream &, xpeed::block_type, xpeed::block_uniquer * = nullptr);
	vote (xpeed::account const &, xpeed::raw_key const &, uint64_t, std::shared_ptr<xpeed::block>);
	vote (xpeed::account const &, xpeed::raw_key const &, uint64_t, std::vector<xpeed::block_hash>);
	std::string hashes_string () const;
	xpeed::uint256_union hash () const;
	xpeed::uint256_union full_hash () const;
	bool operator== (xpeed::vote const &) const;
	bool operator!= (xpeed::vote const &) const;
	void serialize (xpeed::stream &, xpeed::block_type);
	void serialize (xpeed::stream &);
	bool deserialize (xpeed::stream &, xpeed::block_uniquer * = nullptr);
	bool validate ();
	boost::transform_iterator<xpeed::iterate_vote_blocks_as_hash, xpeed::vote_blocks_vec_iter> begin () const;
	boost::transform_iterator<xpeed::iterate_vote_blocks_as_hash, xpeed::vote_blocks_vec_iter> end () const;
	std::string to_json () const;
	// Vote round sequence number
	uint64_t sequence;
	// The blocks, or block hashes, that this vote is for
	std::vector<boost::variant<std::shared_ptr<xpeed::block>, xpeed::block_hash>> blocks;
	// Account that's voting
	xpeed::account account;
	// Signature of sequence + block hashes
	xpeed::signature signature;
	static const std::string hash_prefix;
};
/**
 * This class serves to find and return unique variants of a vote in order to minimize memory usage
 */
class vote_uniquer
{
public:
	using value_type = std::pair<const xpeed::uint256_union, std::weak_ptr<xpeed::vote>>;

	vote_uniquer (xpeed::block_uniquer &);
	std::shared_ptr<xpeed::vote> unique (std::shared_ptr<xpeed::vote>);
	size_t size ();

private:
	xpeed::block_uniquer & uniquer;
	std::mutex mutex;
	std::unordered_map<std::remove_const_t<value_type::first_type>, value_type::second_type> votes;
	static unsigned constexpr cleanup_count = 2;
};

std::unique_ptr<seq_con_info_component> collect_seq_con_info (vote_uniquer & vote_uniquer, const std::string & name);

enum class vote_code
{
	invalid, // Vote is not signed correctly
	replay, // Vote does not have the highest sequence number, it's a replay
	vote // Vote has the highest sequence number
};

enum class process_result
{
	progress, // Hasn't been seen before, signed correctly
	bad_signature, // Signature was bad, forged or transmission error
	old, // Already seen and was valid
	negative_spend, // Malicious attempt to spend a negative amount
	fork, // Malicious fork based on previous
	unreceivable, // Source block doesn't exist, has already been received, or requires an account upgrade (epoch blocks)
	gap_previous, // Block marked as previous is unknown
	gap_source, // Block marked as source is unknown
	opened_burn_account, // The impossible happened, someone found the private key associated with the public key '0'.
	balance_mismatch, // Balance and amount delta don't match
	representative_mismatch, // Representative is changed when it is not allowed
	block_position // This block cannot follow the previous block
};
class process_return
{
public:
	xpeed::process_result code;
	xpeed::account account;
	xpeed::amount amount;
	xpeed::account pending_account;
	boost::optional<bool> state_is_send;
	xpeed::signature_verification verified;
};
enum class tally_result
{
	vote,
	changed,
	confirm
};
extern xpeed::keypair const & zero_key;
extern xpeed::keypair const & test_genesis_key;
extern xpeed::account const & xpd_test_account;
extern xpeed::account const & xpd_beta_account;
extern xpeed::account const & xpd_live_account;
extern std::string const & xpd_test_genesis;
extern std::string const & xpd_beta_genesis;
extern std::string const & xpd_live_genesis;
extern std::string const & genesis_block;
extern xpeed::account const & genesis_account;
extern xpeed::account const & burn_account;
extern xpeed::uint128_t const & genesis_amount;
// An account number that compares inequal to any real account number
extern xpeed::account const & not_an_account ();
class genesis
{
public:
	explicit genesis ();
	xpeed::block_hash hash () const;
	std::shared_ptr<xpeed::block> open;
};
}
