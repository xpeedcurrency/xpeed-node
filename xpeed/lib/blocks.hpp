#pragma once

#include <xpeed/lib/errors.hpp>
#include <xpeed/lib/numbers.hpp>
#include <xpeed/lib/utility.hpp>

#include <boost/property_tree/json_parser.hpp>
#include <cassert>
#include <crypto/blake2/blake2.h>
#include <streambuf>
#include <unordered_map>

namespace xpeed
{
std::string to_string_hex (uint64_t);
bool from_string_hex (std::string const &, uint64_t &);
// We operate on streams of uint8_t by convention
using stream = std::basic_streambuf<uint8_t>;
// Read a raw byte stream the size of `T' and fill value.
template <typename T>
bool try_read (xpeed::stream & stream_a, T & value)
{
	static_assert (std::is_standard_layout<T>::value, "Can't stream read non-standard layout types");
	auto amount_read (stream_a.sgetn (reinterpret_cast<uint8_t *> (&value), sizeof (value)));
	return amount_read != sizeof (value);
}
// A wrapper of try_read which throws if there is an error
template <typename T>
void read (xpeed::stream & stream_a, T & value)
{
	auto error = try_read (stream_a, value);
	if (error)
	{
		throw std::runtime_error ("Failed to read type");
	}
}

template <typename T>
void write (xpeed::stream & stream_a, T const & value)
{
	static_assert (std::is_standard_layout<T>::value, "Can't stream write non-standard layout types");
	auto amount_written (stream_a.sputn (reinterpret_cast<uint8_t const *> (&value), sizeof (value)));
	assert (amount_written == sizeof (value));
}
class block_visitor;
enum class block_type : uint8_t
{
	invalid = 0,
	not_a_block = 1,
	send = 2,
	receive = 3,
	open = 4,
	change = 5,
	state = 6
};
class block
{
public:
	// Return a digest of the hashables in this block.
	xpeed::block_hash hash () const;
	// Return a digest of hashables and non-hashables in this block.
	xpeed::block_hash full_hash () const;
	std::string to_json () const;
	virtual void hash (blake2b_state &) const = 0;
	virtual uint64_t block_work () const = 0;
	virtual void block_work_set (uint64_t) = 0;
	virtual xpeed::account account () const;
	// Previous block in account's chain, zero for open block
	virtual xpeed::block_hash previous () const = 0;
	// Source block for open/receive blocks, zero otherwise.
	virtual xpeed::block_hash source () const;
	// Previous block or account number for open blocks
	virtual xpeed::block_hash root () const = 0;
	// Link field for state blocks, zero otherwise.
	virtual xpeed::block_hash link () const;
	virtual xpeed::account representative () const;
	virtual void serialize (xpeed::stream &) const = 0;
	virtual void serialize_json (std::string &) const = 0;
	virtual void visit (xpeed::block_visitor &) const = 0;
	virtual bool operator== (xpeed::block const &) const = 0;
	virtual xpeed::block_type type () const = 0;
	virtual xpeed::signature block_signature () const = 0;
	virtual void signature_set (xpeed::uint512_union const &) = 0;
	virtual ~block () = default;
	virtual bool valid_predecessor (xpeed::block const &) const = 0;
	static size_t size (xpeed::block_type);
};
class send_hashables
{
public:
	send_hashables () = default;
	send_hashables (xpeed::account const &, xpeed::block_hash const &, xpeed::amount const &);
	send_hashables (bool &, xpeed::stream &);
	send_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	xpeed::block_hash previous;
	xpeed::account destination;
	xpeed::amount balance;
	static size_t constexpr size = sizeof (previous) + sizeof (destination) + sizeof (balance);
};
class send_block : public xpeed::block
{
public:
	send_block () = default;
	send_block (xpeed::block_hash const &, xpeed::account const &, xpeed::amount const &, xpeed::raw_key const &, xpeed::public_key const &, uint64_t);
	send_block (bool &, xpeed::stream &);
	send_block (bool &, boost::property_tree::ptree const &);
	virtual ~send_block () = default;
	using xpeed::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	xpeed::block_hash previous () const override;
	xpeed::block_hash root () const override;
	void serialize (xpeed::stream &) const override;
	bool deserialize (xpeed::stream &);
	void serialize_json (std::string &) const override;
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (xpeed::block_visitor &) const override;
	xpeed::block_type type () const override;
	xpeed::signature block_signature () const override;
	void signature_set (xpeed::uint512_union const &) override;
	bool operator== (xpeed::block const &) const override;
	bool operator== (xpeed::send_block const &) const;
	bool valid_predecessor (xpeed::block const &) const override;
	send_hashables hashables;
	xpeed::signature signature;
	uint64_t work;
	static size_t constexpr size = xpeed::send_hashables::size + sizeof (signature) + sizeof (work);
};
class receive_hashables
{
public:
	receive_hashables () = default;
	receive_hashables (xpeed::block_hash const &, xpeed::block_hash const &);
	receive_hashables (bool &, xpeed::stream &);
	receive_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	xpeed::block_hash previous;
	xpeed::block_hash source;
	static size_t constexpr size = sizeof (previous) + sizeof (source);
};
class receive_block : public xpeed::block
{
public:
	receive_block () = default;
	receive_block (xpeed::block_hash const &, xpeed::block_hash const &, xpeed::raw_key const &, xpeed::public_key const &, uint64_t);
	receive_block (bool &, xpeed::stream &);
	receive_block (bool &, boost::property_tree::ptree const &);
	virtual ~receive_block () = default;
	using xpeed::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	xpeed::block_hash previous () const override;
	xpeed::block_hash source () const override;
	xpeed::block_hash root () const override;
	void serialize (xpeed::stream &) const override;
	bool deserialize (xpeed::stream &);
	void serialize_json (std::string &) const override;
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (xpeed::block_visitor &) const override;
	xpeed::block_type type () const override;
	xpeed::signature block_signature () const override;
	void signature_set (xpeed::uint512_union const &) override;
	bool operator== (xpeed::block const &) const override;
	bool operator== (xpeed::receive_block const &) const;
	bool valid_predecessor (xpeed::block const &) const override;
	receive_hashables hashables;
	xpeed::signature signature;
	uint64_t work;
	static size_t constexpr size = xpeed::receive_hashables::size + sizeof (signature) + sizeof (work);
};
class open_hashables
{
public:
	open_hashables () = default;
	open_hashables (xpeed::block_hash const &, xpeed::account const &, xpeed::account const &);
	open_hashables (bool &, xpeed::stream &);
	open_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	xpeed::block_hash source;
	xpeed::account representative;
	xpeed::account account;
	static size_t constexpr size = sizeof (source) + sizeof (representative) + sizeof (account);
};
class open_block : public xpeed::block
{
public:
	open_block () = default;
	open_block (xpeed::block_hash const &, xpeed::account const &, xpeed::account const &, xpeed::raw_key const &, xpeed::public_key const &, uint64_t);
	open_block (xpeed::block_hash const &, xpeed::account const &, xpeed::account const &, std::nullptr_t);
	open_block (bool &, xpeed::stream &);
	open_block (bool &, boost::property_tree::ptree const &);
	virtual ~open_block () = default;
	using xpeed::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	xpeed::block_hash previous () const override;
	xpeed::account account () const override;
	xpeed::block_hash source () const override;
	xpeed::block_hash root () const override;
	xpeed::account representative () const override;
	void serialize (xpeed::stream &) const override;
	bool deserialize (xpeed::stream &);
	void serialize_json (std::string &) const override;
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (xpeed::block_visitor &) const override;
	xpeed::block_type type () const override;
	xpeed::signature block_signature () const override;
	void signature_set (xpeed::uint512_union const &) override;
	bool operator== (xpeed::block const &) const override;
	bool operator== (xpeed::open_block const &) const;
	bool valid_predecessor (xpeed::block const &) const override;
	xpeed::open_hashables hashables;
	xpeed::signature signature;
	uint64_t work;
	static size_t constexpr size = xpeed::open_hashables::size + sizeof (signature) + sizeof (work);
};
class change_hashables
{
public:
	change_hashables () = default;
	change_hashables (xpeed::block_hash const &, xpeed::account const &);
	change_hashables (bool &, xpeed::stream &);
	change_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	xpeed::block_hash previous;
	xpeed::account representative;
	static size_t constexpr size = sizeof (previous) + sizeof (representative);
};
class change_block : public xpeed::block
{
public:
	change_block () = default;
	change_block (xpeed::block_hash const &, xpeed::account const &, xpeed::raw_key const &, xpeed::public_key const &, uint64_t);
	change_block (bool &, xpeed::stream &);
	change_block (bool &, boost::property_tree::ptree const &);
	virtual ~change_block () = default;
	using xpeed::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	xpeed::block_hash previous () const override;
	xpeed::block_hash root () const override;
	xpeed::account representative () const override;
	void serialize (xpeed::stream &) const override;
	bool deserialize (xpeed::stream &);
	void serialize_json (std::string &) const override;
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (xpeed::block_visitor &) const override;
	xpeed::block_type type () const override;
	xpeed::signature block_signature () const override;
	void signature_set (xpeed::uint512_union const &) override;
	bool operator== (xpeed::block const &) const override;
	bool operator== (xpeed::change_block const &) const;
	bool valid_predecessor (xpeed::block const &) const override;
	xpeed::change_hashables hashables;
	xpeed::signature signature;
	uint64_t work;
	static size_t constexpr size = xpeed::change_hashables::size + sizeof (signature) + sizeof (work);
};
class state_hashables
{
public:
	state_hashables () = default;
	state_hashables (xpeed::account const &, xpeed::block_hash const &, xpeed::account const &, xpeed::amount const &, xpeed::uint256_union const &);
	state_hashables (bool &, xpeed::stream &);
	state_hashables (bool &, boost::property_tree::ptree const &);
	void hash (blake2b_state &) const;
	// Account# / public key that operates this account
	// Uses:
	// Bulk signature validation in advance of further ledger processing
	// Arranging uncomitted transactions by account
	xpeed::account account;
	// Previous transaction in this chain
	xpeed::block_hash previous;
	// Representative of this account
	xpeed::account representative;
	// Current balance of this account
	// Allows lookup of account balance simply by looking at the head block
	xpeed::amount balance;
	// Link field contains source block_hash if receiving, destination account if sending
	xpeed::uint256_union link;
	// Serialized size
	static size_t constexpr size = sizeof (account) + sizeof (previous) + sizeof (representative) + sizeof (balance) + sizeof (link);
};
class state_block : public xpeed::block
{
public:
	state_block () = default;
	state_block (xpeed::account const &, xpeed::block_hash const &, xpeed::account const &, xpeed::amount const &, xpeed::uint256_union const &, xpeed::raw_key const &, xpeed::public_key const &, uint64_t);
	state_block (bool &, xpeed::stream &);
	state_block (bool &, boost::property_tree::ptree const &);
	virtual ~state_block () = default;
	using xpeed::block::hash;
	void hash (blake2b_state &) const override;
	uint64_t block_work () const override;
	void block_work_set (uint64_t) override;
	xpeed::block_hash previous () const override;
	xpeed::account account () const override;
	xpeed::block_hash root () const override;
	xpeed::block_hash link () const override;
	xpeed::account representative () const override;
	void serialize (xpeed::stream &) const override;
	bool deserialize (xpeed::stream &);
	void serialize_json (std::string &) const override;
	bool deserialize_json (boost::property_tree::ptree const &);
	void visit (xpeed::block_visitor &) const override;
	xpeed::block_type type () const override;
	xpeed::signature block_signature () const override;
	void signature_set (xpeed::uint512_union const &) override;
	bool operator== (xpeed::block const &) const override;
	bool operator== (xpeed::state_block const &) const;
	bool valid_predecessor (xpeed::block const &) const override;
	xpeed::state_hashables hashables;
	xpeed::signature signature;
	uint64_t work;
	static size_t constexpr size = xpeed::state_hashables::size + sizeof (signature) + sizeof (work);
};
class block_visitor
{
public:
	virtual void send_block (xpeed::send_block const &) = 0;
	virtual void receive_block (xpeed::receive_block const &) = 0;
	virtual void open_block (xpeed::open_block const &) = 0;
	virtual void change_block (xpeed::change_block const &) = 0;
	virtual void state_block (xpeed::state_block const &) = 0;
	virtual ~block_visitor () = default;
};
/**
 * This class serves to find and return unique variants of a block in order to minimize memory usage
 */
class block_uniquer
{
public:
	using value_type = std::pair<const xpeed::uint256_union, std::weak_ptr<xpeed::block>>;

	std::shared_ptr<xpeed::block> unique (std::shared_ptr<xpeed::block>);
	size_t size ();

private:
	std::mutex mutex;
	std::unordered_map<std::remove_const_t<value_type::first_type>, value_type::second_type> blocks;
	static unsigned constexpr cleanup_count = 2;
};

std::unique_ptr<seq_con_info_component> collect_seq_con_info (block_uniquer & block_uniquer, const std::string & name);

std::shared_ptr<xpeed::block> deserialize_block (xpeed::stream &, xpeed::block_uniquer * = nullptr);
std::shared_ptr<xpeed::block> deserialize_block (xpeed::stream &, xpeed::block_type, xpeed::block_uniquer * = nullptr);
std::shared_ptr<xpeed::block> deserialize_block_json (boost::property_tree::ptree const &, xpeed::block_uniquer * = nullptr);
void serialize_block (xpeed::stream &, xpeed::block const &);
}
