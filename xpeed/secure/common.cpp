#include <xpeed/secure/common.hpp>

#include <xpeed/lib/interface.h>
#include <xpeed/lib/numbers.hpp>
#include <xpeed/node/common.hpp>
#include <xpeed/secure/blockstore.hpp>
#include <xpeed/secure/versioning.hpp>

#include <boost/endian/conversion.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <queue>

#include <crypto/ed25519-donna/ed25519.h>

// Genesis keys for network variants
namespace
{
char const * test_private_key_data = "09D4F6628BBC2E3C62471F11F22353593281A2BD132063D63FD63FB2AF24B51C";
char const * test_public_key_data = "60F11CABC4C835910115DE329325B0CE5C1FA945AB808B53A17CCC0747577C72"; // xpd_1r9j5kowbk3ok61jdqjkkeku3mkw5ynndcw1jfbt4z8e1x5ogz5kd86ex4cs
char const * beta_public_key_data = "EA6E9C162570C06C7F490F2F6B06914B34A47A57AE9F0A37C03B12599EEA44D1"; // xpd_3tmgmid4cw81fjznk5shfe5b4ksnnjx7hdnz3auw1grkd8hgnj8jeoc5zm4c
char const * live_public_key_data = "A4BE0D749685899AA92035D657CABCFE8CDC4A9F4051DB1F64073BB89A8C2C2D"; // xpd_3b7y3otbf3ebmcnk1fgpcz7dszneuj7byi4juehpa3suq4fard3fm5os9ykn
char const * test_genesis_data = R"%%%({
	"type": "open",
	"source": "60F11CABC4C835910115DE329325B0CE5C1FA945AB808B53A17CCC0747577C72",
	"representative": "xpd_1r9j5kowbk3ok61jdqjkkeku3mkw5ynndcw1jfbt4z8e1x5ogz5kd86ex4cs",
	"account": "xpd_1r9j5kowbk3ok61jdqjkkeku3mkw5ynndcw1jfbt4z8e1x5ogz5kd86ex4cs",
	"work": "609f09d4f79d36f0",
	"signature": "587E94CD16D3951D6C41C96054D3D65E0313B1EC09521B06A1E73E2A3E1C0BBB688CB60F74616D1249BECBC2B9BF34BDB0D5E51D62E7DF8849072A0E2216DC0E"
})%%%";

char const * beta_genesis_data = R"%%%({
        "type": "open",
        "source": "EA6E9C162570C06C7F490F2F6B06914B34A47A57AE9F0A37C03B12599EEA44D1",
        "representative": "xpd_3tmgmid4cw81fjznk5shfe5b4ksnnjx7hdnz3auw1grkd8hgnj8jeoc5zm4c",
        "account": "xpd_3tmgmid4cw81fjznk5shfe5b4ksnnjx7hdnz3auw1grkd8hgnj8jeoc5zm4c",
        "work": "df6ff6f1ea4214d5",
        "signature": "CF2A65E5175DB89EBF9DD229A65E7AB1C3670FEAFE7E8381446D2D06D8AF9A7A229444E9ECF727B87D6CCD27967D8D9EC3EBD930331F1E0AA952BFFD1A20030E"
})%%%";

char const * live_genesis_data = R"%%%({
	"type": "open",
	"source": "A4BE0D749685899AA92035D657CABCFE8CDC4A9F4051DB1F64073BB89A8C2C2D",
	"representative": "xpd_3b7y3otbf3ebmcnk1fgpcz7dszneuj7byi4juehpa3suq4fard3fm5os9ykn",
	"account": "xpd_3b7y3otbf3ebmcnk1fgpcz7dszneuj7byi4juehpa3suq4fard3fm5os9ykn",
	"work": "537d0ab391864324",
	"signature": "427C22A6019D275D23476284A5AB301775E32BC21EC143048D5B72A5AD1140DA60E0597BD882591BA4B0A3F6EBE6C20FEA42931337167BAEA216F3CDAB0CB004"
})%%%";

class ledger_constants
{
public:
	ledger_constants () :
	zero_key ("0"),
	test_genesis_key (test_private_key_data),
	xpd_test_account (test_public_key_data),
	xpd_beta_account (beta_public_key_data),
	xpd_live_account (live_public_key_data),
	xpd_test_genesis (test_genesis_data),
	xpd_beta_genesis (beta_genesis_data),
	xpd_live_genesis (live_genesis_data),
	genesis_account (xpeed::is_test_network ? xpd_test_account : xpeed::is_beta_network ? xpd_beta_account : xpd_live_account),
	genesis_block (xpeed::is_test_network ? xpd_test_genesis : xpeed::is_beta_network ? xpd_beta_genesis : xpd_live_genesis),
	genesis_amount (std::numeric_limits<xpeed::uint128_t>::max ()),
	burn_account (0)
	{
	}
	xpeed::keypair zero_key;
	xpeed::keypair test_genesis_key;
	xpeed::account xpd_test_account;
	xpeed::account xpd_beta_account;
	xpeed::account xpd_live_account;
	std::string xpd_test_genesis;
	std::string xpd_beta_genesis;
	std::string xpd_live_genesis;
	xpeed::account genesis_account;
	std::string genesis_block;
	xpeed::uint128_t genesis_amount;
	xpeed::account burn_account;

	xpeed::account const & not_an_account ()
	{
		std::lock_guard<std::mutex> lk (mutex);
		if (!is_initialized)
		{
			// Randomly generating this means that no two nodes will ever have the same sentinel value which protects against some insecure algorithms
			xpeed::random_pool::generate_block (not_an_account_m.bytes.data (), not_an_account_m.bytes.size ());
			is_initialized = true;
		}
		return not_an_account_m;
	}

private:
	xpeed::account not_an_account_m;
	std::mutex mutex;
	bool is_initialized{ false };
};
ledger_constants globals;
}

size_t constexpr xpeed::send_block::size;
size_t constexpr xpeed::receive_block::size;
size_t constexpr xpeed::open_block::size;
size_t constexpr xpeed::change_block::size;
size_t constexpr xpeed::state_block::size;

xpeed::keypair const & xpeed::zero_key (globals.zero_key);
xpeed::keypair const & xpeed::test_genesis_key (globals.test_genesis_key);
xpeed::account const & xpeed::xpd_test_account (globals.xpd_test_account);
xpeed::account const & xpeed::xpd_beta_account (globals.xpd_beta_account);
xpeed::account const & xpeed::xpd_live_account (globals.xpd_live_account);
std::string const & xpeed::xpd_test_genesis (globals.xpd_test_genesis);
std::string const & xpeed::xpd_beta_genesis (globals.xpd_beta_genesis);
std::string const & xpeed::xpd_live_genesis (globals.xpd_live_genesis);

xpeed::account const & xpeed::genesis_account (globals.genesis_account);
std::string const & xpeed::genesis_block (globals.genesis_block);
xpeed::uint128_t const & xpeed::genesis_amount (globals.genesis_amount);
xpeed::account const & xpeed::burn_account (globals.burn_account);
xpeed::account const & xpeed::not_an_account ()
{
	return globals.not_an_account ();
}
// Create a new random keypair
xpeed::keypair::keypair ()
{
	random_pool::generate_block (prv.data.bytes.data (), prv.data.bytes.size ());
	ed25519_publickey (prv.data.bytes.data (), pub.bytes.data ());
}

// Create a keypair given a private key
xpeed::keypair::keypair (xpeed::raw_key && prv_a) :
prv (std::move (prv_a))
{
	ed25519_publickey (prv.data.bytes.data (), pub.bytes.data ());
}

// Create a keypair given a hex string of the private key
xpeed::keypair::keypair (std::string const & prv_a)
{
	auto error (prv.data.decode_hex (prv_a));
	assert (!error);
	ed25519_publickey (prv.data.bytes.data (), pub.bytes.data ());
}

// Serialize a block prefixed with an 8-bit typecode
void xpeed::serialize_block (xpeed::stream & stream_a, xpeed::block const & block_a)
{
	write (stream_a, block_a.type ());
	block_a.serialize (stream_a);
}

xpeed::account_info::account_info () :
head (0),
rep_block (0),
open_block (0),
balance (0),
modified (0),
block_count (0),
epoch (xpeed::epoch::epoch_0)
{
}

xpeed::account_info::account_info (xpeed::block_hash const & head_a, xpeed::block_hash const & rep_block_a, xpeed::block_hash const & open_block_a, xpeed::amount const & balance_a, uint64_t modified_a, uint64_t block_count_a, xpeed::epoch epoch_a) :
head (head_a),
rep_block (rep_block_a),
open_block (open_block_a),
balance (balance_a),
modified (modified_a),
block_count (block_count_a),
epoch (epoch_a)
{
}

void xpeed::account_info::serialize (xpeed::stream & stream_a) const
{
	write (stream_a, head.bytes);
	write (stream_a, rep_block.bytes);
	write (stream_a, open_block.bytes);
	write (stream_a, balance.bytes);
	write (stream_a, modified);
	write (stream_a, block_count);
}

bool xpeed::account_info::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		xpeed::read (stream_a, head.bytes);
		xpeed::read (stream_a, rep_block.bytes);
		xpeed::read (stream_a, open_block.bytes);
		xpeed::read (stream_a, balance.bytes);
		xpeed::read (stream_a, modified);
		xpeed::read (stream_a, block_count);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

bool xpeed::account_info::operator== (xpeed::account_info const & other_a) const
{
	return head == other_a.head && rep_block == other_a.rep_block && open_block == other_a.open_block && balance == other_a.balance && modified == other_a.modified && block_count == other_a.block_count && epoch == other_a.epoch;
}

bool xpeed::account_info::operator!= (xpeed::account_info const & other_a) const
{
	return !(*this == other_a);
}

size_t xpeed::account_info::db_size () const
{
	assert (reinterpret_cast<const uint8_t *> (this) == reinterpret_cast<const uint8_t *> (&head));
	assert (reinterpret_cast<const uint8_t *> (&head) + sizeof (head) == reinterpret_cast<const uint8_t *> (&rep_block));
	assert (reinterpret_cast<const uint8_t *> (&rep_block) + sizeof (rep_block) == reinterpret_cast<const uint8_t *> (&open_block));
	assert (reinterpret_cast<const uint8_t *> (&open_block) + sizeof (open_block) == reinterpret_cast<const uint8_t *> (&balance));
	assert (reinterpret_cast<const uint8_t *> (&balance) + sizeof (balance) == reinterpret_cast<const uint8_t *> (&modified));
	assert (reinterpret_cast<const uint8_t *> (&modified) + sizeof (modified) == reinterpret_cast<const uint8_t *> (&block_count));
	return sizeof (head) + sizeof (rep_block) + sizeof (open_block) + sizeof (balance) + sizeof (modified) + sizeof (block_count);
}

xpeed::block_counts::block_counts () :
send (0),
receive (0),
open (0),
change (0),
state_v0 (0),
state_v1 (0)
{
}

size_t xpeed::block_counts::sum ()
{
	return send + receive + open + change + state_v0 + state_v1;
}

xpeed::pending_info::pending_info () :
source (0),
amount (0),
epoch (xpeed::epoch::epoch_0)
{
}

xpeed::pending_info::pending_info (xpeed::account const & source_a, xpeed::amount const & amount_a, xpeed::epoch epoch_a) :
source (source_a),
amount (amount_a),
epoch (epoch_a)
{
}

void xpeed::pending_info::serialize (xpeed::stream & stream_a) const
{
	xpeed::write (stream_a, source.bytes);
	xpeed::write (stream_a, amount.bytes);
}

bool xpeed::pending_info::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		xpeed::read (stream_a, source.bytes);
		xpeed::read (stream_a, amount.bytes);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

bool xpeed::pending_info::operator== (xpeed::pending_info const & other_a) const
{
	return source == other_a.source && amount == other_a.amount && epoch == other_a.epoch;
}

xpeed::pending_key::pending_key () :
account (0),
hash (0)
{
}

xpeed::pending_key::pending_key (xpeed::account const & account_a, xpeed::block_hash const & hash_a) :
account (account_a),
hash (hash_a)
{
}

void xpeed::pending_key::serialize (xpeed::stream & stream_a) const
{
	xpeed::write (stream_a, account.bytes);
	xpeed::write (stream_a, hash.bytes);
}

bool xpeed::pending_key::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		xpeed::read (stream_a, account.bytes);
		xpeed::read (stream_a, hash.bytes);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

bool xpeed::pending_key::operator== (xpeed::pending_key const & other_a) const
{
	return account == other_a.account && hash == other_a.hash;
}

xpeed::block_hash xpeed::pending_key::key () const
{
	return account;
}

xpeed::unchecked_info::unchecked_info () :
block (nullptr),
account (0),
modified (0),
verified (xpeed::signature_verification::unknown)
{
}

xpeed::unchecked_info::unchecked_info (std::shared_ptr<xpeed::block> block_a, xpeed::account const & account_a, uint64_t modified_a, xpeed::signature_verification verified_a) :
block (block_a),
account (account_a),
modified (modified_a),
verified (verified_a)
{
}

void xpeed::unchecked_info::serialize (xpeed::stream & stream_a) const
{
	assert (block != nullptr);
	xpeed::serialize_block (stream_a, *block);
	xpeed::write (stream_a, account.bytes);
	xpeed::write (stream_a, modified);
	xpeed::write (stream_a, verified);
}

bool xpeed::unchecked_info::deserialize (xpeed::stream & stream_a)
{
	block = xpeed::deserialize_block (stream_a);
	bool error (block == nullptr);
	if (!error)
	{
		try
		{
			xpeed::read (stream_a, account.bytes);
			xpeed::read (stream_a, modified);
			xpeed::read (stream_a, verified);
		}
		catch (std::runtime_error const &)
		{
			error = true;
		}
	}
	return error;
}

bool xpeed::unchecked_info::operator== (xpeed::unchecked_info const & other_a) const
{
	return block->hash () == other_a.block->hash () && account == other_a.account && modified == other_a.modified && verified == other_a.verified;
}

xpeed::endpoint_key::endpoint_key (const std::array<uint8_t, 16> & address_a, uint16_t port_a) :
address (address_a), network_port (boost::endian::native_to_big (port_a))
{
}

const std::array<uint8_t, 16> & xpeed::endpoint_key::address_bytes () const
{
	return address;
}

uint16_t xpeed::endpoint_key::port () const
{
	return boost::endian::big_to_native (network_port);
}

xpeed::block_info::block_info () :
account (0),
balance (0)
{
}

xpeed::block_info::block_info (xpeed::account const & account_a, xpeed::amount const & balance_a) :
account (account_a),
balance (balance_a)
{
}

void xpeed::block_info::serialize (xpeed::stream & stream_a) const
{
	xpeed::write (stream_a, account.bytes);
	xpeed::write (stream_a, balance.bytes);
}

bool xpeed::block_info::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		xpeed::read (stream_a, account.bytes);
		xpeed::read (stream_a, balance.bytes);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

bool xpeed::block_info::operator== (xpeed::block_info const & other_a) const
{
	return account == other_a.account && balance == other_a.balance;
}

bool xpeed::vote::operator== (xpeed::vote const & other_a) const
{
	auto blocks_equal (true);
	if (blocks.size () != other_a.blocks.size ())
	{
		blocks_equal = false;
	}
	else
	{
		for (auto i (0); blocks_equal && i < blocks.size (); ++i)
		{
			auto block (blocks[i]);
			auto other_block (other_a.blocks[i]);
			if (block.which () != other_block.which ())
			{
				blocks_equal = false;
			}
			else if (block.which ())
			{
				if (boost::get<xpeed::block_hash> (block) != boost::get<xpeed::block_hash> (other_block))
				{
					blocks_equal = false;
				}
			}
			else
			{
				if (!(*boost::get<std::shared_ptr<xpeed::block>> (block) == *boost::get<std::shared_ptr<xpeed::block>> (other_block)))
				{
					blocks_equal = false;
				}
			}
		}
	}
	return sequence == other_a.sequence && blocks_equal && account == other_a.account && signature == other_a.signature;
}

bool xpeed::vote::operator!= (xpeed::vote const & other_a) const
{
	return !(*this == other_a);
}

std::string xpeed::vote::to_json () const
{
	std::stringstream stream;
	boost::property_tree::ptree tree;
	tree.put ("account", account.to_account ());
	tree.put ("signature", signature.number ());
	tree.put ("sequence", std::to_string (sequence));
	boost::property_tree::ptree blocks_tree;
	for (auto block : blocks)
	{
		if (block.which ())
		{
			blocks_tree.put ("", boost::get<std::shared_ptr<xpeed::block>> (block)->to_json ());
		}
		else
		{
			blocks_tree.put ("", boost::get<std::shared_ptr<xpeed::block>> (block)->hash ().to_string ());
		}
	}
	tree.add_child ("blocks", blocks_tree);
	boost::property_tree::write_json (stream, tree);
	return stream.str ();
}

xpeed::vote::vote (xpeed::vote const & other_a) :
sequence (other_a.sequence),
blocks (other_a.blocks),
account (other_a.account),
signature (other_a.signature)
{
}

xpeed::vote::vote (bool & error_a, xpeed::stream & stream_a, xpeed::block_uniquer * uniquer_a)
{
	error_a = deserialize (stream_a, uniquer_a);
}

xpeed::vote::vote (bool & error_a, xpeed::stream & stream_a, xpeed::block_type type_a, xpeed::block_uniquer * uniquer_a)
{
	try
	{
		xpeed::read (stream_a, account.bytes);
		xpeed::read (stream_a, signature.bytes);
		xpeed::read (stream_a, sequence);

		while (stream_a.in_avail () > 0)
		{
			if (type_a == xpeed::block_type::not_a_block)
			{
				xpeed::block_hash block_hash;
				xpeed::read (stream_a, block_hash);
				blocks.push_back (block_hash);
			}
			else
			{
				std::shared_ptr<xpeed::block> block (xpeed::deserialize_block (stream_a, type_a, uniquer_a));
				if (block == nullptr)
				{
					throw std::runtime_error ("Block is null");
				}
				blocks.push_back (block);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}

	if (blocks.empty ())
	{
		error_a = true;
	}
}

xpeed::vote::vote (xpeed::account const & account_a, xpeed::raw_key const & prv_a, uint64_t sequence_a, std::shared_ptr<xpeed::block> block_a) :
sequence (sequence_a),
blocks (1, block_a),
account (account_a),
signature (xpeed::sign_message (prv_a, account_a, hash ()))
{
}

xpeed::vote::vote (xpeed::account const & account_a, xpeed::raw_key const & prv_a, uint64_t sequence_a, std::vector<xpeed::block_hash> blocks_a) :
sequence (sequence_a),
account (account_a)
{
	assert (blocks_a.size () > 0);
	assert (blocks_a.size () <= 12);
	for (auto hash : blocks_a)
	{
		blocks.push_back (hash);
	}
	signature = xpeed::sign_message (prv_a, account_a, hash ());
}

std::string xpeed::vote::hashes_string () const
{
	std::string result;
	for (auto hash : *this)
	{
		result += hash.to_string ();
		result += ", ";
	}
	return result;
}

const std::string xpeed::vote::hash_prefix = "vote ";

xpeed::uint256_union xpeed::vote::hash () const
{
	xpeed::uint256_union result;
	blake2b_state hash;
	blake2b_init (&hash, sizeof (result.bytes));
	if (blocks.size () > 1 || (blocks.size () > 0 && blocks[0].which ()))
	{
		blake2b_update (&hash, hash_prefix.data (), hash_prefix.size ());
	}
	for (auto block_hash : *this)
	{
		blake2b_update (&hash, block_hash.bytes.data (), sizeof (block_hash.bytes));
	}
	union
	{
		uint64_t qword;
		std::array<uint8_t, 8> bytes;
	};
	qword = sequence;
	blake2b_update (&hash, bytes.data (), sizeof (bytes));
	blake2b_final (&hash, result.bytes.data (), sizeof (result.bytes));
	return result;
}

xpeed::uint256_union xpeed::vote::full_hash () const
{
	xpeed::uint256_union result;
	blake2b_state state;
	blake2b_init (&state, sizeof (result.bytes));
	blake2b_update (&state, hash ().bytes.data (), sizeof (hash ().bytes));
	blake2b_update (&state, account.bytes.data (), sizeof (account.bytes.data ()));
	blake2b_update (&state, signature.bytes.data (), sizeof (signature.bytes.data ()));
	blake2b_final (&state, result.bytes.data (), sizeof (result.bytes));
	return result;
}

void xpeed::vote::serialize (xpeed::stream & stream_a, xpeed::block_type type)
{
	write (stream_a, account);
	write (stream_a, signature);
	write (stream_a, sequence);
	for (auto block : blocks)
	{
		if (block.which ())
		{
			assert (type == xpeed::block_type::not_a_block);
			write (stream_a, boost::get<xpeed::block_hash> (block));
		}
		else
		{
			if (type == xpeed::block_type::not_a_block)
			{
				write (stream_a, boost::get<std::shared_ptr<xpeed::block>> (block)->hash ());
			}
			else
			{
				boost::get<std::shared_ptr<xpeed::block>> (block)->serialize (stream_a);
			}
		}
	}
}

void xpeed::vote::serialize (xpeed::stream & stream_a)
{
	write (stream_a, account);
	write (stream_a, signature);
	write (stream_a, sequence);
	for (auto block : blocks)
	{
		if (block.which ())
		{
			write (stream_a, xpeed::block_type::not_a_block);
			write (stream_a, boost::get<xpeed::block_hash> (block));
		}
		else
		{
			xpeed::serialize_block (stream_a, *boost::get<std::shared_ptr<xpeed::block>> (block));
		}
	}
}

bool xpeed::vote::deserialize (xpeed::stream & stream_a, xpeed::block_uniquer * uniquer_a)
{
	auto error (false);
	try
	{
		xpeed::read (stream_a, account);
		xpeed::read (stream_a, signature);
		xpeed::read (stream_a, sequence);

		xpeed::block_type type;

		while (true)
		{
			if (xpeed::try_read (stream_a, type))
			{
				// Reached the end of the stream
				break;
			}

			if (type == xpeed::block_type::not_a_block)
			{
				xpeed::block_hash block_hash;
				xpeed::read (stream_a, block_hash);
				blocks.push_back (block_hash);
			}
			else
			{
				std::shared_ptr<xpeed::block> block (xpeed::deserialize_block (stream_a, type, uniquer_a));
				if (block == nullptr)
				{
					throw std::runtime_error ("Block is empty");
				}

				blocks.push_back (block);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	if (blocks.empty ())
	{
		error = true;
	}

	return error;
}

bool xpeed::vote::validate ()
{
	auto result (xpeed::validate_message (account, hash (), signature));
	return result;
}

xpeed::block_hash xpeed::iterate_vote_blocks_as_hash::operator() (boost::variant<std::shared_ptr<xpeed::block>, xpeed::block_hash> const & item) const
{
	xpeed::block_hash result;
	if (item.which ())
	{
		result = boost::get<xpeed::block_hash> (item);
	}
	else
	{
		result = boost::get<std::shared_ptr<xpeed::block>> (item)->hash ();
	}
	return result;
}

boost::transform_iterator<xpeed::iterate_vote_blocks_as_hash, xpeed::vote_blocks_vec_iter> xpeed::vote::begin () const
{
	return boost::transform_iterator<xpeed::iterate_vote_blocks_as_hash, xpeed::vote_blocks_vec_iter> (blocks.begin (), xpeed::iterate_vote_blocks_as_hash ());
}

boost::transform_iterator<xpeed::iterate_vote_blocks_as_hash, xpeed::vote_blocks_vec_iter> xpeed::vote::end () const
{
	return boost::transform_iterator<xpeed::iterate_vote_blocks_as_hash, xpeed::vote_blocks_vec_iter> (blocks.end (), xpeed::iterate_vote_blocks_as_hash ());
}

xpeed::vote_uniquer::vote_uniquer (xpeed::block_uniquer & uniquer_a) :
uniquer (uniquer_a)
{
}

std::shared_ptr<xpeed::vote> xpeed::vote_uniquer::unique (std::shared_ptr<xpeed::vote> vote_a)
{
	auto result (vote_a);
	if (result != nullptr && !result->blocks.empty ())
	{
		if (!result->blocks[0].which ())
		{
			result->blocks[0] = uniquer.unique (boost::get<std::shared_ptr<xpeed::block>> (result->blocks[0]));
		}
		xpeed::uint256_union key (vote_a->full_hash ());
		std::lock_guard<std::mutex> lock (mutex);
		auto & existing (votes[key]);
		if (auto block_l = existing.lock ())
		{
			result = block_l;
		}
		else
		{
			existing = vote_a;
		}

		release_assert (std::numeric_limits<CryptoPP::word32>::max () > votes.size ());
		for (auto i (0); i < cleanup_count && votes.size () > 0; ++i)
		{
			auto random_offset = xpeed::random_pool::generate_word32 (0, static_cast<CryptoPP::word32> (votes.size () - 1));

			auto existing (std::next (votes.begin (), random_offset));
			if (existing == votes.end ())
			{
				existing = votes.begin ();
			}
			if (existing != votes.end ())
			{
				if (auto block_l = existing->second.lock ())
				{
					// Still live
				}
				else
				{
					votes.erase (existing);
				}
			}
		}
	}
	return result;
}

size_t xpeed::vote_uniquer::size ()
{
	std::lock_guard<std::mutex> lock (mutex);
	return votes.size ();
}

namespace xpeed
{
std::unique_ptr<seq_con_info_component> collect_seq_con_info (vote_uniquer & vote_uniquer, const std::string & name)
{
	auto count = vote_uniquer.size ();
	auto sizeof_element = sizeof (vote_uniquer::value_type);
	auto composite = std::make_unique<seq_con_info_composite> (name);
	composite->add_component (std::make_unique<seq_con_info_leaf> (seq_con_info{ "votes", count, sizeof_element }));
	return composite;
}
}

xpeed::genesis::genesis ()
{
	boost::property_tree::ptree tree;
	std::stringstream istream (xpeed::genesis_block);
	boost::property_tree::read_json (istream, tree);
	open = xpeed::deserialize_block_json (tree);
	assert (open != nullptr);
}

xpeed::block_hash xpeed::genesis::hash () const
{
	return open->hash ();
}
