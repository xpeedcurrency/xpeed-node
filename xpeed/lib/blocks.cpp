#include <xpeed/lib/blocks.hpp>
#include <xpeed/lib/numbers.hpp>
#include <xpeed/lib/utility.hpp>

#include <boost/endian/conversion.hpp>

#include <crypto/xxhash/xxhash.h>

/** Compare blocks, first by type, then content. This is an optimization over dynamic_cast, which is very slow on some platforms. */
namespace
{
template <typename T>
bool blocks_equal (T const & first, xpeed::block const & second)
{
	static_assert (std::is_base_of<xpeed::block, T>::value, "Input parameter is not a block type");
	return (first.type () == second.type ()) && (static_cast<T const &> (second)) == first;
}
}

std::string xpeed::to_string_hex (uint64_t value_a)
{
	std::stringstream stream;
	stream << std::hex << std::noshowbase << std::setw (16) << std::setfill ('0');
	stream << value_a;
	return stream.str ();
}

bool xpeed::from_string_hex (std::string const & value_a, uint64_t & target_a)
{
	auto error (value_a.empty ());
	if (!error)
	{
		error = value_a.size () > 16;
		if (!error)
		{
			std::stringstream stream (value_a);
			stream << std::hex << std::noshowbase;
			try
			{
				uint64_t number_l;
				stream >> number_l;
				target_a = number_l;
				if (!stream.eof ())
				{
					error = true;
				}
			}
			catch (std::runtime_error &)
			{
				error = true;
			}
		}
	}
	return error;
}

std::string xpeed::block::to_json () const
{
	std::string result;
	serialize_json (result);
	return result;
}

size_t xpeed::block::size (xpeed::block_type type_a)
{
	size_t result (0);
	switch (type_a)
	{
		case xpeed::block_type::invalid:
		case xpeed::block_type::not_a_block:
			assert (false);
			break;
		case xpeed::block_type::send:
			result = xpeed::send_block::size;
			break;
		case xpeed::block_type::receive:
			result = xpeed::receive_block::size;
			break;
		case xpeed::block_type::change:
			result = xpeed::change_block::size;
			break;
		case xpeed::block_type::open:
			result = xpeed::open_block::size;
			break;
		case xpeed::block_type::state:
			result = xpeed::state_block::size;
			break;
	}
	return result;
}

xpeed::block_hash xpeed::block::hash () const
{
	xpeed::uint256_union result;
	blake2b_state hash_l;
	auto status (blake2b_init (&hash_l, sizeof (result.bytes)));
	assert (status == 0);
	hash (hash_l);
	status = blake2b_final (&hash_l, result.bytes.data (), sizeof (result.bytes));
	assert (status == 0);
	return result;
}

xpeed::block_hash xpeed::block::full_hash () const
{
	xpeed::block_hash result;
	blake2b_state state;
	blake2b_init (&state, sizeof (result.bytes));
	blake2b_update (&state, hash ().bytes.data (), sizeof (hash ()));
	auto signature (block_signature ());
	blake2b_update (&state, signature.bytes.data (), sizeof (signature));
	auto work (block_work ());
	blake2b_update (&state, &work, sizeof (work));
	blake2b_final (&state, result.bytes.data (), sizeof (result.bytes));
	return result;
}

xpeed::account xpeed::block::representative () const
{
	return 0;
}

xpeed::block_hash xpeed::block::source () const
{
	return 0;
}

xpeed::block_hash xpeed::block::link () const
{
	return 0;
}

xpeed::account xpeed::block::account () const
{
	return 0;
}

void xpeed::send_block::visit (xpeed::block_visitor & visitor_a) const
{
	visitor_a.send_block (*this);
}

void xpeed::send_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t xpeed::send_block::block_work () const
{
	return work;
}

void xpeed::send_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

xpeed::send_hashables::send_hashables (xpeed::block_hash const & previous_a, xpeed::account const & destination_a, xpeed::amount const & balance_a) :
previous (previous_a),
destination (destination_a),
balance (balance_a)
{
}

xpeed::send_hashables::send_hashables (bool & error_a, xpeed::stream & stream_a)
{
	try
	{
		xpeed::read (stream_a, previous.bytes);
		xpeed::read (stream_a, destination.bytes);
		xpeed::read (stream_a, balance.bytes);
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

xpeed::send_hashables::send_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto destination_l (tree_a.get<std::string> ("destination"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = destination.decode_account (destination_l);
			if (!error_a)
			{
				error_a = balance.decode_hex (balance_l);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void xpeed::send_hashables::hash (blake2b_state & hash_a) const
{
	auto status (blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes)));
	assert (status == 0);
	status = blake2b_update (&hash_a, destination.bytes.data (), sizeof (destination.bytes));
	assert (status == 0);
	status = blake2b_update (&hash_a, balance.bytes.data (), sizeof (balance.bytes));
	assert (status == 0);
}

void xpeed::send_block::serialize (xpeed::stream & stream_a) const
{
	write (stream_a, hashables.previous.bytes);
	write (stream_a, hashables.destination.bytes);
	write (stream_a, hashables.balance.bytes);
	write (stream_a, signature.bytes);
	write (stream_a, work);
}

bool xpeed::send_block::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		read (stream_a, hashables.previous.bytes);
		read (stream_a, hashables.destination.bytes);
		read (stream_a, hashables.balance.bytes);
		read (stream_a, signature.bytes);
		read (stream_a, work);
	}
	catch (std::exception const &)
	{
		error = true;
	}

	return error;
}

void xpeed::send_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "send");
	std::string previous;
	hashables.previous.encode_hex (previous);
	tree.put ("previous", previous);
	tree.put ("destination", hashables.destination.to_account ());
	std::string balance;
	hashables.balance.encode_hex (balance);
	tree.put ("balance", balance);
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", xpeed::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool xpeed::send_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "send");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto destination_l (tree_a.get<std::string> ("destination"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.destination.decode_account (destination_l);
			if (!error)
			{
				error = hashables.balance.decode_hex (balance_l);
				if (!error)
				{
					error = xpeed::from_string_hex (work_l, work);
					if (!error)
					{
						error = signature.decode_hex (signature_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

xpeed::send_block::send_block (xpeed::block_hash const & previous_a, xpeed::account const & destination_a, xpeed::amount const & balance_a, xpeed::raw_key const & prv_a, xpeed::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, destination_a, balance_a),
signature (xpeed::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

xpeed::send_block::send_block (bool & error_a, xpeed::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		try
		{
			xpeed::read (stream_a, signature.bytes);
			xpeed::read (stream_a, work);
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

xpeed::send_block::send_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = signature.decode_hex (signature_l);
			if (!error_a)
			{
				error_a = xpeed::from_string_hex (work_l, work);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

bool xpeed::send_block::operator== (xpeed::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool xpeed::send_block::valid_predecessor (xpeed::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case xpeed::block_type::send:
		case xpeed::block_type::receive:
		case xpeed::block_type::open:
		case xpeed::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

xpeed::block_type xpeed::send_block::type () const
{
	return xpeed::block_type::send;
}

bool xpeed::send_block::operator== (xpeed::send_block const & other_a) const
{
	auto result (hashables.destination == other_a.hashables.destination && hashables.previous == other_a.hashables.previous && hashables.balance == other_a.hashables.balance && work == other_a.work && signature == other_a.signature);
	return result;
}

xpeed::block_hash xpeed::send_block::previous () const
{
	return hashables.previous;
}

xpeed::block_hash xpeed::send_block::root () const
{
	return hashables.previous;
}

xpeed::signature xpeed::send_block::block_signature () const
{
	return signature;
}

void xpeed::send_block::signature_set (xpeed::uint512_union const & signature_a)
{
	signature = signature_a;
}

xpeed::open_hashables::open_hashables (xpeed::block_hash const & source_a, xpeed::account const & representative_a, xpeed::account const & account_a) :
source (source_a),
representative (representative_a),
account (account_a)
{
}

xpeed::open_hashables::open_hashables (bool & error_a, xpeed::stream & stream_a)
{
	try
	{
		xpeed::read (stream_a, source.bytes);
		xpeed::read (stream_a, representative.bytes);
		xpeed::read (stream_a, account.bytes);
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

xpeed::open_hashables::open_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto source_l (tree_a.get<std::string> ("source"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto account_l (tree_a.get<std::string> ("account"));
		error_a = source.decode_hex (source_l);
		if (!error_a)
		{
			error_a = representative.decode_account (representative_l);
			if (!error_a)
			{
				error_a = account.decode_account (account_l);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void xpeed::open_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, source.bytes.data (), sizeof (source.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
	blake2b_update (&hash_a, account.bytes.data (), sizeof (account.bytes));
}

xpeed::open_block::open_block (xpeed::block_hash const & source_a, xpeed::account const & representative_a, xpeed::account const & account_a, xpeed::raw_key const & prv_a, xpeed::public_key const & pub_a, uint64_t work_a) :
hashables (source_a, representative_a, account_a),
signature (xpeed::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
	assert (!representative_a.is_zero ());
}

xpeed::open_block::open_block (xpeed::block_hash const & source_a, xpeed::account const & representative_a, xpeed::account const & account_a, std::nullptr_t) :
hashables (source_a, representative_a, account_a),
work (0)
{
	signature.clear ();
}

xpeed::open_block::open_block (bool & error_a, xpeed::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		try
		{
			xpeed::read (stream_a, signature);
			xpeed::read (stream_a, work);
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

xpeed::open_block::open_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto work_l (tree_a.get<std::string> ("work"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			error_a = xpeed::from_string_hex (work_l, work);
			if (!error_a)
			{
				error_a = signature.decode_hex (signature_l);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void xpeed::open_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t xpeed::open_block::block_work () const
{
	return work;
}

void xpeed::open_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

xpeed::block_hash xpeed::open_block::previous () const
{
	xpeed::block_hash result (0);
	return result;
}

xpeed::account xpeed::open_block::account () const
{
	return hashables.account;
}

void xpeed::open_block::serialize (xpeed::stream & stream_a) const
{
	write (stream_a, hashables.source);
	write (stream_a, hashables.representative);
	write (stream_a, hashables.account);
	write (stream_a, signature);
	write (stream_a, work);
}

bool xpeed::open_block::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		read (stream_a, hashables.source);
		read (stream_a, hashables.representative);
		read (stream_a, hashables.account);
		read (stream_a, signature);
		read (stream_a, work);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

void xpeed::open_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "open");
	tree.put ("source", hashables.source.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("account", hashables.account.to_account ());
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", xpeed::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool xpeed::open_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "open");
		auto source_l (tree_a.get<std::string> ("source"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto account_l (tree_a.get<std::string> ("account"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.source.decode_hex (source_l);
		if (!error)
		{
			error = hashables.representative.decode_hex (representative_l);
			if (!error)
			{
				error = hashables.account.decode_hex (account_l);
				if (!error)
				{
					error = xpeed::from_string_hex (work_l, work);
					if (!error)
					{
						error = signature.decode_hex (signature_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void xpeed::open_block::visit (xpeed::block_visitor & visitor_a) const
{
	visitor_a.open_block (*this);
}

xpeed::block_type xpeed::open_block::type () const
{
	return xpeed::block_type::open;
}

bool xpeed::open_block::operator== (xpeed::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool xpeed::open_block::operator== (xpeed::open_block const & other_a) const
{
	return hashables.source == other_a.hashables.source && hashables.representative == other_a.hashables.representative && hashables.account == other_a.hashables.account && work == other_a.work && signature == other_a.signature;
}

bool xpeed::open_block::valid_predecessor (xpeed::block const & block_a) const
{
	return false;
}

xpeed::block_hash xpeed::open_block::source () const
{
	return hashables.source;
}

xpeed::block_hash xpeed::open_block::root () const
{
	return hashables.account;
}

xpeed::account xpeed::open_block::representative () const
{
	return hashables.representative;
}

xpeed::signature xpeed::open_block::block_signature () const
{
	return signature;
}

void xpeed::open_block::signature_set (xpeed::uint512_union const & signature_a)
{
	signature = signature_a;
}

xpeed::change_hashables::change_hashables (xpeed::block_hash const & previous_a, xpeed::account const & representative_a) :
previous (previous_a),
representative (representative_a)
{
}

xpeed::change_hashables::change_hashables (bool & error_a, xpeed::stream & stream_a)
{
	try
	{
		xpeed::read (stream_a, previous);
		xpeed::read (stream_a, representative);
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

xpeed::change_hashables::change_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = representative.decode_account (representative_l);
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void xpeed::change_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
}

xpeed::change_block::change_block (xpeed::block_hash const & previous_a, xpeed::account const & representative_a, xpeed::raw_key const & prv_a, xpeed::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, representative_a),
signature (xpeed::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

xpeed::change_block::change_block (bool & error_a, xpeed::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		try
		{
			xpeed::read (stream_a, signature);
			xpeed::read (stream_a, work);
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

xpeed::change_block::change_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto work_l (tree_a.get<std::string> ("work"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			error_a = xpeed::from_string_hex (work_l, work);
			if (!error_a)
			{
				error_a = signature.decode_hex (signature_l);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void xpeed::change_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t xpeed::change_block::block_work () const
{
	return work;
}

void xpeed::change_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

xpeed::block_hash xpeed::change_block::previous () const
{
	return hashables.previous;
}

void xpeed::change_block::serialize (xpeed::stream & stream_a) const
{
	write (stream_a, hashables.previous);
	write (stream_a, hashables.representative);
	write (stream_a, signature);
	write (stream_a, work);
}

bool xpeed::change_block::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		read (stream_a, hashables.previous);
		read (stream_a, hashables.representative);
		read (stream_a, signature);
		read (stream_a, work);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

void xpeed::change_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "change");
	tree.put ("previous", hashables.previous.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("work", xpeed::to_string_hex (work));
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool xpeed::change_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "change");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.representative.decode_hex (representative_l);
			if (!error)
			{
				error = xpeed::from_string_hex (work_l, work);
				if (!error)
				{
					error = signature.decode_hex (signature_l);
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void xpeed::change_block::visit (xpeed::block_visitor & visitor_a) const
{
	visitor_a.change_block (*this);
}

xpeed::block_type xpeed::change_block::type () const
{
	return xpeed::block_type::change;
}

bool xpeed::change_block::operator== (xpeed::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool xpeed::change_block::operator== (xpeed::change_block const & other_a) const
{
	return hashables.previous == other_a.hashables.previous && hashables.representative == other_a.hashables.representative && work == other_a.work && signature == other_a.signature;
}

bool xpeed::change_block::valid_predecessor (xpeed::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case xpeed::block_type::send:
		case xpeed::block_type::receive:
		case xpeed::block_type::open:
		case xpeed::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

xpeed::block_hash xpeed::change_block::root () const
{
	return hashables.previous;
}

xpeed::account xpeed::change_block::representative () const
{
	return hashables.representative;
}

xpeed::signature xpeed::change_block::block_signature () const
{
	return signature;
}

void xpeed::change_block::signature_set (xpeed::uint512_union const & signature_a)
{
	signature = signature_a;
}

xpeed::state_hashables::state_hashables (xpeed::account const & account_a, xpeed::block_hash const & previous_a, xpeed::account const & representative_a, xpeed::amount const & balance_a, xpeed::uint256_union const & link_a) :
account (account_a),
previous (previous_a),
representative (representative_a),
balance (balance_a),
link (link_a)
{
}

xpeed::state_hashables::state_hashables (bool & error_a, xpeed::stream & stream_a)
{
	try
	{
		xpeed::read (stream_a, account);
		xpeed::read (stream_a, previous);
		xpeed::read (stream_a, representative);
		xpeed::read (stream_a, balance);
		xpeed::read (stream_a, link);
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

xpeed::state_hashables::state_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));
		error_a = account.decode_account (account_l);
		if (!error_a)
		{
			error_a = previous.decode_hex (previous_l);
			if (!error_a)
			{
				error_a = representative.decode_account (representative_l);
				if (!error_a)
				{
					error_a = balance.decode_dec (balance_l);
					if (!error_a)
					{
						error_a = link.decode_account (link_l) && link.decode_hex (link_l);
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void xpeed::state_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, account.bytes.data (), sizeof (account.bytes));
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, representative.bytes.data (), sizeof (representative.bytes));
	blake2b_update (&hash_a, balance.bytes.data (), sizeof (balance.bytes));
	blake2b_update (&hash_a, link.bytes.data (), sizeof (link.bytes));
}

xpeed::state_block::state_block (xpeed::account const & account_a, xpeed::block_hash const & previous_a, xpeed::account const & representative_a, xpeed::amount const & balance_a, xpeed::uint256_union const & link_a, xpeed::raw_key const & prv_a, xpeed::public_key const & pub_a, uint64_t work_a) :
hashables (account_a, previous_a, representative_a, balance_a, link_a),
signature (xpeed::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

xpeed::state_block::state_block (bool & error_a, xpeed::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		try
		{
			xpeed::read (stream_a, signature);
			xpeed::read (stream_a, work);
			boost::endian::big_to_native_inplace (work);
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

xpeed::state_block::state_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto type_l (tree_a.get<std::string> ("type"));
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = type_l != "state";
			if (!error_a)
			{
				error_a = xpeed::from_string_hex (work_l, work);
				if (!error_a)
				{
					error_a = signature.decode_hex (signature_l);
				}
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void xpeed::state_block::hash (blake2b_state & hash_a) const
{
	xpeed::uint256_union preamble (static_cast<uint64_t> (xpeed::block_type::state));
	blake2b_update (&hash_a, preamble.bytes.data (), preamble.bytes.size ());
	hashables.hash (hash_a);
}

uint64_t xpeed::state_block::block_work () const
{
	return work;
}

void xpeed::state_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

xpeed::block_hash xpeed::state_block::previous () const
{
	return hashables.previous;
}

xpeed::account xpeed::state_block::account () const
{
	return hashables.account;
}

void xpeed::state_block::serialize (xpeed::stream & stream_a) const
{
	write (stream_a, hashables.account);
	write (stream_a, hashables.previous);
	write (stream_a, hashables.representative);
	write (stream_a, hashables.balance);
	write (stream_a, hashables.link);
	write (stream_a, signature);
	write (stream_a, boost::endian::native_to_big (work));
}

bool xpeed::state_block::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		read (stream_a, hashables.account);
		read (stream_a, hashables.previous);
		read (stream_a, hashables.representative);
		read (stream_a, hashables.balance);
		read (stream_a, hashables.link);
		read (stream_a, signature);
		read (stream_a, work);
		boost::endian::big_to_native_inplace (work);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

void xpeed::state_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "state");
	tree.put ("account", hashables.account.to_account ());
	tree.put ("previous", hashables.previous.to_string ());
	tree.put ("representative", representative ().to_account ());
	tree.put ("balance", hashables.balance.to_string_dec ());
	tree.put ("link", hashables.link.to_string ());
	tree.put ("link_as_account", hashables.link.to_account ());
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("signature", signature_l);
	tree.put ("work", xpeed::to_string_hex (work));
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool xpeed::state_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "state");
		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto representative_l (tree_a.get<std::string> ("representative"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.account.decode_account (account_l);
		if (!error)
		{
			error = hashables.previous.decode_hex (previous_l);
			if (!error)
			{
				error = hashables.representative.decode_account (representative_l);
				if (!error)
				{
					error = hashables.balance.decode_dec (balance_l);
					if (!error)
					{
						error = hashables.link.decode_account (link_l) && hashables.link.decode_hex (link_l);
						if (!error)
						{
							error = xpeed::from_string_hex (work_l, work);
							if (!error)
							{
								error = signature.decode_hex (signature_l);
							}
						}
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void xpeed::state_block::visit (xpeed::block_visitor & visitor_a) const
{
	visitor_a.state_block (*this);
}

xpeed::block_type xpeed::state_block::type () const
{
	return xpeed::block_type::state;
}

bool xpeed::state_block::operator== (xpeed::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool xpeed::state_block::operator== (xpeed::state_block const & other_a) const
{
	return hashables.account == other_a.hashables.account && hashables.previous == other_a.hashables.previous && hashables.representative == other_a.hashables.representative && hashables.balance == other_a.hashables.balance && hashables.link == other_a.hashables.link && signature == other_a.signature && work == other_a.work;
}

bool xpeed::state_block::valid_predecessor (xpeed::block const & block_a) const
{
	return true;
}

xpeed::block_hash xpeed::state_block::root () const
{
	return !hashables.previous.is_zero () ? hashables.previous : hashables.account;
}

xpeed::block_hash xpeed::state_block::link () const
{
	return hashables.link;
}

xpeed::account xpeed::state_block::representative () const
{
	return hashables.representative;
}

xpeed::signature xpeed::state_block::block_signature () const
{
	return signature;
}

void xpeed::state_block::signature_set (xpeed::uint512_union const & signature_a)
{
	signature = signature_a;
}

std::shared_ptr<xpeed::block> xpeed::deserialize_block_json (boost::property_tree::ptree const & tree_a, xpeed::block_uniquer * uniquer_a)
{
	std::shared_ptr<xpeed::block> result;
	try
	{
		auto type (tree_a.get<std::string> ("type"));
		if (type == "receive")
		{
			bool error (false);
			std::unique_ptr<xpeed::receive_block> obj (new xpeed::receive_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "send")
		{
			bool error (false);
			std::unique_ptr<xpeed::send_block> obj (new xpeed::send_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "open")
		{
			bool error (false);
			std::unique_ptr<xpeed::open_block> obj (new xpeed::open_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "change")
		{
			bool error (false);
			std::unique_ptr<xpeed::change_block> obj (new xpeed::change_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
		else if (type == "state")
		{
			bool error (false);
			std::unique_ptr<xpeed::state_block> obj (new xpeed::state_block (error, tree_a));
			if (!error)
			{
				result = std::move (obj);
			}
		}
	}
	catch (std::runtime_error const &)
	{
	}
	if (uniquer_a != nullptr)
	{
		result = uniquer_a->unique (result);
	}
	return result;
}

std::shared_ptr<xpeed::block> xpeed::deserialize_block (xpeed::stream & stream_a, xpeed::block_uniquer * uniquer_a)
{
	xpeed::block_type type;
	auto error (try_read (stream_a, type));
	std::shared_ptr<xpeed::block> result;
	if (!error)
	{
		result = xpeed::deserialize_block (stream_a, type);
	}
	return result;
}

std::shared_ptr<xpeed::block> xpeed::deserialize_block (xpeed::stream & stream_a, xpeed::block_type type_a, xpeed::block_uniquer * uniquer_a)
{
	std::shared_ptr<xpeed::block> result;
	switch (type_a)
	{
		case xpeed::block_type::receive:
		{
			bool error (false);
			std::unique_ptr<xpeed::receive_block> obj (new xpeed::receive_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case xpeed::block_type::send:
		{
			bool error (false);
			std::unique_ptr<xpeed::send_block> obj (new xpeed::send_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case xpeed::block_type::open:
		{
			bool error (false);
			std::unique_ptr<xpeed::open_block> obj (new xpeed::open_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case xpeed::block_type::change:
		{
			bool error (false);
			std::unique_ptr<xpeed::change_block> obj (new xpeed::change_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		case xpeed::block_type::state:
		{
			bool error (false);
			std::unique_ptr<xpeed::state_block> obj (new xpeed::state_block (error, stream_a));
			if (!error)
			{
				result = std::move (obj);
			}
			break;
		}
		default:
			assert (false);
			break;
	}
	if (uniquer_a != nullptr)
	{
		result = uniquer_a->unique (result);
	}
	return result;
}

void xpeed::receive_block::visit (xpeed::block_visitor & visitor_a) const
{
	visitor_a.receive_block (*this);
}

bool xpeed::receive_block::operator== (xpeed::receive_block const & other_a) const
{
	auto result (hashables.previous == other_a.hashables.previous && hashables.source == other_a.hashables.source && work == other_a.work && signature == other_a.signature);
	return result;
}

void xpeed::receive_block::serialize (xpeed::stream & stream_a) const
{
	write (stream_a, hashables.previous.bytes);
	write (stream_a, hashables.source.bytes);
	write (stream_a, signature.bytes);
	write (stream_a, work);
}

bool xpeed::receive_block::deserialize (xpeed::stream & stream_a)
{
	auto error (false);
	try
	{
		read (stream_a, hashables.previous.bytes);
		read (stream_a, hashables.source.bytes);
		read (stream_a, signature.bytes);
		read (stream_a, work);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

void xpeed::receive_block::serialize_json (std::string & string_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("type", "receive");
	std::string previous;
	hashables.previous.encode_hex (previous);
	tree.put ("previous", previous);
	std::string source;
	hashables.source.encode_hex (source);
	tree.put ("source", source);
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("work", xpeed::to_string_hex (work));
	tree.put ("signature", signature_l);
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool xpeed::receive_block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		assert (tree_a.get<std::string> ("type") == "receive");
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto source_l (tree_a.get<std::string> ("source"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.previous.decode_hex (previous_l);
		if (!error)
		{
			error = hashables.source.decode_hex (source_l);
			if (!error)
			{
				error = xpeed::from_string_hex (work_l, work);
				if (!error)
				{
					error = signature.decode_hex (signature_l);
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

xpeed::receive_block::receive_block (xpeed::block_hash const & previous_a, xpeed::block_hash const & source_a, xpeed::raw_key const & prv_a, xpeed::public_key const & pub_a, uint64_t work_a) :
hashables (previous_a, source_a),
signature (xpeed::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
}

xpeed::receive_block::receive_block (bool & error_a, xpeed::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		try
		{
			xpeed::read (stream_a, signature);
			xpeed::read (stream_a, work);
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

xpeed::receive_block::receive_block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = signature.decode_hex (signature_l);
			if (!error_a)
			{
				error_a = xpeed::from_string_hex (work_l, work);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

void xpeed::receive_block::hash (blake2b_state & hash_a) const
{
	hashables.hash (hash_a);
}

uint64_t xpeed::receive_block::block_work () const
{
	return work;
}

void xpeed::receive_block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

bool xpeed::receive_block::operator== (xpeed::block const & other_a) const
{
	return blocks_equal (*this, other_a);
}

bool xpeed::receive_block::valid_predecessor (xpeed::block const & block_a) const
{
	bool result;
	switch (block_a.type ())
	{
		case xpeed::block_type::send:
		case xpeed::block_type::receive:
		case xpeed::block_type::open:
		case xpeed::block_type::change:
			result = true;
			break;
		default:
			result = false;
			break;
	}
	return result;
}

xpeed::block_hash xpeed::receive_block::previous () const
{
	return hashables.previous;
}

xpeed::block_hash xpeed::receive_block::source () const
{
	return hashables.source;
}

xpeed::block_hash xpeed::receive_block::root () const
{
	return hashables.previous;
}

xpeed::signature xpeed::receive_block::block_signature () const
{
	return signature;
}

void xpeed::receive_block::signature_set (xpeed::uint512_union const & signature_a)
{
	signature = signature_a;
}

xpeed::block_type xpeed::receive_block::type () const
{
	return xpeed::block_type::receive;
}

xpeed::receive_hashables::receive_hashables (xpeed::block_hash const & previous_a, xpeed::block_hash const & source_a) :
previous (previous_a),
source (source_a)
{
}

xpeed::receive_hashables::receive_hashables (bool & error_a, xpeed::stream & stream_a)
{
	try
	{
		xpeed::read (stream_a, previous.bytes);
		xpeed::read (stream_a, source.bytes);
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

xpeed::receive_hashables::receive_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	try
	{
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto source_l (tree_a.get<std::string> ("source"));
		error_a = previous.decode_hex (previous_l);
		if (!error_a)
		{
			error_a = source.decode_hex (source_l);
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void xpeed::receive_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, source.bytes.data (), sizeof (source.bytes));
}

std::shared_ptr<xpeed::block> xpeed::block_uniquer::unique (std::shared_ptr<xpeed::block> block_a)
{
	auto result (block_a);
	if (result != nullptr)
	{
		xpeed::uint256_union key (block_a->full_hash ());
		std::lock_guard<std::mutex> lock (mutex);
		auto & existing (blocks[key]);
		if (auto block_l = existing.lock ())
		{
			result = block_l;
		}
		else
		{
			existing = block_a;
		}
		release_assert (std::numeric_limits<CryptoPP::word32>::max () > blocks.size ());
		for (auto i (0); i < cleanup_count && blocks.size () > 0; ++i)
		{
			auto random_offset (xpeed::random_pool::generate_word32 (0, static_cast<CryptoPP::word32> (blocks.size () - 1)));
			auto existing (std::next (blocks.begin (), random_offset));
			if (existing == blocks.end ())
			{
				existing = blocks.begin ();
			}
			if (existing != blocks.end ())
			{
				if (auto block_l = existing->second.lock ())
				{
					// Still live
				}
				else
				{
					blocks.erase (existing);
				}
			}
		}
	}
	return result;
}

size_t xpeed::block_uniquer::size ()
{
	std::lock_guard<std::mutex> lock (mutex);
	return blocks.size ();
}

namespace xpeed
{
std::unique_ptr<seq_con_info_component> collect_seq_con_info (block_uniquer & block_uniquer, const std::string & name)
{
	auto count = block_uniquer.size ();
	auto sizeof_element = sizeof (block_uniquer::value_type);
	auto composite = std::make_unique<seq_con_info_composite> (name);
	composite->add_component (std::make_unique<seq_con_info_leaf> (seq_con_info{ "blocks", count, sizeof_element }));
	return composite;
}
}
