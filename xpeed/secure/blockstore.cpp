#include <xpeed/node/common.hpp>
#include <xpeed/node/wallet.hpp>
#include <xpeed/secure/blockstore.hpp>

#include <boost/polymorphic_cast.hpp>

#include <boost/endian/conversion.hpp>

xpeed::block_sideband::block_sideband (xpeed::block_type type_a, xpeed::account const & account_a, xpeed::block_hash const & successor_a, xpeed::amount const & balance_a, uint64_t height_a, uint64_t timestamp_a) :
type (type_a),
successor (successor_a),
account (account_a),
balance (balance_a),
height (height_a),
timestamp (timestamp_a)
{
}

size_t xpeed::block_sideband::size (xpeed::block_type type_a)
{
	size_t result (0);
	result += sizeof (successor);
	if (type_a != xpeed::block_type::state && type_a != xpeed::block_type::open)
	{
		result += sizeof (account);
	}
	if (type_a != xpeed::block_type::open)
	{
		result += sizeof (height);
	}
	if (type_a == xpeed::block_type::receive || type_a == xpeed::block_type::change || type_a == xpeed::block_type::open)
	{
		result += sizeof (balance);
	}
	result += sizeof (timestamp);
	return result;
}

void xpeed::block_sideband::serialize (xpeed::stream & stream_a) const
{
	xpeed::write (stream_a, successor.bytes);
	if (type != xpeed::block_type::state && type != xpeed::block_type::open)
	{
		xpeed::write (stream_a, account.bytes);
	}
	if (type != xpeed::block_type::open)
	{
		xpeed::write (stream_a, boost::endian::native_to_big (height));
	}
	if (type == xpeed::block_type::receive || type == xpeed::block_type::change || type == xpeed::block_type::open)
	{
		xpeed::write (stream_a, balance.bytes);
	}
	xpeed::write (stream_a, boost::endian::native_to_big (timestamp));
}

bool xpeed::block_sideband::deserialize (xpeed::stream & stream_a)
{
	bool result (false);
	try
	{
		xpeed::read (stream_a, successor.bytes);
		if (type != xpeed::block_type::state && type != xpeed::block_type::open)
		{
			xpeed::read (stream_a, account.bytes);
		}
		if (type != xpeed::block_type::open)
		{
			xpeed::read (stream_a, height);
			boost::endian::big_to_native_inplace (height);
		}
		else
		{
			height = 1;
		}
		if (type == xpeed::block_type::receive || type == xpeed::block_type::change || type == xpeed::block_type::open)
		{
			xpeed::read (stream_a, balance.bytes);
		}
		xpeed::read (stream_a, timestamp);
		boost::endian::big_to_native_inplace (timestamp);
	}
	catch (std::runtime_error &)
	{
		result = true;
	}

	return result;
}

xpeed::summation_visitor::summation_visitor (xpeed::transaction const & transaction_a, xpeed::block_store & store_a) :
transaction (transaction_a),
store (store_a)
{
}

void xpeed::summation_visitor::send_block (xpeed::send_block const & block_a)
{
	assert (current->type != summation_type::invalid && current != nullptr);
	if (current->type == summation_type::amount)
	{
		sum_set (block_a.hashables.balance.number ());
		current->balance_hash = block_a.hashables.previous;
		current->amount_hash = 0;
	}
	else
	{
		sum_add (block_a.hashables.balance.number ());
		current->balance_hash = 0;
	}
}

void xpeed::summation_visitor::state_block (xpeed::state_block const & block_a)
{
	assert (current->type != summation_type::invalid && current != nullptr);
	sum_set (block_a.hashables.balance.number ());
	if (current->type == summation_type::amount)
	{
		current->balance_hash = block_a.hashables.previous;
		current->amount_hash = 0;
	}
	else
	{
		current->balance_hash = 0;
	}
}

void xpeed::summation_visitor::receive_block (xpeed::receive_block const & block_a)
{
	assert (current->type != summation_type::invalid && current != nullptr);
	if (current->type == summation_type::amount)
	{
		current->amount_hash = block_a.hashables.source;
	}
	else
	{
		xpeed::block_info block_info;
		if (!store.block_info_get (transaction, block_a.hash (), block_info))
		{
			sum_add (block_info.balance.number ());
			current->balance_hash = 0;
		}
		else
		{
			current->amount_hash = block_a.hashables.source;
			current->balance_hash = block_a.hashables.previous;
		}
	}
}

void xpeed::summation_visitor::open_block (xpeed::open_block const & block_a)
{
	assert (current->type != summation_type::invalid && current != nullptr);
	if (current->type == summation_type::amount)
	{
		if (block_a.hashables.source != xpeed::genesis_account)
		{
			current->amount_hash = block_a.hashables.source;
		}
		else
		{
			sum_set (xpeed::genesis_amount);
			current->amount_hash = 0;
		}
	}
	else
	{
		current->amount_hash = block_a.hashables.source;
		current->balance_hash = 0;
	}
}

void xpeed::summation_visitor::change_block (xpeed::change_block const & block_a)
{
	assert (current->type != summation_type::invalid && current != nullptr);
	if (current->type == summation_type::amount)
	{
		sum_set (0);
		current->amount_hash = 0;
	}
	else
	{
		xpeed::block_info block_info;
		if (!store.block_info_get (transaction, block_a.hash (), block_info))
		{
			sum_add (block_info.balance.number ());
			current->balance_hash = 0;
		}
		else
		{
			current->balance_hash = block_a.hashables.previous;
		}
	}
}

xpeed::summation_visitor::frame xpeed::summation_visitor::push (xpeed::summation_visitor::summation_type type_a, xpeed::block_hash const & hash_a)
{
	frames.emplace (type_a, type_a == summation_type::balance ? hash_a : 0, type_a == summation_type::amount ? hash_a : 0);
	return frames.top ();
}

void xpeed::summation_visitor::sum_add (xpeed::uint128_t addend_a)
{
	current->sum += addend_a;
	result = current->sum;
}

void xpeed::summation_visitor::sum_set (xpeed::uint128_t value_a)
{
	current->sum = value_a;
	result = current->sum;
}

xpeed::uint128_t xpeed::summation_visitor::compute_internal (xpeed::summation_visitor::summation_type type_a, xpeed::block_hash const & hash_a)
{
	push (type_a, hash_a);

	/*
	 Invocation loop representing balance and amount computations calling each other.
	 This is usually better done by recursion or something like boost::coroutine2, but
	 segmented stacks are not supported on all platforms so we do it manually to avoid
	 stack overflow (the mutual calls are not tail-recursive so we cannot rely on the
	 compiler optimizing that into a loop, though a future alternative is to do a
	 CPS-style implementation to enforce tail calls.)
	*/
	while (frames.size () > 0)
	{
		current = &frames.top ();
		assert (current->type != summation_type::invalid && current != nullptr);

		if (current->type == summation_type::balance)
		{
			if (current->awaiting_result)
			{
				sum_add (current->incoming_result);
				current->awaiting_result = false;
			}

			while (!current->awaiting_result && (!current->balance_hash.is_zero () || !current->amount_hash.is_zero ()))
			{
				if (!current->amount_hash.is_zero ())
				{
					// Compute amount
					current->awaiting_result = true;
					push (summation_type::amount, current->amount_hash);
					current->amount_hash = 0;
				}
				else
				{
					auto block (store.block_get (transaction, current->balance_hash));
					assert (block != nullptr);
					block->visit (*this);
				}
			}

			epilogue ();
		}
		else if (current->type == summation_type::amount)
		{
			if (current->awaiting_result)
			{
				sum_set (current->sum < current->incoming_result ? current->incoming_result - current->sum : current->sum - current->incoming_result);
				current->awaiting_result = false;
			}

			while (!current->awaiting_result && (!current->amount_hash.is_zero () || !current->balance_hash.is_zero ()))
			{
				if (!current->amount_hash.is_zero ())
				{
					auto block (store.block_get (transaction, current->amount_hash));
					if (block != nullptr)
					{
						block->visit (*this);
					}
					else
					{
						if (current->amount_hash == xpeed::genesis_account)
						{
							sum_set (std::numeric_limits<xpeed::uint128_t>::max ());
							current->amount_hash = 0;
						}
						else
						{
							assert (false);
							sum_set (0);
							current->amount_hash = 0;
						}
					}
				}
				else
				{
					// Compute balance
					current->awaiting_result = true;
					push (summation_type::balance, current->balance_hash);
					current->balance_hash = 0;
				}
			}

			epilogue ();
		}
	}

	return result;
}

void xpeed::summation_visitor::epilogue ()
{
	if (!current->awaiting_result)
	{
		frames.pop ();
		if (frames.size () > 0)
		{
			frames.top ().incoming_result = current->sum;
		}
	}
}

xpeed::uint128_t xpeed::summation_visitor::compute_amount (xpeed::block_hash const & block_hash)
{
	return compute_internal (summation_type::amount, block_hash);
}

xpeed::uint128_t xpeed::summation_visitor::compute_balance (xpeed::block_hash const & block_hash)
{
	return compute_internal (summation_type::balance, block_hash);
}

xpeed::representative_visitor::representative_visitor (xpeed::transaction const & transaction_a, xpeed::block_store & store_a) :
transaction (transaction_a),
store (store_a),
result (0)
{
}

void xpeed::representative_visitor::compute (xpeed::block_hash const & hash_a)
{
	current = hash_a;
	while (result.is_zero ())
	{
		auto block (store.block_get (transaction, current));
		assert (block != nullptr);
		block->visit (*this);
	}
}

void xpeed::representative_visitor::send_block (xpeed::send_block const & block_a)
{
	current = block_a.previous ();
}

void xpeed::representative_visitor::receive_block (xpeed::receive_block const & block_a)
{
	current = block_a.previous ();
}

void xpeed::representative_visitor::open_block (xpeed::open_block const & block_a)
{
	result = block_a.hash ();
}

void xpeed::representative_visitor::change_block (xpeed::change_block const & block_a)
{
	result = block_a.hash ();
}

void xpeed::representative_visitor::state_block (xpeed::state_block const & block_a)
{
	result = block_a.hash ();
}
