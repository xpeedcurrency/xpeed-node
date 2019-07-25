#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cstdlib>
#include <xpeed/node/common.hpp>
#include <xpeed/node/testing.hpp>

std::string xpeed::error_system_messages::message (int ev) const
{
	switch (static_cast<xpeed::error_system> (ev))
	{
		case xpeed::error_system::generic:
			return "Unknown error";
		case xpeed::error_system::deadline_expired:
			return "Deadline expired";
	}

	return "Invalid error code";
}

xpeed::system::system (uint16_t port_a, uint16_t count_a) :
alarm (io_ctx),
work (1, nullptr)
{
	auto scale_str = std::getenv ("DEADLINE_SCALE_FACTOR");
	if (scale_str)
	{
		deadline_scaling_factor = std::stod (scale_str);
	}
	logging.init (xpeed::unique_path ());
	nodes.reserve (count_a);
	for (uint16_t i (0); i < count_a; ++i)
	{
		xpeed::node_init init;
		xpeed::node_config config (port_a + i, logging);
		auto node (std::make_shared<xpeed::node> (init, io_ctx, xpeed::unique_path (), alarm, config, work));
		assert (!init.error ());
		node->start ();
		xpeed::uint256_union wallet;
		xpeed::random_pool::generate_block (wallet.bytes.data (), wallet.bytes.size ());
		node->wallets.create (wallet);
		nodes.push_back (node);
	}
	for (auto i (nodes.begin ()), j (nodes.begin () + 1), n (nodes.end ()); j != n; ++i, ++j)
	{
		auto starting1 ((*i)->peers.size ());
		decltype (starting1) new1;
		auto starting2 ((*j)->peers.size ());
		decltype (starting2) new2;
		(*j)->network.send_keepalive ((*i)->network.endpoint ());
		do
		{
			poll ();
			new1 = (*i)->peers.size ();
			new2 = (*j)->peers.size ();
		} while (new1 == starting1 || new2 == starting2);
	}
	auto iterations1 (0);
	while (std::any_of (nodes.begin (), nodes.end (), [](std::shared_ptr<xpeed::node> const & node_a) { return node_a->bootstrap_initiator.in_progress (); }))
	{
		poll ();
		++iterations1;
		assert (iterations1 < 10000);
	}
}

xpeed::system::~system ()
{
	for (auto & i : nodes)
	{
		i->stop ();
	}

	// Clean up tmp directories created by the tests. Since it's sometimes useful to
	// see log files after test failures, an environment variable is supported to
	// retain the files.
	if (std::getenv ("TEST_KEEP_TMPDIRS") == nullptr)
	{
		xpeed::remove_temporary_directories ();
	}
}

std::shared_ptr<xpeed::wallet> xpeed::system::wallet (size_t index_a)
{
	assert (nodes.size () > index_a);
	auto size (nodes[index_a]->wallets.items.size ());
	assert (size == 1);
	return nodes[index_a]->wallets.items.begin ()->second;
}

xpeed::account xpeed::system::account (xpeed::transaction const & transaction_a, size_t index_a)
{
	auto wallet_l (wallet (index_a));
	auto keys (wallet_l->store.begin (transaction_a));
	assert (keys != wallet_l->store.end ());
	auto result (keys->first);
	assert (++keys == wallet_l->store.end ());
	return xpeed::account (result);
}

void xpeed::system::deadline_set (std::chrono::duration<double, std::nano> const & delta_a)
{
	deadline = std::chrono::steady_clock::now () + delta_a * deadline_scaling_factor;
}

std::error_code xpeed::system::poll (std::chrono::nanoseconds const & wait_time)
{
	std::error_code ec;
	io_ctx.run_one_for (wait_time);

	if (std::chrono::steady_clock::now () > deadline)
	{
		ec = xpeed::error_system::deadline_expired;
		stop ();
	}
	return ec;
}

namespace
{
class traffic_generator : public std::enable_shared_from_this<traffic_generator>
{
public:
	traffic_generator (uint32_t count_a, uint32_t wait_a, std::shared_ptr<xpeed::node> node_a, xpeed::system & system_a) :
	count (count_a),
	wait (wait_a),
	node (node_a),
	system (system_a)
	{
	}
	void run ()
	{
		auto count_l (count - 1);
		count = count_l - 1;
		system.generate_activity (*node, accounts);
		if (count_l > 0)
		{
			auto this_l (shared_from_this ());
			node->alarm.add (std::chrono::steady_clock::now () + std::chrono::milliseconds (wait), [this_l]() { this_l->run (); });
		}
	}
	std::vector<xpeed::account> accounts;
	uint32_t count;
	uint32_t wait;
	std::shared_ptr<xpeed::node> node;
	xpeed::system & system;
};
}

void xpeed::system::generate_usage_traffic (uint32_t count_a, uint32_t wait_a)
{
	for (size_t i (0), n (nodes.size ()); i != n; ++i)
	{
		generate_usage_traffic (count_a, wait_a, i);
	}
}

void xpeed::system::generate_usage_traffic (uint32_t count_a, uint32_t wait_a, size_t index_a)
{
	assert (nodes.size () > index_a);
	assert (count_a > 0);
	auto generate (std::make_shared<traffic_generator> (count_a, wait_a, nodes[index_a], *this));
	generate->run ();
}

void xpeed::system::generate_rollback (xpeed::node & node_a, std::vector<xpeed::account> & accounts_a)
{
	auto transaction (node_a.store.tx_begin_write ());
	assert (std::numeric_limits<CryptoPP::word32>::max () > accounts_a.size ());
	auto index (random_pool::generate_word32 (0, static_cast<CryptoPP::word32> (accounts_a.size () - 1)));
	auto account (accounts_a[index]);
	xpeed::account_info info;
	auto error (node_a.store.account_get (transaction, account, info));
	if (!error)
	{
		auto hash (info.open_block);
		xpeed::genesis genesis;
		if (hash != genesis.hash ())
		{
			accounts_a[index] = accounts_a[accounts_a.size () - 1];
			accounts_a.pop_back ();
			node_a.ledger.rollback (transaction, hash);
		}
	}
}

void xpeed::system::generate_receive (xpeed::node & node_a)
{
	std::shared_ptr<xpeed::block> send_block;
	{
		auto transaction (node_a.store.tx_begin_read ());
		xpeed::uint256_union random_block;
		random_pool::generate_block (random_block.bytes.data (), sizeof (random_block.bytes));
		auto i (node_a.store.pending_begin (transaction, xpeed::pending_key (random_block, 0)));
		if (i != node_a.store.pending_end ())
		{
			xpeed::pending_key send_hash (i->first);
			send_block = node_a.store.block_get (transaction, send_hash.hash);
		}
	}
	if (send_block != nullptr)
	{
		auto receive_error (wallet (0)->receive_sync (send_block, xpeed::genesis_account, std::numeric_limits<xpeed::uint128_t>::max ()));
		(void)receive_error;
	}
}

void xpeed::system::generate_activity (xpeed::node & node_a, std::vector<xpeed::account> & accounts_a)
{
	auto what (random_pool::generate_byte ());
	if (what < 0x1)
	{
		generate_rollback (node_a, accounts_a);
	}
	else if (what < 0x10)
	{
		generate_change_known (node_a, accounts_a);
	}
	else if (what < 0x20)
	{
		generate_change_unknown (node_a, accounts_a);
	}
	else if (what < 0x70)
	{
		generate_receive (node_a);
	}
	else if (what < 0xc0)
	{
		generate_send_existing (node_a, accounts_a);
	}
	else
	{
		generate_send_new (node_a, accounts_a);
	}
}

xpeed::account xpeed::system::get_random_account (std::vector<xpeed::account> & accounts_a)
{
	assert (std::numeric_limits<CryptoPP::word32>::max () > accounts_a.size ());
	auto index (random_pool::generate_word32 (0, static_cast<CryptoPP::word32> (accounts_a.size () - 1)));
	auto result (accounts_a[index]);
	return result;
}

xpeed::uint128_t xpeed::system::get_random_amount (xpeed::transaction const & transaction_a, xpeed::node & node_a, xpeed::account const & account_a)
{
	xpeed::uint128_t balance (node_a.ledger.account_balance (transaction_a, account_a));
	std::string balance_text (balance.convert_to<std::string> ());
	xpeed::uint128_union random_amount;
	xpeed::random_pool::generate_block (random_amount.bytes.data (), sizeof (random_amount.bytes));
	auto result (((xpeed::uint256_t{ random_amount.number () } * balance) / xpeed::uint256_t{ std::numeric_limits<xpeed::uint128_t>::max () }).convert_to<xpeed::uint128_t> ());
	std::string text (result.convert_to<std::string> ());
	return result;
}

void xpeed::system::generate_send_existing (xpeed::node & node_a, std::vector<xpeed::account> & accounts_a)
{
	xpeed::uint128_t amount;
	xpeed::account destination;
	xpeed::account source;
	{
		xpeed::account account;
		random_pool::generate_block (account.bytes.data (), sizeof (account.bytes));
		auto transaction (node_a.store.tx_begin_read ());
		xpeed::store_iterator<xpeed::account, xpeed::account_info> entry (node_a.store.latest_begin (transaction, account));
		if (entry == node_a.store.latest_end ())
		{
			entry = node_a.store.latest_begin (transaction);
		}
		assert (entry != node_a.store.latest_end ());
		destination = xpeed::account (entry->first);
		source = get_random_account (accounts_a);
		amount = get_random_amount (transaction, node_a, source);
	}
	if (!amount.is_zero ())
	{
		auto hash (wallet (0)->send_sync (source, destination, amount));
		assert (!hash.is_zero ());
	}
}

void xpeed::system::generate_change_known (xpeed::node & node_a, std::vector<xpeed::account> & accounts_a)
{
	xpeed::account source (get_random_account (accounts_a));
	if (!node_a.latest (source).is_zero ())
	{
		xpeed::account destination (get_random_account (accounts_a));
		auto change_error (wallet (0)->change_sync (source, destination));
		assert (!change_error);
	}
}

void xpeed::system::generate_change_unknown (xpeed::node & node_a, std::vector<xpeed::account> & accounts_a)
{
	xpeed::account source (get_random_account (accounts_a));
	if (!node_a.latest (source).is_zero ())
	{
		xpeed::keypair key;
		xpeed::account destination (key.pub);
		auto change_error (wallet (0)->change_sync (source, destination));
		assert (!change_error);
	}
}

void xpeed::system::generate_send_new (xpeed::node & node_a, std::vector<xpeed::account> & accounts_a)
{
	assert (node_a.wallets.items.size () == 1);
	xpeed::uint128_t amount;
	xpeed::account source;
	{
		auto transaction (node_a.store.tx_begin_read ());
		source = get_random_account (accounts_a);
		amount = get_random_amount (transaction, node_a, source);
	}
	if (!amount.is_zero ())
	{
		auto pub (node_a.wallets.items.begin ()->second->deterministic_insert ());
		accounts_a.push_back (pub);
		auto hash (wallet (0)->send_sync (source, pub, amount));
		assert (!hash.is_zero ());
	}
}

void xpeed::system::generate_mass_activity (uint32_t count_a, xpeed::node & node_a)
{
	std::vector<xpeed::account> accounts;
	wallet (0)->insert_adhoc (xpeed::test_genesis_key.prv);
	accounts.push_back (xpeed::test_genesis_key.pub);
	auto previous (std::chrono::steady_clock::now ());
	for (uint32_t i (0); i < count_a; ++i)
	{
		if ((i & 0xff) == 0)
		{
			auto now (std::chrono::steady_clock::now ());
			auto us (std::chrono::duration_cast<std::chrono::microseconds> (now - previous).count ());
			uint64_t count (0);
			uint64_t state (0);
			{
				auto transaction (node_a.store.tx_begin_read ());
				auto block_counts (node_a.store.block_count (transaction));
				count = block_counts.sum ();
				state = block_counts.state_v0 + block_counts.state_v1;
			}
			std::cerr << boost::str (boost::format ("Mass activity iteration %1% us %2% us/t %3% state: %4% old: %5%\n") % i % us % (us / 256) % state % (count - state));
			previous = now;
		}
		generate_activity (node_a, accounts);
	}
}

void xpeed::system::stop ()
{
	for (auto i : nodes)
	{
		i->stop ();
	}
	work.stop ();
}

xpeed::landing_store::landing_store ()
{
}

xpeed::landing_store::landing_store (xpeed::account const & source_a, xpeed::account const & destination_a, uint64_t start_a, uint64_t last_a) :
source (source_a),
destination (destination_a),
start (start_a),
last (last_a)
{
}

xpeed::landing_store::landing_store (bool & error_a, std::istream & stream_a)
{
	error_a = deserialize (stream_a);
}

bool xpeed::landing_store::deserialize (std::istream & stream_a)
{
	bool result;
	try
	{
		boost::property_tree::ptree tree;
		boost::property_tree::read_json (stream_a, tree);
		auto source_l (tree.get<std::string> ("source"));
		auto destination_l (tree.get<std::string> ("destination"));
		auto start_l (tree.get<std::string> ("start"));
		auto last_l (tree.get<std::string> ("last"));
		result = source.decode_account (source_l);
		if (!result)
		{
			result = destination.decode_account (destination_l);
			if (!result)
			{
				start = std::stoull (start_l);
				last = std::stoull (last_l);
			}
		}
	}
	catch (std::logic_error const &)
	{
		result = true;
	}
	catch (std::runtime_error const &)
	{
		result = true;
	}
	return result;
}

void xpeed::landing_store::serialize (std::ostream & stream_a) const
{
	boost::property_tree::ptree tree;
	tree.put ("source", source.to_account ());
	tree.put ("destination", destination.to_account ());
	tree.put ("start", std::to_string (start));
	tree.put ("last", std::to_string (last));
	boost::property_tree::write_json (stream_a, tree);
}

bool xpeed::landing_store::operator== (xpeed::landing_store const & other_a) const
{
	return source == other_a.source && destination == other_a.destination && start == other_a.start && last == other_a.last;
}

xpeed::landing::landing (xpeed::node & node_a, std::shared_ptr<xpeed::wallet> wallet_a, xpeed::landing_store & store_a, boost::filesystem::path const & path_a) :
path (path_a),
store (store_a),
wallet (wallet_a),
node (node_a)
{
}

void xpeed::landing::write_store ()
{
	std::ofstream store_file;
	store_file.open (path.string ());
	if (!store_file.fail ())
	{
		store.serialize (store_file);
	}
	else
	{
		std::stringstream str;
		store.serialize (str);
		BOOST_LOG (node.log) << boost::str (boost::format ("Error writing store file %1%") % str.str ());
	}
}

xpeed::uint128_t xpeed::landing::distribution_amount (uint64_t interval)
{
	// Halving period ~= Exponent of 2 in seconds approximately 1 year = 2^25 = 33554432
	// Interval = Exponent of 2 in seconds approximately 1 minute = 2^10 = 64
	uint64_t intervals_per_period (1 << (25 - interval_exponent));
	xpeed::uint128_t result;
	if (interval < intervals_per_period * 1)
	{
		// Total supply / 2^halving period / intervals per period
		// 2^128 / 2^1 / (2^25 / 2^10)
		result = xpeed::uint128_t (1) << (127 - (25 - interval_exponent)); // 50%
	}
	else if (interval < intervals_per_period * 2)
	{
		result = xpeed::uint128_t (1) << (126 - (25 - interval_exponent)); // 25%
	}
	else if (interval < intervals_per_period * 3)
	{
		result = xpeed::uint128_t (1) << (125 - (25 - interval_exponent)); // 13%
	}
	else if (interval < intervals_per_period * 4)
	{
		result = xpeed::uint128_t (1) << (124 - (25 - interval_exponent)); // 6.3%
	}
	else if (interval < intervals_per_period * 5)
	{
		result = xpeed::uint128_t (1) << (123 - (25 - interval_exponent)); // 3.1%
	}
	else if (interval < intervals_per_period * 6)
	{
		result = xpeed::uint128_t (1) << (122 - (25 - interval_exponent)); // 1.6%
	}
	else if (interval < intervals_per_period * 7)
	{
		result = xpeed::uint128_t (1) << (121 - (25 - interval_exponent)); // 0.8%
	}
	else if (interval < intervals_per_period * 8)
	{
		result = xpeed::uint128_t (1) << (121 - (25 - interval_exponent)); // 0.8*
	}
	else
	{
		result = 0;
	}
	return result;
}

void xpeed::landing::distribute_one ()
{
	auto now (xpeed::seconds_since_epoch ());
	xpeed::block_hash last (1);
	while (!last.is_zero () && store.last + distribution_interval.count () < now)
	{
		auto amount (distribution_amount ((store.last - store.start) >> interval_exponent));
		last = wallet->send_sync (store.source, store.destination, amount);
		if (!last.is_zero ())
		{
			BOOST_LOG (node.log) << boost::str (boost::format ("Successfully distributed %1% in block %2%") % amount % last.to_string ());
			store.last += distribution_interval.count ();
			write_store ();
		}
		else
		{
			BOOST_LOG (node.log) << "Error while sending distribution";
		}
	}
}

void xpeed::landing::distribute_ongoing ()
{
	distribute_one ();
	BOOST_LOG (node.log) << "Waiting for next distribution cycle";
	node.alarm.add (std::chrono::steady_clock::now () + sleep_seconds, [this]() { distribute_ongoing (); });
}

std::chrono::seconds constexpr xpeed::landing::distribution_interval;
std::chrono::seconds constexpr xpeed::landing::sleep_seconds;
