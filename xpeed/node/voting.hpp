#pragma once

#include <xpeed/lib/numbers.hpp>
#include <xpeed/lib/utility.hpp>
#include <xpeed/secure/common.hpp>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/thread.hpp>

#include <condition_variable>
#include <deque>
#include <mutex>

namespace xpeed
{
class node;
class vote_generator
{
public:
	vote_generator (xpeed::node &, std::chrono::milliseconds);
	void add (xpeed::block_hash const &);
	void stop ();

private:
	void run ();
	void send (std::unique_lock<std::mutex> &);
	xpeed::node & node;
	std::mutex mutex;
	std::condition_variable condition;
	std::deque<xpeed::block_hash> hashes;
	std::chrono::milliseconds wait;
	bool stopped;
	bool started;
	boost::thread thread;

	friend std::unique_ptr<seq_con_info_component> collect_seq_con_info (vote_generator & vote_generator, const std::string & name);
};

std::unique_ptr<seq_con_info_component> collect_seq_con_info (vote_generator & vote_generator, const std::string & name);
class cached_votes
{
public:
	std::chrono::steady_clock::time_point time;
	xpeed::block_hash hash;
	std::vector<std::shared_ptr<xpeed::vote>> votes;
};
class votes_cache
{
public:
	void add (std::shared_ptr<xpeed::vote> const &);
	std::vector<std::shared_ptr<xpeed::vote>> find (xpeed::block_hash const &);
	void remove (xpeed::block_hash const &);

private:
	std::mutex cache_mutex;
	boost::multi_index_container<
	xpeed::cached_votes,
	boost::multi_index::indexed_by<
	boost::multi_index::ordered_non_unique<boost::multi_index::member<xpeed::cached_votes, std::chrono::steady_clock::time_point, &xpeed::cached_votes::time>>,
	boost::multi_index::hashed_unique<boost::multi_index::member<xpeed::cached_votes, xpeed::block_hash, &xpeed::cached_votes::hash>>>>
	cache;
	static size_t constexpr max_cache = (xpeed::is_test_network) ? 2 : 1000;

	friend std::unique_ptr<seq_con_info_component> collect_seq_con_info (votes_cache & votes_cache, const std::string & name);
};

std::unique_ptr<seq_con_info_component> collect_seq_con_info (votes_cache & votes_cache, const std::string & name);
}
