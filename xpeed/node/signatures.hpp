#pragma once

#include <atomic>
#include <future>
#include <mutex>
#include <xpeed/lib/utility.hpp>

#include <boost/asio.hpp>

namespace xpeed
{
class signature_check_set final
{
public:
	signature_check_set (size_t size, unsigned char const ** messages, size_t * message_lengths, unsigned char const ** pub_keys, unsigned char const ** signatures, int * verifications) :
	size (size), messages (messages), message_lengths (message_lengths), pub_keys (pub_keys), signatures (signatures), verifications (verifications)
	{
	}

	size_t size;
	unsigned char const ** messages;
	size_t * message_lengths;
	unsigned char const ** pub_keys;
	unsigned char const ** signatures;
	int * verifications;
};

/** Multi-threaded signature checker */
class signature_checker final
{
public:
	signature_checker (unsigned num_threads);
	~signature_checker ();
	void verify (signature_check_set &);
	void stop ();
	void flush ();

private:
	struct Task final
	{
		Task (xpeed::signature_check_set & check, int pending) :
		check (check), pending (pending)
		{
		}
		~Task ()
		{
			release_assert (pending == 0);
		}
		xpeed::signature_check_set & check;
		std::atomic<int> pending;
	};

	bool verify_batch (const xpeed::signature_check_set & check_a, size_t index, size_t size);
	void verify_async (xpeed::signature_check_set & check_a, size_t num_batches, std::promise<void> & promise);
	void set_thread_names (unsigned num_threads);
	boost::asio::thread_pool thread_pool;
	std::atomic<int> tasks_remaining{ 0 };
	/** minimum signature_check_set size eligible to be multithreaded */
	static constexpr size_t multithreaded_cutoff = 513;
	static constexpr size_t batch_size = 256;
	const bool single_threaded;
	unsigned num_threads;
	std::mutex mutex;
	bool stopped{ false };
};
}
