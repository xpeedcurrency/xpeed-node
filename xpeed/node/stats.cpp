#include <xpeed/node/stats.hpp>

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <tuple>

xpeed::error xpeed::stat_config::deserialize_json (xpeed::jsonconfig & json)
{
	auto sampling_l (json.get_optional_child ("sampling"));
	if (sampling_l)
	{
		sampling_l->get<bool> ("enabled", sampling_enabled);
		sampling_l->get<size_t> ("capacity", capacity);
		sampling_l->get<size_t> ("interval", interval);
	}

	auto log_l (json.get_optional_child ("log"));
	if (log_l)
	{
		log_l->get<bool> ("headers", log_headers);
		log_l->get<size_t> ("interval_counters", log_interval_counters);
		log_l->get<size_t> ("interval_samples", log_interval_samples);
		log_l->get<size_t> ("rotation_count", log_rotation_count);
		log_l->get<std::string> ("filename_counters", log_counters_filename);
		log_l->get<std::string> ("filename_samples", log_samples_filename);

		// Don't allow specifying the same file name for counter and samples logs
		if (log_counters_filename == log_samples_filename)
		{
			json.get_error ().set ("The statistics counter and samples config values must be different");
		}
	}

	return json.get_error ();
}

std::string xpeed::stat_log_sink::tm_to_string (tm & tm)
{
	return (boost::format ("%04d.%02d.%02d %02d:%02d:%02d") % (1900 + tm.tm_year) % (tm.tm_mon + 1) % tm.tm_mday % tm.tm_hour % tm.tm_min % tm.tm_sec).str ();
}

/** JSON sink. The resulting JSON object is provided as both a property_tree::ptree (to_object) and a string (to_string) */
class json_writer : public xpeed::stat_log_sink
{
	boost::property_tree::ptree tree;
	boost::property_tree::ptree entries;

public:
	std::ostream & out () override
	{
		return sstr;
	}

	void begin () override
	{
		tree.clear ();
	}

	void write_header (std::string header, std::chrono::system_clock::time_point & walltime) override
	{
		std::time_t now = std::chrono::system_clock::to_time_t (walltime);
		tm tm = *localtime (&now);
		tree.put ("type", header);
		tree.put ("created", tm_to_string (tm));
	}

	void write_entry (tm & tm, std::string type, std::string detail, std::string dir, uint64_t value) override
	{
		boost::property_tree::ptree entry;
		entry.put ("time", boost::format ("%02d:%02d:%02d") % tm.tm_hour % tm.tm_min % tm.tm_sec);
		entry.put ("type", type);
		entry.put ("detail", detail);
		entry.put ("dir", dir);
		entry.put ("value", value);
		entries.push_back (std::make_pair ("", entry));
	}

	void finalize () override
	{
		tree.add_child ("entries", entries);
	}

	void * to_object () override
	{
		return &tree;
	}

	std::string to_string () override
	{
		boost::property_tree::write_json (sstr, tree);
		return sstr.str ();
	}

private:
	std::ostringstream sstr;
};

/** File sink with rotation support */
class file_writer : public xpeed::stat_log_sink
{
public:
	std::ofstream log;
	std::string filename;

	file_writer (std::string filename) :
	filename (filename)
	{
		log.open (filename.c_str (), std::ofstream::out);
	}
	virtual ~file_writer ()
	{
		log.close ();
	}
	std::ostream & out () override
	{
		return log;
	}

	void write_header (std::string header, std::chrono::system_clock::time_point & walltime) override
	{
		std::time_t now = std::chrono::system_clock::to_time_t (walltime);
		tm tm = *localtime (&now);
		log << header << "," << boost::format ("%04d.%02d.%02d %02d:%02d:%02d") % (1900 + tm.tm_year) % (tm.tm_mon + 1) % tm.tm_mday % tm.tm_hour % tm.tm_min % tm.tm_sec << std::endl;
	}

	void write_entry (tm & tm, std::string type, std::string detail, std::string dir, uint64_t value) override
	{
		log << boost::format ("%02d:%02d:%02d") % tm.tm_hour % tm.tm_min % tm.tm_sec << "," << type << "," << detail << "," << dir << "," << value << std::endl;
	}

	void rotate () override
	{
		log.close ();
		log.open (filename.c_str (), std::ofstream::out);
		log_entries = 0;
	}
};

xpeed::stat::stat (xpeed::stat_config config) :
config (config)
{
}

std::shared_ptr<xpeed::stat_entry> xpeed::stat::get_entry (uint32_t key)
{
	return get_entry (key, config.interval, config.capacity);
}

std::shared_ptr<xpeed::stat_entry> xpeed::stat::get_entry (uint32_t key, size_t interval, size_t capacity)
{
	std::unique_lock<std::mutex> lock (stat_mutex);
	return get_entry_impl (key, interval, capacity);
}

std::shared_ptr<xpeed::stat_entry> xpeed::stat::get_entry_impl (uint32_t key, size_t interval, size_t capacity)
{
	std::shared_ptr<xpeed::stat_entry> res;
	auto entry = entries.find (key);
	if (entry == entries.end ())
	{
		res = entries.insert (std::make_pair (key, std::make_shared<xpeed::stat_entry> (capacity, interval))).first->second;
	}
	else
	{
		res = entry->second;
	}

	return res;
}

std::unique_ptr<xpeed::stat_log_sink> xpeed::stat::log_sink_json ()
{
	return std::make_unique<json_writer> ();
}

std::unique_ptr<xpeed::stat_log_sink> log_sink_file (std::string filename)
{
	return std::make_unique<file_writer> (filename);
}

void xpeed::stat::log_counters (stat_log_sink & sink)
{
	std::unique_lock<std::mutex> lock (stat_mutex);
	log_counters_impl (sink);
}

void xpeed::stat::log_counters_impl (stat_log_sink & sink)
{
	sink.begin ();
	if (sink.entries () >= config.log_rotation_count)
	{
		sink.rotate ();
	}

	if (config.log_headers)
	{
		auto walltime (std::chrono::system_clock::now ());
		sink.write_header ("counters", walltime);
	}

	for (auto & it : entries)
	{
		std::time_t time = std::chrono::system_clock::to_time_t (it.second->counter.get_timestamp ());
		tm local_tm = *localtime (&time);

		auto key = it.first;
		std::string type = type_to_string (key);
		std::string detail = detail_to_string (key);
		std::string dir = dir_to_string (key);
		sink.write_entry (local_tm, type, detail, dir, it.second->counter.get_value ());
	}
	sink.entries ()++;
	sink.finalize ();
}

void xpeed::stat::log_samples (stat_log_sink & sink)
{
	std::unique_lock<std::mutex> lock (stat_mutex);
	log_samples_impl (sink);
}

void xpeed::stat::log_samples_impl (stat_log_sink & sink)
{
	sink.begin ();
	if (sink.entries () >= config.log_rotation_count)
	{
		sink.rotate ();
	}

	if (config.log_headers)
	{
		auto walltime (std::chrono::system_clock::now ());
		sink.write_header ("samples", walltime);
	}

	for (auto & it : entries)
	{
		auto key = it.first;
		std::string type = type_to_string (key);
		std::string detail = detail_to_string (key);
		std::string dir = dir_to_string (key);

		for (auto & datapoint : it.second->samples)
		{
			std::time_t time = std::chrono::system_clock::to_time_t (datapoint.get_timestamp ());
			tm local_tm = *localtime (&time);
			sink.write_entry (local_tm, type, detail, dir, datapoint.get_value ());
		}
	}
	sink.entries ()++;
	sink.finalize ();
}

void xpeed::stat::update (uint32_t key_a, uint64_t value)
{
	static file_writer log_count (config.log_counters_filename);
	static file_writer log_sample (config.log_samples_filename);

	auto now (std::chrono::steady_clock::now ());

	std::unique_lock<std::mutex> lock (stat_mutex);
	auto entry (get_entry_impl (key_a, config.interval, config.capacity));

	// Counters
	auto old (entry->counter.get_value ());
	entry->counter.add (value);
	entry->count_observers.notify (old, entry->counter.get_value ());

	std::chrono::duration<double, std::milli> duration = now - log_last_count_writeout;
	if (config.log_interval_counters > 0 && duration.count () > config.log_interval_counters)
	{
		log_counters_impl (log_count);
		log_last_count_writeout = now;
	}

	// Samples
	if (config.sampling_enabled && entry->sample_interval > 0)
	{
		entry->sample_current.add (value, false);

		std::chrono::duration<double, std::milli> duration = now - entry->sample_start_time;
		if (duration.count () > entry->sample_interval)
		{
			entry->sample_start_time = now;

			// Make a snapshot of samples for thread safety and to get a stable container
			entry->sample_current.set_timestamp (std::chrono::system_clock::now ());
			entry->samples.push_back (entry->sample_current);
			entry->sample_current.set_value (0);

			if (entry->sample_observers.observers.size () > 0)
			{
				auto snapshot (entry->samples);
				entry->sample_observers.notify (snapshot);
			}

			// Log sink
			duration = now - log_last_sample_writeout;
			if (config.log_interval_samples > 0 && duration.count () > config.log_interval_samples)
			{
				log_samples_impl (log_sample);
				log_last_sample_writeout = now;
			}
		}
	}
}

std::chrono::seconds xpeed::stat::last_reset ()
{
	std::unique_lock<std::mutex> lock (stat_mutex);
	auto now (std::chrono::steady_clock::now ());
	return std::chrono::duration_cast<std::chrono::seconds> (now - timestamp);
}

void xpeed::stat::clear ()
{
	std::unique_lock<std::mutex> lock (stat_mutex);
	entries.clear ();
	timestamp = std::chrono::steady_clock::now ();
}

std::string xpeed::stat::type_to_string (uint32_t key)
{
	auto type = static_cast<stat::type> (key >> 16 & 0x000000ff);
	std::string res;
	switch (type)
	{
		case xpeed::stat::type::ipc:
			res = "ipc";
			break;
		case xpeed::stat::type::block:
			res = "block";
			break;
		case xpeed::stat::type::bootstrap:
			res = "bootstrap";
			break;
		case xpeed::stat::type::error:
			res = "error";
			break;
		case xpeed::stat::type::http_callback:
			res = "http_callback";
			break;
		case xpeed::stat::type::ledger:
			res = "ledger";
			break;
		case xpeed::stat::type::udp:
			res = "udp";
			break;
		case xpeed::stat::type::peering:
			res = "peering";
			break;
		case xpeed::stat::type::rollback:
			res = "rollback";
			break;
		case xpeed::stat::type::traffic:
			res = "traffic";
			break;
		case xpeed::stat::type::traffic_bootstrap:
			res = "traffic_bootstrap";
			break;
		case xpeed::stat::type::vote:
			res = "vote";
			break;
		case xpeed::stat::type::message:
			res = "message";
			break;
	}
	return res;
}

std::string xpeed::stat::detail_to_string (uint32_t key)
{
	auto detail = static_cast<stat::detail> (key >> 8 & 0x000000ff);
	std::string res;
	switch (detail)
	{
		case xpeed::stat::detail::all:
			res = "all";
			break;
		case xpeed::stat::detail::bad_sender:
			res = "bad_sender";
			break;
		case xpeed::stat::detail::bulk_pull:
			res = "bulk_pull";
			break;
		case xpeed::stat::detail::bulk_pull_account:
			res = "bulk_pull_account";
			break;
		case xpeed::stat::detail::bulk_push:
			res = "bulk_push";
			break;
		case xpeed::stat::detail::change:
			res = "change";
			break;
		case xpeed::stat::detail::confirm_ack:
			res = "confirm_ack";
			break;
		case xpeed::stat::detail::node_id_handshake:
			res = "node_id_handshake";
			break;
		case xpeed::stat::detail::confirm_req:
			res = "confirm_req";
			break;
		case xpeed::stat::detail::fork:
			res = "fork";
			break;
		case xpeed::stat::detail::frontier_req:
			res = "frontier_req";
			break;
		case xpeed::stat::detail::handshake:
			res = "handshake";
			break;
		case xpeed::stat::detail::http_callback:
			res = "http_callback";
			break;
		case xpeed::stat::detail::initiate:
			res = "initiate";
			break;
		case xpeed::stat::detail::initiate_lazy:
			res = "initiate_lazy";
			break;
		case xpeed::stat::detail::initiate_wallet_lazy:
			res = "initiate_wallet_lazy";
			break;
		case xpeed::stat::detail::insufficient_work:
			res = "insufficient_work";
			break;
		case xpeed::stat::detail::invocations:
			res = "invocations";
			break;
		case xpeed::stat::detail::keepalive:
			res = "keepalive";
			break;
		case xpeed::stat::detail::open:
			res = "open";
			break;
		case xpeed::stat::detail::publish:
			res = "publish";
			break;
		case xpeed::stat::detail::receive:
			res = "receive";
			break;
		case xpeed::stat::detail::republish_vote:
			res = "republish_vote";
			break;
		case xpeed::stat::detail::send:
			res = "send";
			break;
		case xpeed::stat::detail::state_block:
			res = "state_block";
			break;
		case xpeed::stat::detail::epoch_block:
			res = "epoch_block";
			break;
		case xpeed::stat::detail::vote_valid:
			res = "vote_valid";
			break;
		case xpeed::stat::detail::vote_replay:
			res = "vote_replay";
			break;
		case xpeed::stat::detail::vote_invalid:
			res = "vote_invalid";
			break;
		case xpeed::stat::detail::vote_overflow:
			res = "vote_overflow";
			break;
		case xpeed::stat::detail::blocking:
			res = "blocking";
			break;
		case xpeed::stat::detail::overflow:
			res = "overflow";
			break;
		case xpeed::stat::detail::unreachable_host:
			res = "unreachable_host";
			break;
		case xpeed::stat::detail::invalid_magic:
			res = "invalid_magic";
			break;
		case xpeed::stat::detail::invalid_network:
			res = "invalid_network";
			break;
		case xpeed::stat::detail::invalid_header:
			res = "invalid_header";
			break;
		case xpeed::stat::detail::invalid_message_type:
			res = "invalid_message_type";
			break;
		case xpeed::stat::detail::invalid_keepalive_message:
			res = "invalid_keepalive_message";
			break;
		case xpeed::stat::detail::invalid_publish_message:
			res = "invalid_publish_message";
			break;
		case xpeed::stat::detail::invalid_confirm_req_message:
			res = "invalid_confirm_req_message";
			break;
		case xpeed::stat::detail::invalid_confirm_ack_message:
			res = "invalid_confirm_ack_message";
			break;
		case xpeed::stat::detail::invalid_node_id_handshake_message:
			res = "invalid_node_id_handshake_message";
			break;
		case xpeed::stat::detail::outdated_version:
			res = "outdated_version";
			break;
	}
	return res;
}

std::string xpeed::stat::dir_to_string (uint32_t key)
{
	auto dir = static_cast<stat::dir> (key & 0x000000ff);
	std::string res;
	switch (dir)
	{
		case xpeed::stat::dir::in:
			res = "in";
			break;
		case xpeed::stat::dir::out:
			res = "out";
			break;
	}
	return res;
}
