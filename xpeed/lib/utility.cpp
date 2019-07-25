#include <iostream>
#include <xpeed/lib/utility.hpp>

namespace xpeed
{
seq_con_info_composite::seq_con_info_composite (const std::string & name) :
name (name)
{
}

bool seq_con_info_composite::is_composite () const
{
	return true;
}

void seq_con_info_composite::add_component (std::unique_ptr<seq_con_info_component> child)
{
	children.push_back (std::move (child));
}

const std::vector<std::unique_ptr<seq_con_info_component>> & seq_con_info_composite::get_children () const
{
	return children;
}

const std::string & seq_con_info_composite::get_name () const
{
	return name;
}

seq_con_info_leaf::seq_con_info_leaf (const seq_con_info & info) :
info (info)
{
}
bool seq_con_info_leaf::is_composite () const
{
	return false;
}
const seq_con_info & seq_con_info_leaf::get_info () const
{
	return info;
}

namespace thread_role
{
	/*
	 * xpeed::thread_role namespace
	 *
	 * Manage thread role
	 */
	static thread_local xpeed::thread_role::name current_thread_role = xpeed::thread_role::name::unknown;
	xpeed::thread_role::name get ()
	{
		return current_thread_role;
	}

	static std::string get_string (xpeed::thread_role::name role)
	{
		std::string thread_role_name_string;

		switch (role)
		{
			case xpeed::thread_role::name::unknown:
				thread_role_name_string = "<unknown>";
				break;
			case xpeed::thread_role::name::io:
				thread_role_name_string = "I/O";
				break;
			case xpeed::thread_role::name::work:
				thread_role_name_string = "Work pool";
				break;
			case xpeed::thread_role::name::packet_processing:
				thread_role_name_string = "Pkt processing";
				break;
			case xpeed::thread_role::name::alarm:
				thread_role_name_string = "Alarm";
				break;
			case xpeed::thread_role::name::vote_processing:
				thread_role_name_string = "Vote processing";
				break;
			case xpeed::thread_role::name::block_processing:
				thread_role_name_string = "Blck processing";
				break;
			case xpeed::thread_role::name::request_loop:
				thread_role_name_string = "Request loop";
				break;
			case xpeed::thread_role::name::wallet_actions:
				thread_role_name_string = "Wallet actions";
				break;
			case xpeed::thread_role::name::bootstrap_initiator:
				thread_role_name_string = "Bootstrap init";
				break;
			case xpeed::thread_role::name::voting:
				thread_role_name_string = "Voting";
				break;
			case xpeed::thread_role::name::signature_checking:
				thread_role_name_string = "Signature check";
				break;
			case xpeed::thread_role::name::slow_db_upgrade:
				thread_role_name_string = "Slow db upgrade";
				break;
		}

		/*
		 * We want to constrain the thread names to 15
		 * characters, since this is the smallest maximum
		 * length supported by the platforms we support
		 * (specifically, Linux)
		 */
		assert (thread_role_name_string.size () < 16);
		return (thread_role_name_string);
	}

	std::string get_string ()
	{
		return get_string (current_thread_role);
	}

	void set (xpeed::thread_role::name role)
	{
		auto thread_role_name_string (get_string (role));

		xpeed::thread_role::set_os_name (thread_role_name_string);

		xpeed::thread_role::current_thread_role = role;
	}
}
}

void xpeed::thread_attributes::set (boost::thread::attributes & attrs)
{
	auto attrs_l (&attrs);
	attrs_l->set_stack_size (8000000); //8MB
}

/*
 * Backing code for "release_assert", which is itself a macro
 */
void release_assert_internal (bool check, const char * check_expr, const char * file, unsigned int line)
{
	if (check)
	{
		return;
	}

	std::cerr << "Assertion (" << check_expr << ") failed " << file << ":" << line << std::endl;
	abort ();
}
