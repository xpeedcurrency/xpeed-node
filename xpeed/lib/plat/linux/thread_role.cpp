#include <xpeed/lib/utility.hpp>
#include <pthread.h>

void xpeed::thread_role::set_os_name (std::string thread_name)
{
	pthread_setname_np (pthread_self (), thread_name.c_str ());
}
