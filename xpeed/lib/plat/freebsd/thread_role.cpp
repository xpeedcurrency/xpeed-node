#include <xpeed/lib/utility.hpp>
#include <pthread.h>
#include <pthread_np.h>

void xpeed::thread_role::set_os_name (std::string thread_name)
{
	pthread_set_name_np (pthread_self (), thread_name.c_str ());
}
