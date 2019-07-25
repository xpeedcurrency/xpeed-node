#include <xpeed/lib/utility.hpp>

#include <windows.h>

void xpeed::work_thread_reprioritize ()
{
	auto SUCCESS (SetThreadPriority (GetCurrentThread (), THREAD_MODE_BACKGROUND_BEGIN));
}
