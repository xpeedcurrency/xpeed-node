#pragma once

#include <boost/optional.hpp>
#include <boost/property_tree/ptree.hpp>
#include <xpeed/lib/errors.hpp>
#include <xpeed/lib/jsonconfig.hpp>
#include <xpeed/node/xorshift.hpp>

#include <map>
#include <mutex>
#include <vector>

#ifdef __APPLE__
#define CL_SILENCE_DEPRECATION
#include <OpenCL/opencl.h>
#else
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#include <CL/cl.h>
#endif

namespace xpeed
{
class logging;
class opencl_platform
{
public:
	cl_platform_id platform;
	std::vector<cl_device_id> devices;
};
class opencl_environment
{
public:
	opencl_environment (bool &);
	void dump (std::ostream & stream);
	std::vector<xpeed::opencl_platform> platforms;
};
union uint256_union;
class work_pool;
class opencl_config
{
public:
	opencl_config ();
	opencl_config (unsigned, unsigned, unsigned);
	xpeed::error serialize_json (xpeed::jsonconfig &) const;
	xpeed::error deserialize_json (xpeed::jsonconfig &);
	unsigned platform;
	unsigned device;
	unsigned threads;
};
class opencl_work
{
public:
	opencl_work (bool &, xpeed::opencl_config const &, xpeed::opencl_environment &, xpeed::logging &);
	~opencl_work ();
	boost::optional<uint64_t> generate_work (xpeed::uint256_union const &);
	static std::unique_ptr<opencl_work> create (bool, xpeed::opencl_config const &, xpeed::logging &);
	xpeed::opencl_config const & config;
	std::mutex mutex;
	cl_context context;
	cl_mem attempt_buffer;
	cl_mem result_buffer;
	cl_mem item_buffer;
	cl_program program;
	cl_kernel kernel;
	cl_command_queue queue;
	xpeed::xorshift1024star rand;
	xpeed::logging & logging;
};
}
