#include <xpeed/lib/errors.hpp>
#include <xpeed/node/node.hpp>
#include <xpeed/node/rpc.hpp>

namespace xpd_daemon
{
class daemon
{
public:
	void run (boost::filesystem::path const &, xpeed::node_flags const & flags);
};
class daemon_config
{
public:
	daemon_config ();
	xpeed::error deserialize_json (bool &, xpeed::jsonconfig &);
	xpeed::error serialize_json (xpeed::jsonconfig &);
	/** 
	 * Returns true if an upgrade occurred
	 * @param version The version to upgrade to.
	 * @param config Configuration to upgrade.
	 */
	bool upgrade_json (unsigned version, xpeed::jsonconfig & config);
	bool rpc_enable;
	xpeed::rpc_config rpc;
	xpeed::node_config node;
	bool opencl_enable;
	xpeed::opencl_config opencl;
	int json_version () const
	{
		return 2;
	}
};
}
