#include <boost/filesystem.hpp>

#include <xpeed/lib/utility.hpp>

#include <sys/stat.h>
#include <sys/types.h>

void xpeed::set_umask ()
{
	umask (077);
}

void xpeed::set_secure_perm_directory (boost::filesystem::path const & path)
{
	boost::filesystem::permissions (path, boost::filesystem::owner_all);
}

void xpeed::set_secure_perm_directory (boost::filesystem::path const & path, boost::system::error_code & ec)
{
	boost::filesystem::permissions (path, boost::filesystem::owner_all, ec);
}

void xpeed::set_secure_perm_file (boost::filesystem::path const & path)
{
	boost::filesystem::permissions (path, boost::filesystem::perms::owner_read | boost::filesystem::perms::owner_write);
}

void xpeed::set_secure_perm_file (boost::filesystem::path const & path, boost::system::error_code & ec)
{
	boost::filesystem::permissions (path, boost::filesystem::perms::owner_read | boost::filesystem::perms::owner_write, ec);
}
