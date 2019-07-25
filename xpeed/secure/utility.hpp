#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <type_traits>

#include <boost/filesystem.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <crypto/cryptopp/osrng.h>

#include <xpeed/lib/config.hpp>
#include <xpeed/lib/errors.hpp>
#include <xpeed/lib/interface.h>
#include <xpeed/lib/numbers.hpp>

namespace xpeed
{
using bufferstream = boost::iostreams::stream_buffer<boost::iostreams::basic_array_source<uint8_t>>;
using vectorstream = boost::iostreams::stream_buffer<boost::iostreams::back_insert_device<std::vector<uint8_t>>>;
// OS-specific way of finding a path to a home directory.
boost::filesystem::path working_path (bool = false);
// Function to migrate working_path() from above from RaiBlocks to Xpeed
bool migrate_working_path (std::string &);
// Get a unique path within the home directory, used for testing.
// Any directories created at this location will be removed when a test finishes.
boost::filesystem::path unique_path ();
// Remove all unique tmp directories created by the process. The list of unique paths are returned.
std::vector<boost::filesystem::path> remove_temporary_directories ();
}
