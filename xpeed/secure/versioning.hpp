#pragma once

#include <xpeed/lib/blocks.hpp>
#include <xpeed/node/lmdb.hpp>
#include <xpeed/secure/utility.hpp>

namespace xpeed
{
class account_info_v1
{
public:
	account_info_v1 ();
	account_info_v1 (MDB_val const &);
	account_info_v1 (xpeed::account_info_v1 const &) = default;
	account_info_v1 (xpeed::block_hash const &, xpeed::block_hash const &, xpeed::amount const &, uint64_t);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	xpeed::mdb_val val () const;
	xpeed::block_hash head;
	xpeed::block_hash rep_block;
	xpeed::amount balance;
	uint64_t modified;
};
class pending_info_v3
{
public:
	pending_info_v3 ();
	pending_info_v3 (MDB_val const &);
	pending_info_v3 (xpeed::account const &, xpeed::amount const &, xpeed::account const &);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	bool operator== (xpeed::pending_info_v3 const &) const;
	xpeed::mdb_val val () const;
	xpeed::account source;
	xpeed::amount amount;
	xpeed::account destination;
};
// Latest information about an account
class account_info_v5
{
public:
	account_info_v5 ();
	account_info_v5 (MDB_val const &);
	account_info_v5 (xpeed::account_info_v5 const &) = default;
	account_info_v5 (xpeed::block_hash const &, xpeed::block_hash const &, xpeed::block_hash const &, xpeed::amount const &, uint64_t);
	void serialize (xpeed::stream &) const;
	bool deserialize (xpeed::stream &);
	xpeed::mdb_val val () const;
	xpeed::block_hash head;
	xpeed::block_hash rep_block;
	xpeed::block_hash open_block;
	xpeed::amount balance;
	uint64_t modified;
};
}
