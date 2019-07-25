#pragma once

#include <xpeed/secure/common.hpp>

namespace xpeed
{
class block_store;
class stat;

class shared_ptr_block_hash
{
public:
	size_t operator() (std::shared_ptr<xpeed::block> const &) const;
	bool operator() (std::shared_ptr<xpeed::block> const &, std::shared_ptr<xpeed::block> const &) const;
};
using tally_t = std::map<xpeed::uint128_t, std::shared_ptr<xpeed::block>, std::greater<xpeed::uint128_t>>;
class ledger
{
public:
	ledger (xpeed::block_store &, xpeed::stat &, xpeed::uint256_union const & = 1, xpeed::account const & = 0);
	xpeed::account account (xpeed::transaction const &, xpeed::block_hash const &);
	xpeed::uint128_t amount (xpeed::transaction const &, xpeed::block_hash const &);
	xpeed::uint128_t balance (xpeed::transaction const &, xpeed::block_hash const &);
	xpeed::uint128_t account_balance (xpeed::transaction const &, xpeed::account const &);
	xpeed::uint128_t account_pending (xpeed::transaction const &, xpeed::account const &);
	xpeed::uint128_t weight (xpeed::transaction const &, xpeed::account const &);
	std::shared_ptr<xpeed::block> successor (xpeed::transaction const &, xpeed::uint512_union const &);
	std::shared_ptr<xpeed::block> forked_block (xpeed::transaction const &, xpeed::block const &);
	xpeed::block_hash latest (xpeed::transaction const &, xpeed::account const &);
	xpeed::block_hash latest_root (xpeed::transaction const &, xpeed::account const &);
	xpeed::block_hash representative (xpeed::transaction const &, xpeed::block_hash const &);
	xpeed::block_hash representative_calculated (xpeed::transaction const &, xpeed::block_hash const &);
	bool block_exists (xpeed::block_hash const &);
	bool block_exists (xpeed::block_type, xpeed::block_hash const &);
	std::string block_text (char const *);
	std::string block_text (xpeed::block_hash const &);
	bool is_send (xpeed::transaction const &, xpeed::state_block const &);
	xpeed::block_hash block_destination (xpeed::transaction const &, xpeed::block const &);
	xpeed::block_hash block_source (xpeed::transaction const &, xpeed::block const &);
	xpeed::process_return process (xpeed::transaction const &, xpeed::block const &, xpeed::signature_verification = xpeed::signature_verification::unknown);
	void rollback (xpeed::transaction const &, xpeed::block_hash const &, std::vector<xpeed::block_hash> &);
	void rollback (xpeed::transaction const &, xpeed::block_hash const &);
	void change_latest (xpeed::transaction const &, xpeed::account const &, xpeed::block_hash const &, xpeed::account const &, xpeed::uint128_union const &, uint64_t, bool = false, xpeed::epoch = xpeed::epoch::epoch_0);
	void dump_account_chain (xpeed::account const &);
	bool could_fit (xpeed::transaction const &, xpeed::block const &);
	bool is_epoch_link (xpeed::uint256_union const &);
	static xpeed::uint128_t const unit;
	xpeed::block_store & store;
	xpeed::stat & stats;
	std::unordered_map<xpeed::account, xpeed::uint128_t> bootstrap_weights;
	uint64_t bootstrap_weight_max_blocks;
	std::atomic<bool> check_bootstrap_weights;
	xpeed::uint256_union epoch_link;
	xpeed::account epoch_signer;
};

std::unique_ptr<seq_con_info_component> collect_seq_con_info (ledger & ledger, const std::string & name);
}
