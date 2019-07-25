#include "xpeed/lib/errors.hpp"

std::string xpeed::error_common_messages::message (int ev) const
{
	switch (static_cast<xpeed::error_common> (ev))
	{
		case xpeed::error_common::generic:
			return "Unknown error";
		case xpeed::error_common::missing_account:
			return "Missing account";
		case xpeed::error_common::missing_balance:
			return "Missing balance";
		case xpeed::error_common::missing_link:
			return "Missing link, source or destination";
		case xpeed::error_common::missing_previous:
			return "Missing previous";
		case xpeed::error_common::missing_representative:
			return "Missing representative";
		case xpeed::error_common::missing_signature:
			return "Missing signature";
		case xpeed::error_common::missing_work:
			return "Missing work";
		case xpeed::error_common::exception:
			return "Exception thrown";
		case xpeed::error_common::account_exists:
			return "Account already exists";
		case xpeed::error_common::account_not_found:
			return "Account not found";
		case xpeed::error_common::account_not_found_wallet:
			return "Account not found in wallet";
		case xpeed::error_common::bad_account_number:
			return "Bad account number";
		case xpeed::error_common::bad_balance:
			return "Bad balance";
		case xpeed::error_common::bad_link:
			return "Bad link value";
		case xpeed::error_common::bad_previous:
			return "Bad previous hash";
		case xpeed::error_common::bad_representative_number:
			return "Bad representative";
		case xpeed::error_common::bad_source:
			return "Bad source";
		case xpeed::error_common::bad_signature:
			return "Bad signature";
		case xpeed::error_common::bad_private_key:
			return "Bad private key";
		case xpeed::error_common::bad_public_key:
			return "Bad public key";
		case xpeed::error_common::bad_seed:
			return "Bad seed";
		case xpeed::error_common::bad_threshold:
			return "Bad threshold number";
		case xpeed::error_common::bad_wallet_number:
			return "Bad wallet number";
		case xpeed::error_common::bad_work_format:
			return "Bad work";
		case xpeed::error_common::insufficient_balance:
			return "Insufficient balance";
		case xpeed::error_common::invalid_amount:
			return "Invalid amount number";
		case xpeed::error_common::invalid_amount_big:
			return "Amount too big";
		case xpeed::error_common::invalid_count:
			return "Invalid count";
		case xpeed::error_common::invalid_ip_address:
			return "Invalid IP address";
		case xpeed::error_common::invalid_port:
			return "Invalid port";
		case xpeed::error_common::invalid_index:
			return "Invalid index";
		case xpeed::error_common::invalid_type_conversion:
			return "Invalid type conversion";
		case xpeed::error_common::invalid_work:
			return "Invalid work";
		case xpeed::error_common::numeric_conversion:
			return "Numeric conversion error";
		case xpeed::error_common::wallet_lmdb_max_dbs:
			return "Failed to create wallet. Increase lmdb_max_dbs in node config";
		case xpeed::error_common::wallet_locked:
			return "Wallet is locked";
		case xpeed::error_common::wallet_not_found:
			return "Wallet not found";
	}

	return "Invalid error code";
}

std::string xpeed::error_blocks_messages::message (int ev) const
{
	switch (static_cast<xpeed::error_blocks> (ev))
	{
		case xpeed::error_blocks::generic:
			return "Unknown error";
		case xpeed::error_blocks::bad_hash_number:
			return "Bad hash number";
		case xpeed::error_blocks::invalid_block:
			return "Block is invalid";
		case xpeed::error_blocks::invalid_block_hash:
			return "Invalid block hash";
		case xpeed::error_blocks::invalid_type:
			return "Invalid block type";
		case xpeed::error_blocks::not_found:
			return "Block not found";
		case xpeed::error_blocks::work_low:
			return "Block work is less than threshold";
	}

	return "Invalid error code";
}

std::string xpeed::error_rpc_messages::message (int ev) const
{
	switch (static_cast<xpeed::error_rpc> (ev))
	{
		case xpeed::error_rpc::generic:
			return "Unknown error";
		case xpeed::error_rpc::bad_destination:
			return "Bad destination account";
		case xpeed::error_rpc::bad_key:
			return "Bad key";
		case xpeed::error_rpc::bad_link:
			return "Bad link number";
		case xpeed::error_rpc::bad_previous:
			return "Bad previous";
		case xpeed::error_rpc::bad_representative_number:
			return "Bad representative number";
		case xpeed::error_rpc::bad_source:
			return "Bad source";
		case xpeed::error_rpc::bad_timeout:
			return "Bad timeout number";
		case xpeed::error_rpc::block_create_balance_mismatch:
			return "Balance mismatch for previous block";
		case xpeed::error_rpc::block_create_key_required:
			return "Private key or local wallet and account required";
		case xpeed::error_rpc::block_create_public_key_mismatch:
			return "Incorrect key for given account";
		case xpeed::error_rpc::block_create_requirements_state:
			return "Previous, representative, final balance and link (source or destination) are required";
		case xpeed::error_rpc::block_create_requirements_open:
			return "Representative account and source hash required";
		case xpeed::error_rpc::block_create_requirements_receive:
			return "Previous hash and source hash required";
		case xpeed::error_rpc::block_create_requirements_change:
			return "Representative account and previous hash required";
		case xpeed::error_rpc::block_create_requirements_send:
			return "Destination account, previous hash, current balance and amount required";
		case xpeed::error_rpc::confirmation_not_found:
			return "Active confirmation not found";
		case xpeed::error_rpc::invalid_balance:
			return "Invalid balance number";
		case xpeed::error_rpc::invalid_destinations:
			return "Invalid destinations number";
		case xpeed::error_rpc::invalid_offset:
			return "Invalid offset";
		case xpeed::error_rpc::invalid_missing_type:
			return "Invalid or missing type argument";
		case xpeed::error_rpc::invalid_root:
			return "Invalid root hash";
		case xpeed::error_rpc::invalid_sources:
			return "Invalid sources number";
		case xpeed::error_rpc::invalid_subtype:
			return "Invalid block subtype";
		case xpeed::error_rpc::invalid_subtype_balance:
			return "Invalid block balance for given subtype";
		case xpeed::error_rpc::invalid_subtype_epoch_link:
			return "Invalid epoch link";
		case xpeed::error_rpc::invalid_subtype_previous:
			return "Invalid previous block for given subtype";
		case xpeed::error_rpc::invalid_timestamp:
			return "Invalid timestamp";
		case xpeed::error_rpc::payment_account_balance:
			return "Account has non-zero balance";
		case xpeed::error_rpc::payment_unable_create_account:
			return "Unable to create transaction account";
		case xpeed::error_rpc::rpc_control_disabled:
			return "RPC control is disabled";
		case xpeed::error_rpc::sign_hash_disabled:
			return "Signing by block hash is disabled";
		case xpeed::error_rpc::source_not_found:
			return "Source not found";
	}

	return "Invalid error code";
}

std::string xpeed::error_process_messages::message (int ev) const
{
	switch (static_cast<xpeed::error_process> (ev))
	{
		case xpeed::error_process::generic:
			return "Unknown error";
		case xpeed::error_process::bad_signature:
			return "Bad signature";
		case xpeed::error_process::old:
			return "Old block";
		case xpeed::error_process::negative_spend:
			return "Negative spend";
		case xpeed::error_process::fork:
			return "Fork";
		case xpeed::error_process::unreceivable:
			return "Unreceivable";
		case xpeed::error_process::gap_previous:
			return "Gap previous block";
		case xpeed::error_process::gap_source:
			return "Gap source block";
		case xpeed::error_process::opened_burn_account:
			return "Burning account";
		case xpeed::error_process::balance_mismatch:
			return "Balance and amount delta do not match";
		case xpeed::error_process::block_position:
			return "This block cannot follow the previous block";
		case xpeed::error_process::other:
			return "Error processing block";
	}

	return "Invalid error code";
}

std::string xpeed::error_config_messages::message (int ev) const
{
	switch (static_cast<xpeed::error_config> (ev))
	{
		case xpeed::error_config::generic:
			return "Unknown error";
		case xpeed::error_config::invalid_value:
			return "Invalid configuration value";
		case xpeed::error_config::missing_value:
			return "Missing value in configuration";
	}

	return "Invalid error code";
}
