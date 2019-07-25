#pragma once

#include <memory>
#include <xpeed/lib/blocks.hpp>
#include <xpeed/lib/errors.hpp>

namespace xpeed
{
/** Flags to track builder state */
enum class build_flags : uint8_t
{
	signature_present = 1,
	work_present = 2,
	account_present = 4,
	balance_present = 8,
	/* link also covers source and destination for legacy blocks */
	link_present = 16,
	previous_present = 32,
	representative_present = 64
};

inline xpeed::build_flags operator| (xpeed::build_flags a, xpeed::build_flags b)
{
	return static_cast<xpeed::build_flags> (static_cast<uint8_t> (a) | static_cast<uint8_t> (b));
}
inline uint8_t operator| (uint8_t a, xpeed::build_flags b)
{
	return static_cast<uint8_t> (a | static_cast<uint8_t> (b));
}
inline uint8_t operator& (uint8_t a, xpeed::build_flags b)
{
	return static_cast<uint8_t> (a & static_cast<uint8_t> (b));
}
inline uint8_t operator|= (uint8_t & a, xpeed::build_flags b)
{
	return a = static_cast<uint8_t> (a | static_cast<uint8_t> (b));
}

/**
 * Base type for block builder implementations. We employ static polymorphism
 * to pass validation through subtypes without incurring the vtable cost.
 */
template <typename BLOCKTYPE, typename BUILDER>
class abstract_builder
{
public:
	/** Returns the built block as a unique_ptr */
	inline std::unique_ptr<BLOCKTYPE> build ()
	{
		if (!ec)
		{
			static_cast<BUILDER *> (this)->validate ();
		}
		assert (!ec);
		return std::move (block);
	}

	/** Returns the built block as a unique_ptr. Any errors are placed in \p ec */
	inline std::unique_ptr<BLOCKTYPE> build (std::error_code & ec)
	{
		if (!this->ec)
		{
			static_cast<BUILDER *> (this)->validate ();
		}
		ec = this->ec;
		return std::move (block);
	}

	/** Set work value */
	inline abstract_builder & work (uint64_t work)
	{
		block->work = work;
		build_state |= build_flags::work_present;
		return *this;
	}

	/** Sign the block using the \p private_key and \p public_key */
	inline abstract_builder & sign (xpeed::raw_key const & private_key, xpeed::public_key const & public_key)
	{
		block->signature = xpeed::sign_message (private_key, public_key, block->hash ());
		build_state |= build_flags::signature_present;
		return *this;
	}

	/** Set signature to zero to pass build() validation, allowing block to be signed at a later point. This is mostly useful for tests. */
	inline abstract_builder & sign_zero ()
	{
		block->signature.clear ();
		build_state |= build_flags::signature_present;
		return *this;
	}

protected:
	abstract_builder ()
	{
	}

	/** Create a new block and resets the internal builder state */
	inline void construct_block ()
	{
		block = std::make_unique<BLOCKTYPE> ();
		ec.clear ();
		build_state = 0;
	}

	/** The block we're building. Clients can convert this to shared_ptr as needed. */
	std::unique_ptr<BLOCKTYPE> block;

	/**
	 * Set if any builder functions fail. This will be output via the build(std::error_code) function,
	 * or cause an assert for the parameter-less overload.
	 */
	std::error_code ec;

	/** Bitset to track build state */
	uint8_t build_state{ 0 };

	/** Required field shared by all block types*/
	uint8_t base_fields = static_cast<uint8_t> (xpeed::build_flags::work_present | xpeed::build_flags::signature_present);
};

/** Builder for state blocks */
class state_block_builder : public abstract_builder<xpeed::state_block, state_block_builder>
{
public:
	/** Creates a state block builder by calling make_block() */
	state_block_builder ();
	/** Creates a new block with fields, signature and work set to sentinel values. All fields must be set or zeroed for build() to succeed. */
	state_block_builder & make_block ();
	/** Sets all hashables, signature and work to zero. */
	state_block_builder & zero ();
	/** Set account */
	state_block_builder & account (xpeed::account account);
	/** Set account from hex representation of public key */
	state_block_builder & account_hex (std::string account_hex);
	/** Set account from an xpd_ address */
	state_block_builder & account_address (std::string account_address);
	/** Set representative */
	state_block_builder & representative (xpeed::account account);
	/** Set representative from hex representation of public key */
	state_block_builder & representative_hex (std::string account_hex);
	/** Set representative from an xpd_ address */
	state_block_builder & representative_address (std::string account_address);
	/** Set previous block hash */
	state_block_builder & previous (xpeed::block_hash previous);
	/** Set previous block hash from hex representation */
	state_block_builder & previous_hex (std::string previous_hex);
	/** Set balance */
	state_block_builder & balance (xpeed::amount balance);
	/** Set balance from decimal string */
	state_block_builder & balance_dec (std::string balance_decimal);
	/** Set balance from hex string */
	state_block_builder & balance_hex (std::string balance_hex);
	/** Set link */
	state_block_builder & link (xpeed::uint256_union link);
	/** Set link from hex representation */
	state_block_builder & link_hex (std::string link_hex);
	/** Set link from an xpd_ address */
	state_block_builder & link_address (std::string link_address);
	/** Provides validation for build() */
	void validate ();

private:
	uint8_t required_fields = base_fields | static_cast<uint8_t> (xpeed::build_flags::account_present | xpeed::build_flags::balance_present | xpeed::build_flags::link_present | xpeed::build_flags::previous_present | xpeed::build_flags::representative_present);
};

/** Builder for open blocks */
class open_block_builder : public abstract_builder<xpeed::open_block, open_block_builder>
{
public:
	/** Creates an open block builder by calling make_block() */
	open_block_builder ();
	/** Creates a new block with fields, signature and work set to sentinel values. All fields must be set or zeroed for build() to succeed. */
	open_block_builder & make_block ();
	/** Sets all hashables, signature and work to zero. */
	open_block_builder & zero ();
	/** Set account */
	open_block_builder & account (xpeed::account account);
	/** Set account from hex representation of public key */
	open_block_builder & account_hex (std::string account_hex);
	/** Set account from an or xpd_ address */
	open_block_builder & account_address (std::string account_address);
	/** Set representative */
	open_block_builder & representative (xpeed::account account);
	/** Set representative from hex representation of public key */
	open_block_builder & representative_hex (std::string account_hex);
	/** Set representative from an xpd_ address */
	open_block_builder & representative_address (std::string account_address);
	/** Set source block hash */
	open_block_builder & source (xpeed::block_hash source);
	/** Set source block hash from hex representation */
	open_block_builder & source_hex (std::string source_hex);
	/** Provides validation for build() */
	void validate ();

private:
	uint8_t required_fields = base_fields | static_cast<uint8_t> (xpeed::build_flags::account_present | xpeed::build_flags::representative_present | xpeed::build_flags::link_present);
};

/** Builder for change blocks */
class change_block_builder : public abstract_builder<xpeed::change_block, change_block_builder>
{
public:
	/** Create a change block builder by calling make_block() */
	change_block_builder ();
	/** Creates a new block with fields, signature and work set to sentinel values. All fields must be set or zeroed for build() to succeed. */
	change_block_builder & make_block ();
	/** Sets all hashables, signature and work to zero. */
	change_block_builder & zero ();
	/** Set representative */
	change_block_builder & representative (xpeed::account account);
	/** Set representative from hex representation of public key */
	change_block_builder & representative_hex (std::string account_hex);
	/** Set representative from an xpd_ address */
	change_block_builder & representative_address (std::string account_address);
	/** Set previous block hash */
	change_block_builder & previous (xpeed::block_hash previous);
	/** Set previous block hash from hex representation */
	change_block_builder & previous_hex (std::string previous_hex);
	/** Provides validation for build() */
	void validate ();

private:
	uint8_t required_fields = base_fields | static_cast<uint8_t> (xpeed::build_flags::previous_present | xpeed::build_flags::representative_present);
};

/** Builder for send blocks */
class send_block_builder : public abstract_builder<xpeed::send_block, send_block_builder>
{
public:
	/** Creates a send block builder by calling make_block() */
	send_block_builder ();
	/** Creates a new block with fields, signature and work set to sentinel values. All fields must be set or zeroed for build() to succeed. */
	send_block_builder & make_block ();
	/** Sets all hashables, signature and work to zero. */
	send_block_builder & zero ();
	/** Set destination */
	send_block_builder & destination (xpeed::account account);
	/** Set destination from hex representation of public key */
	send_block_builder & destination_hex (std::string account_hex);
	/** Set destination from an xpd_ address */
	send_block_builder & destination_address (std::string account_address);
	/** Set previous block hash */
	send_block_builder & previous (xpeed::block_hash previous);
	/** Set previous block hash from hex representation */
	send_block_builder & previous_hex (std::string previous_hex);
	/** Set balance */
	send_block_builder & balance (xpeed::amount balance);
	/** Set balance from decimal string */
	send_block_builder & balance_dec (std::string balance_decimal);
	/** Set balance from hex string */
	send_block_builder & balance_hex (std::string balance_hex);
	/** Provides validation for build() */
	void validate ();

private:
	uint8_t required_fields = base_fields | static_cast<uint8_t> (build_flags::previous_present | build_flags::link_present | build_flags::balance_present);
};

/** Builder for receive blocks */
class receive_block_builder : public abstract_builder<xpeed::receive_block, receive_block_builder>
{
public:
	/** Creates a receive block by calling make_block() */
	receive_block_builder ();
	/** Creates a new block with fields, signature and work set to sentinel values. All fields must be set or zeroed for build() to succeed. */
	receive_block_builder & make_block ();
	/** Sets all hashables, signature and work to zero. */
	receive_block_builder & zero ();
	/** Set previous block hash */
	receive_block_builder & previous (xpeed::block_hash previous);
	/** Set previous block hash from hex representation */
	receive_block_builder & previous_hex (std::string previous_hex);
	/** Set source block hash */
	receive_block_builder & source (xpeed::block_hash source);
	/** Set source block hash from hex representation */
	receive_block_builder & source_hex (std::string source_hex);
	/** Provides validation for build() */
	void validate ();

private:
	uint8_t required_fields = base_fields | static_cast<uint8_t> (build_flags::previous_present | build_flags::link_present);
};

/** Block builder to simplify construction of the various block types */
class block_builder
{
public:
	/** Prepares a new state block and returns a block builder */
	inline xpeed::state_block_builder & state ()
	{
		state_builder.make_block ();
		return state_builder;
	}

	/** Prepares a new open block and returns a block builder */
	inline xpeed::open_block_builder & open ()
	{
		open_builder.make_block ();
		return open_builder;
	}

	/** Prepares a new change block and returns a block builder */
	inline xpeed::change_block_builder & change ()
	{
		change_builder.make_block ();
		return change_builder;
	}

	/** Prepares a new send block and returns a block builder */
	inline xpeed::send_block_builder & send ()
	{
		send_builder.make_block ();
		return send_builder;
	}

	/** Prepares a new receive block and returns a block builder */
	inline xpeed::receive_block_builder & receive ()
	{
		receive_builder.make_block ();
		return receive_builder;
	}

private:
	xpeed::state_block_builder state_builder;
	xpeed::open_block_builder open_builder;
	xpeed::change_block_builder change_builder;
	xpeed::send_block_builder send_builder;
	xpeed::receive_block_builder receive_builder;
};
}
