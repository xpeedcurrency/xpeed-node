cmake_minimum_required (VERSION 3.4)
project (xpeed-node)

set (CPACK_PACKAGE_VERSION_MAJOR "18")
set (CPACK_PACKAGE_VERSION_MINOR "0")
set (CPACK_PACKAGE_VERSION_PATCH "0")
set (CPACK_PACKAGE_VENDOR "Xpeed Coin")

set(CMAKE_INSTALL_RPATH "@executable_path/../Frameworks")
# Create all libraries and executables in the root binary dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set (XPD_GUI OFF CACHE BOOL "")
set (XPD_TEST OFF CACHE BOOL "")
set (XPD_SECURE_RPC OFF CACHE BOOL "")

option(XPD_ASAN_INT "Enable ASan+UBSan+Integer overflow" OFF)
option(XPD_ASAN "Enable ASan+UBSan" OFF)
option(XPD_TSAN "Enable TSan" OFF)
option(XPD_SIMD_OPTIMIZATIONS "Enable CPU-specific SIMD optimizations (SSE/AVX or NEON, e.g.)" OFF)
option(ENABLE_AES "Enable AES optimizations (enabled by default with XPD_SIMD_OPTIMIZATIONS, set OFF to disable" ON)
option(ENABLE_AVX2 "Enable AVX2 optimizations" OFF)

SET (ACTIVE_NETWORK xpd_live_network CACHE STRING "Selects which network parameters are used")
set_property (CACHE ACTIVE_NETWORK PROPERTY STRINGS xpd_test_network xpd_beta_network xpd_live_network)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads)


add_compile_options(-Werror=switch)
if (XPD_ASAN)
	add_compile_options(-fsanitize=address,undefined)
	add_definitions(-DED25519_NO_INLINE_ASM)
elseif (XPD_ASAN_INT)
	add_compile_options(-fsanitize=address,undefined,integer)
	add_definitions(-DED25519_NO_INLINE_ASM)
elseif (XPD_TSAN)
	add_compile_options(-fsanitize=thread)
	if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
		add_compile_options("-fsanitize-blacklist=${PROJECT_SOURCE_DIR}/tsan_blacklist")
	endif()
	add_definitions(-DED25519_NO_INLINE_ASM)
endif()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(i.86|x86(_64)?)$")
	if (XPD_SIMD_OPTIMIZATIONS)
		add_compile_options(-msse4)
		if (ENABLE_AES)
			add_compile_options(-maes)
		else ()
			add_definitions(-DCRYPTOPP_DISABLE_AESNI)
		endif ()
	elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
		add_compile_options(-msse2)
		add_definitions(-DCRYPTOPP_DISABLE_SSSE3
						-DCRYPTOPP_DISABLE_AESNI)
	endif()

	if (ENABLE_AVX2)
		add_compile_options(-mavx2 -mbmi -mbmi2 -maes)
		if (PERMUTE_WITH_GATHER)
			add_definitions(-DPERMUTE_WITH_GATHER)
		elseif (PERMUTE_WITH_SHUFFLES)
			add_definitions(-DPERMUTE_WITH_SHUFFLES)
		endif()
	endif()
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
	if (XPD_SIMD_OPTIMIZATIONS)
		add_compile_options(-march=armv8-a+crc+crypto)
	else ()
		add_compile_options(-march=armv8-a)
		add_definitions(-DCRYPTOPP_DISABLE_ASM)
	endif ()
endif()


set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
#set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(CMAKE_CXX_EXTENSIONS OFF)


set (PLATFORM_LINK_FLAGS "-static-libgcc -static-libstdc++")


if (XPD_ASAN)
	set (PLATFORM_LINK_FLAGS "${PLATFORM_LINK_FLAGS} -fsanitize=address,undefined")
elseif (XPD_ASAN_INT)
	set (PLATFORM_LINK_FLAGS "${PLATFORM_LINK_FLAGS} -fsanitize=address,undefined,integer")
elseif (XPD_TSAN)
	set (PLATFORM_LINK_FLAGS "${PLATFORM_LINK_FLAGS} -fsanitize=thread")
	if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
		set (PLATFORM_LINK_FLAGS "${PLATFORM_LINK_FLAGS} -fsanitize-blacklist=${PROJECT_SOURCE_DIR}/tsan_blacklist")
	endif()
endif()


SET( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${PLATFORM_LINK_FLAGS}" )

if (XPD_SECURE_RPC)
	find_package (OpenSSL 1.0 REQUIRED)
	include_directories(${OPENSSL_INCLUDE_DIR})
	add_definitions (-DXPD_SECURE_RPC)
	message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
	message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
	message("OpenSSL lib: ${OPENSSL_SSL_LIBRARY}")
	message("Crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")
else ()
	set (OPENSSL_LIBRARIES "")
endif ()

include_directories (${CMAKE_SOURCE_DIR})

set(Boost_USE_STATIC_LIBS        ON)
set(Boost_USE_MULTITHREADED      ON)

if (BOOST_ROOT)
	list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")
endif ()

find_package (Boost 1.66.0 REQUIRED COMPONENTS filesystem log thread program_options system)

add_subdirectory(crypto/ed25519-donna)

set (UPNPC_BUILD_SHARED OFF CACHE BOOL "")
add_subdirectory (miniupnp/miniupnpc EXCLUDE_FROM_ALL)
# FIXME: This fixes miniupnpc include directories without modifying miniupnpc's
# CMakeLists.txt but should be set there
set_target_properties(libminiupnpc-static PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
	"${CMAKE_SOURCE_DIR}/miniupnp/miniupnpc")

set (BUILD_SHARED OFF CACHE BOOL "")
set (BUILD_TESTING OFF CACHE BOOL "")
set (USE_INTERMEDIATE_OBJECTS_TARGET OFF CACHE BOOL "")
set (CRYPTOPP_EXTRA "")
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" AND (XPD_SIMD_OPTIMIZATIONS))
	set (CRYPTOPP_EXTRA crypto/cryptopp/crc_simd.cpp
					crypto/cryptopp/gcm_simd.cpp
					crypto/cryptopp/gf2n_simd.cpp
					crypto/cryptopp/neon_simd.cpp)
	add_definitions(-DCRYPTOPP_NO_CPU_FEATURE_PROBES)
endif ()
# Some Clang cannot handle mixed asm with positional arguments, where the
# body is Intel style with no prefix and the templates are AT&T style.
# See: crypto/cryptopp/config.h
# Also see https://bugs.llvm.org/show_bug.cgi?id=39895
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
	add_definitions(-DCRYPTOPP_DISABLE_MIXED_ASM -DCRYPTOPP_DISABLE_ASM)
	message("CryptoPP with disabled ASM for ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
endif ()
add_definitions(-DCRYPTOPP_DISABLE_SHANI)
# Fix failing builds after commit https://github.com/weidai11/cryptopp/commit/df9fa62205f2d341e2b1b26595a3a1b6377c60c5
add_definitions(-DCRYPTOPP_DISABLE_CLMUL)

set (CRYPTOPP_LIBRARY cryptopp)
add_library (cryptopp
	crypto/cryptopp/algparam.cpp
	crypto/cryptopp/asn.cpp
	crypto/cryptopp/basecode.cpp
	crypto/cryptopp/cpu.cpp
	crypto/cryptopp/cryptlib.cpp
	crypto/cryptopp/default.cpp
	crypto/cryptopp/des.cpp
	crypto/cryptopp/dessp.cpp
	crypto/cryptopp/dll.cpp
	crypto/cryptopp/ec2n.cpp
	crypto/cryptopp/ecp.cpp
	crypto/cryptopp/filters.cpp
	crypto/cryptopp/fips140.cpp
	crypto/cryptopp/gcm.cpp
	crypto/cryptopp/gf2n.cpp
	crypto/cryptopp/gfpcrypt.cpp
	crypto/cryptopp/hex.cpp
	crypto/cryptopp/hmac.cpp
	crypto/cryptopp/hrtimer.cpp
	crypto/cryptopp/integer.cpp
	crypto/cryptopp/iterhash.cpp
	crypto/cryptopp/misc.cpp
	crypto/cryptopp/modes.cpp
	crypto/cryptopp/mqueue.cpp
	crypto/cryptopp/nbtheory.cpp
	crypto/cryptopp/oaep.cpp
	crypto/cryptopp/osrng.cpp
	crypto/cryptopp/pubkey.cpp
	crypto/cryptopp/queue.cpp
	crypto/cryptopp/randpool.cpp
	crypto/cryptopp/rdtables.cpp
	crypto/cryptopp/rijndael.cpp
	crypto/cryptopp/rijndael_simd.cpp
	crypto/cryptopp/rng.cpp
	crypto/cryptopp/sha.cpp
	crypto/cryptopp/sha_simd.cpp
	crypto/cryptopp/simple.cpp
	crypto/cryptopp/sse_simd.cpp
	${CRYPTOPP_EXTRA})

if ((XPD_SIMD_OPTIMIZATIONS) AND NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
	set (ARGON_CORE crypto/phc-winner-argon2/src/opt.c)
else ()
	set (ARGON_CORE crypto/phc-winner-argon2/src/ref.c)
endif ()

add_library (argon2
	crypto/phc-winner-argon2/src/argon2.c
	crypto/phc-winner-argon2/include/argon2.h
	crypto/phc-winner-argon2/src/core.c
	crypto/phc-winner-argon2/src/thread.c
	crypto/phc-winner-argon2/src/encoding.c
	${ARGON_CORE})

target_include_directories(argon2 PUBLIC crypto/phc-winner-argon2/include)
target_include_directories(argon2 PUBLIC crypto/phc-winner-argon2/src)
target_include_directories(argon2 PUBLIC crypto/blake2)

add_library (xxhash
	crypto/xxhash/xxhash.c
	crypto/xxhash/xxhash.h)

add_library (lmdb
	lmdb/libraries/liblmdb/lmdb.h
	lmdb/libraries/liblmdb/mdb.c
	lmdb/libraries/liblmdb/midl.c)



IF (CMAKE_SYSTEM_PROCESSOR MATCHES "^(i.86|x86(_64)?)$")
	set (BLAKE2_IMPLEMENTATION "crypto/blake2/blake2b.c")
else()
	set (BLAKE2_IMPLEMENTATION "crypto/blake2/blake2b-ref.c")
endif()


add_library (blake2
	crypto/blake2/blake2-config.h
	crypto/blake2/blake2-impl.h
	crypto/blake2/blake2.h
	${BLAKE2_IMPLEMENTATION})

target_compile_definitions(blake2 PRIVATE -D__SSE2__)

add_subdirectory(xpeed/secure)
add_subdirectory(xpeed/lib)
add_subdirectory(xpeed/node)
add_subdirectory(xpeed/xpd_node)

if (XPD_TEST)
    set (gtest_force_shared_crt OFF)

    add_subdirectory (gtest)
	# FIXME: This fixes gtest include directories without modifying gtest's
	# CMakeLists.txt. Ideally we should use GTest::GTest and GTest::Main as
	# dependencies but it requires building gtest differently
	set_target_properties(gtest PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
		"${CMAKE_SOURCE_DIR}/gtest/include")

endif ()

set (CPACK_RESOURCE_FILE_LICENSE ${CMAKE_SOURCE_DIR}/LICENSE)

include (CPack)
