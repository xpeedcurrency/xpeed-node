if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	set (platform_sources plat/default/priority.cpp plat/posix/perms.cpp plat/darwin/thread_role.cpp)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	set (platform_sources plat/windows/priority.cpp plat/windows/perms.cpp plat/windows/thread_role.cpp)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	set (platform_sources plat/linux/priority.cpp plat/posix/perms.cpp plat/linux/thread_role.cpp)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
	set (platform_sources plat/default/priority.cpp plat/posix/perms.cpp plat/freebsd/thread_role.cpp)
else ()
	error ("Unknown platform: ${CMAKE_SYSTEM_NAME}")
endif ()

add_library (xpd_lib
	${platform_sources}
	errors.hpp
	errors.cpp
	expected.hpp
	blockbuilders.cpp
	blockbuilders.hpp
	blocks.cpp
	blocks.hpp
	config.hpp
	interface.cpp
	interface.h
	jsonconfig.hpp
	numbers.cpp
	numbers.hpp
	timer.hpp
	utility.cpp
	utility.hpp
	work.hpp
	work.cpp)

target_link_libraries (xpd_lib
	xxhash
	blake2
	${CRYPTOPP_LIBRARY}
	Boost::boost)

target_compile_definitions(xpd_lib
	PUBLIC
		-DACTIVE_NETWORK=${ACTIVE_NETWORK}
)

if ((XPD_GUI) AND NOT APPLE)
	install(TARGETS xpd_lib
			RUNTIME DESTINATION bin
			LIBRARY DESTINATION lib
			ARCHIVE DESTINATION lib
	)
endif()
