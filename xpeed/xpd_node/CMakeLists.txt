add_executable (xpd_node
	daemon.cpp
	daemon.hpp
	entry.cpp)

target_link_libraries (xpd_node
	node
	secure
	argon2
	Boost::boost
	${PLATFORM_LIBS}
)

target_compile_definitions(xpd_node
	PRIVATE
		-DXPD_VERSION_MAJOR=${CPACK_PACKAGE_VERSION_MAJOR}
		-DXPD_VERSION_MINOR=${CPACK_PACKAGE_VERSION_MINOR}
		-DXPD_VERSION_PATCH=${CPACK_PACKAGE_VERSION_PATCH})

set_target_properties (xpd_node
	PROPERTIES
		COMPILE_FLAGS
			"-DQT_NO_KEYWORDS -DBOOST_ASIO_HAS_STD_ARRAY=1")

if ((XPD_GUI) AND NOT APPLE)
	install(TARGETS xpd_node
			RUNTIME DESTINATION bin
			LIBRARY DESTINATION lib
			ARCHIVE DESTINATION lib
	)
endif()
