cmake_minimum_required (VERSION 2.6)

IF(APPLE)
	SET(CMAKE_OSX_ARCHITECTURES "i386;x86_64")
ELSEIF(UNIX)
	SET(CMAKE_INSTALL_PREFIX "/usr")
ENDIF()

project (SiliconDust)

set(CMAKE_BUILD_TYPE RELEASE)

IF(CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wpointer-arith -Wno-unused-parameter")
ENDIF()

add_library(hdhomerun SHARED
	hdhomerun_channels.c
	hdhomerun_channelscan.c
	hdhomerun_control.c
	hdhomerun_debug.c
	hdhomerun_device.c
	hdhomerun_device_selector.c
	hdhomerun_discover.c
	hdhomerun_os_posix.c
	hdhomerun_pkt.c
	hdhomerun_sock_posix.c
	hdhomerun_video.c
)

set_property(TARGET hdhomerun PROPERTY VERSION "20161117")
set_property(TARGET hdhomerun PROPERTY SOVERSION 1 )
IF(WIN32)
	target_link_libraries(hdhomerun PUBLIC pthread iphlpapi)
ELSE()
	target_link_libraries(hdhomerun PUBLIC pthread rt)
ENDIF()

add_executable(hdhomerun_config
	hdhomerun_config.c
)

target_link_libraries(hdhomerun_config PUBLIC hdhomerun)

install(TARGETS hdhomerun DESTINATION lib)
install(TARGETS hdhomerun_config DESTINATION bin)
