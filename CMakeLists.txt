project(hdhomerun)
cmake_minimum_required(VERSION 3.0.2)

set(hdhomerun_sources
  hdhomerun_channels.c
  hdhomerun_channelscan.c
  hdhomerun_control.c
  hdhomerun_debug.c
  hdhomerun_device.c
  hdhomerun_device_selector.c
  hdhomerun_discover.c
  hdhomerun_os_posix.c
  hdhomerun_pkt.c
  hdhomerun_sock.c
  hdhomerun_sock_posix.c
  hdhomerun_video.c
  )

set(hdhomerun_headers
  hdhomerun_channels.h
  hdhomerun_channelscan.h
  hdhomerun_control.h
  hdhomerun_debug.h
  hdhomerun_device.h
  hdhomerun_device_selector.h
  hdhomerun_discover.h
  hdhomerun.h
  hdhomerun_os.h
  hdhomerun_pkt.h
  hdhomerun_sock.h
  hdhomerun_types.h
  hdhomerun_video.h
  )

if (WIN32)

  set(hdhomerun_sources
    ${hdhomerun_sources}

    hdhomerun_os_windows.c
    hdhomerun_sock_netdevice.c
    )

  set(hdhomerun_headers
    ${hdhomerun_headers}

    hdhomerun_os_windows.h
    )

  set(hdhomerun_libs iphlpapi ws2_32)

else (WIN32)

  set(hdhomerun_headers
    ${hdhomerun_headers}

    hdhomerun_os_posix.h
    )

  set(hdhomerun_libs pthread)

  if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(hdhomerun_sources
      ${hdhomerun_sources}
      hdhomerun_sock_netlink.c
      )
    set(hdhomerun_libs ${hdhomerun_libs} rt)
  else()
    set(hdhomerun_sources
      ${hdhomerun_sources}
      hdhomerun_sock_getifaddrs.c
      )
  endif()

  if (CMAKE_SYSTEM_NAME MATCHES "(Solaris|SunOS)")
    set(hdhomerun_libs ${hdhomerun_libs} socket)
  endif()
endif ()

add_library(hdhomerun SHARED ${hdhomerun_sources} ${hdhomerun_headers})
target_compile_definitions(hdhomerun PRIVATE -DLIBHDHOMERUN_DLLEXPORT)
target_link_libraries(hdhomerun
  PRIVATE
  ${hdhomerun_libs}
  )

install(TARGETS hdhomerun DESTINATION lib)
install(FILES ${hdhomerun_headers} DESTINATION include)

add_executable(hdhomerun_config hdhomerun_config.c)
target_compile_definitions(hdhomerun_config PRIVATE -DLIBHDHOMERUN_DLLIMPORT)
target_link_libraries(hdhomerun_config
  PRIVATE
  hdhomerun
  ${hdhomerun_libs}
  )

install(TARGETS hdhomerun_config DESTINATION bin)
