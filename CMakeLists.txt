cmake_minimum_required(VERSION 2.8)

project(hdhomerun)

include(CheckLibraryExists)

set(SOURCES 
  hdhomerun_channels.c
  hdhomerun_channelscan.c
  hdhomerun_control.c
  hdhomerun_debug.c
  hdhomerun_device.c
  hdhomerun_discover.c
  hdhomerun_pkt.c
  hdhomerun_video.c)

set(HEADERS 
  ${PROJECT_SOURCE_DIR}/hdhomerun.h
  hdhomerun_channels.h
  hdhomerun_channelscan.h
  hdhomerun_control.h
  hdhomerun_debug.h
  hdhomerun_device.h
  hdhomerun_device_selector.h
  hdhomerun_discover.h
  hdhomerun_pkt.h
  hdhomerun_sock.h
  hdhomerun_types.h
  hdhomerun_os.h
  hdhomerun_video.h)

if(WIN32)
  LIST(APPEND SOURCES hdhomerun_os_windows.c)
  LIST(APPEND SOURCES hdhomerun_sock_windows.c)
  LIST(APPEND HEADERS hdhomerun_os_windows.h)
else()
  LIST(APPEND SOURCES hdhomerun_os_posix.c)
  LIST(APPEND SOURCES hdhomerun_sock_posix.c)
  LIST(APPEND HEADERS hdhomerun_os_posix.h)
endif()

if(WIN32)
  list(APPEND DEPLIBS ws2_32 iphlpapi)
else()
  list(APPEND DEPLIBS pthread)
  check_library_exists(rt clock_gettime "" HAS_LIBRT)
  if (HAS_LIBRT)
    list(APPEND DEPLIBS rt)
  endif()  
endif()

if(MSVC)
  set_source_files_properties(${SOURCES} PROPERTIES LANGUAGE "CXX")
  add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

add_library(hdhomerun SHARED ${SOURCES})
target_link_libraries(hdhomerun ${DEPLIBS})

if(WIN32)
  set_target_properties(hdhomerun PROPERTIES DEFINE_SYMBOL "LIBHDHOMERUN_DLLEXPORT") 
endif()

add_executable(hdhomerun_config hdhomerun_config.c)
target_link_libraries(hdhomerun_config hdhomerun)

include_directories(${PROJECT_SOURCE_DIR})

install(FILES ${HEADERS} DESTINATION include/hdhomerun)
install(TARGETS hdhomerun hdhomerun_config
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
