project(
    'libhdhomerun',
    'c',
    license: 'LGPL-2.1-or-later',
    meson_version: '>=0.54',
)

if target_machine.system() == 'windows'
    if_detect = 'netdevice'
elif target_machine.system() == 'linux'
    if_detect = 'netlink'
else
    if_detect = 'getifaddrs'
endif

srcs = files(
    'hdhomerun_channels.c',
    'hdhomerun_channelscan.c',
    'hdhomerun_control.c',
    'hdhomerun_debug.c',
    'hdhomerun_device.c',
    'hdhomerun_device_selector.c',
    'hdhomerun_discover.c',
    'hdhomerun_os_posix.c',
    'hdhomerun_pkt.c',
    'hdhomerun_sock.c',
    'hdhomerun_sock_posix.c',
    'hdhomerun_sock_@0@.c'.format(if_detect),
    'hdhomerun_video.c',
)

hdrs = files(
    'hdhomerun_channelscan.h',
    'hdhomerun_channels.h',
    'hdhomerun_control.h',
    'hdhomerun_debug.h',
    'hdhomerun_device.h',
    'hdhomerun_device_selector.h',
    'hdhomerun_discover.h',
    'hdhomerun.h',
    'hdhomerun_os.h',
    'hdhomerun_os_posix.h',
    'hdhomerun_os_windows.h',
    'hdhomerun_pkt.h',
    'hdhomerun_sock.h',
    'hdhomerun_types.h',
    'hdhomerun_video.h',
)

hdhomerun_lib = library(
    'hdhomerun',
    srcs,
    install: true,
)

libhdhomerun_dep = declare_dependency(
    include_directories: [include_directories('.')],
    link_with: hdhomerun_lib,
)
meson.override_dependency('libhdhomerun', libhdhomerun_dep)

executable(
    'hdhomerun_config',
    'hdhomerun_config.c',
    dependencies: libhdhomerun_dep,
    install: true,
)

executable(
    'hdhomerun_discover_example',
    'hdhomerun_discover_example.c',
    dependencies: libhdhomerun_dep,
)

install_headers(hdrs)

pkg = import('pkgconfig')
pkg.generate(hdhomerun_lib, filebase: 'libhdhomerun')

