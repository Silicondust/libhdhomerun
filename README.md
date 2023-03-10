Copyright © 2005-2022 Silicondust USA Inc. <www.silicondust.com>.

This library implements the libhdhomerun protocol for use with Silicondust HDHomeRun TV tuners.

To compile simply "make" - this will compile both the library and the hdhomerun_config command line
utility suitable for sending commands or scripting control of a HDHomeRun.

The top level API is hdhomerun_device - see hdhomerun_device.h for documentation.

Additional libraries required:
- pthread (osx, linux, bsd)
- iphlpapi (windows)

# Compile Instructions

## Linux/BSD
* run `make`

## Windows
* Create a new Visual Studio project (empty C++)
* Include all the .c and .h files, except `hdhomerun_os_posix.h`, `hdhomerun_os_posix.c`,  `hdhomerun_sock_getifaddrs.c`, `hdhomerun_sock_netdevice.c`, `hdhomerun_sock_netlink.c` & `hdhomerun_sock_posix.c` 
* Under the Linker input, add `Bcrypt.lib`, `Ws2_32.lib`, `iphlpapi.lib` as Additional Dependencies.
* Build using Visual Studio

If using VS2017 or earlier, on the project properties page under C/C++ advanced, change the Compile As type to C, click apply and then change it back to C++ – this is a workaround for a bug in MSVC++.
