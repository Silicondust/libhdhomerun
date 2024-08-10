
ifneq ($(OS),Windows_NT)
OS := $(shell uname -s)
endif

CC    := $(CROSS_COMPILE)gcc
STRIP := $(CROSS_COMPILE)strip

CFLAGS += -O2 -Wall -Wextra -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wpointer-arith -Wno-unused-parameter
LDFLAGS += -lpthread
SHARED = -shared -Wl,-soname,libhdhomerun$(LIBEXT)

IF_DETECT := getifaddrs
BINEXT :=
LIBEXT := .so

ifeq ($(OS),Windows_NT)
  IF_DETECT := netdevice
  BINEXT := .exe
  LIBEXT := .dll
  LDFLAGS += -liphlpapi
endif

ifeq ($(OS),Linux)
  IF_DETECT := netlink
  LDFLAGS += -lrt
endif

LIBSRCS += hdhomerun_channels.c
LIBSRCS += hdhomerun_channelscan.c
LIBSRCS += hdhomerun_control.c
LIBSRCS += hdhomerun_debug.c
LIBSRCS += hdhomerun_device.c
LIBSRCS += hdhomerun_device_selector.c
LIBSRCS += hdhomerun_discover.c
LIBSRCS += hdhomerun_os_posix.c
LIBSRCS += hdhomerun_pkt.c
LIBSRCS += hdhomerun_sock.c
LIBSRCS += hdhomerun_sock_posix.c
LIBSRCS += hdhomerun_sock_$(IF_DETECT).c
LIBSRCS += hdhomerun_video.c

ifeq ($(OS),Darwin)

TARGET_X64 := -target x86_64-apple-macos10.11
TARGET_ARM64 := -target arm64-apple-macos11

all : hdhomerun_config libhdhomerun.dylib

hdhomerun_config_x64 : hdhomerun_config.c $(LIBSRCS)
	$(CC) $(TARGET_X64) $(CFLAGS) $+ $(LDFLAGS) -o $@
	$(STRIP) $@

hdhomerun_config_arm64 : hdhomerun_config.c $(LIBSRCS)
	$(CC) $(TARGET_ARM64) $(CFLAGS) $+ $(LDFLAGS) -o $@
	$(STRIP) $@

hdhomerun_config : hdhomerun_config_x64 hdhomerun_config_arm64
	lipo -create -output hdhomerun_config hdhomerun_config_x64 hdhomerun_config_arm64

libhdhomerun_x64.dylib : $(LIBSRCS)
	$(CC) $(TARGET_X64) $(CFLAGS) -DDLL_EXPORT -fPIC -dynamiclib $+ $(LDFLAGS) -o $@

libhdhomerun_arm64.dylib : $(LIBSRCS)
	$(CC) $(TARGET_ARM64) $(CFLAGS) -DDLL_EXPORT -fPIC -dynamiclib $+ $(LDFLAGS) -o $@

libhdhomerun.dylib : libhdhomerun_x64.dylib libhdhomerun_arm64.dylib
	lipo -create -output libhdhomerun.dylib libhdhomerun_x64.dylib libhdhomerun_arm64.dylib

else

all : hdhomerun_config$(BINEXT) libhdhomerun$(LIBEXT)

hdhomerun_config$(BINEXT) : hdhomerun_config.c $(LIBSRCS)
	$(CC) $(CFLAGS) $+ $(LDFLAGS) -o $@
	$(STRIP) $@

libhdhomerun$(LIBEXT) : $(LIBSRCS)
	$(CC) $(CFLAGS) -DDLL_EXPORT -fPIC $(SHARED) $+ $(LDFLAGS) -o $@

endif

hdhomerun_discover_example$(BINEXT): hdhomerun_discover_example.c $(LIBSRCS)
	$(CC) $(CFLAGS) $+ $(LDFLAGS) -o $@
	$(STRIP) $@

clean :
	-rm -f hdhomerun_config$(BINEXT)
	-rm -f libhdhomerun$(LIBEXT)
	-rm -f hdhomerun_discover_example$(BINEXT)

distclean : clean

%:
	@echo "(ignoring request to make $@)"

.PHONY: all list clean distclean
