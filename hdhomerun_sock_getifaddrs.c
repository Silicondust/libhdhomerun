/*
 * hdhomerun_sock_getifaddrs.c
 *
 * Copyright © 2010-2022 Silicondust USA Inc. <www.silicondust.com>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "hdhomerun.h"

#if defined(__APPLE__)
#import <TargetConditionals.h> 
#endif

#include <sys/ioctl.h>
#include <net/if.h>

#if !defined(TARGET_OS_IPHONE)
#include <netinet6/in6_var.h>
#endif

#include <ifaddrs.h>

static uint8_t hdhomerun_local_ip_netmask_to_cidr(uint8_t *subnet_mask, size_t len)
{
	uint8_t result = 0;

	uint8_t *ptr = subnet_mask;
	uint8_t *end = subnet_mask + len;
	while (ptr < end) {
		uint8_t c = *ptr++;
		if (c == 0xFF) {
			result += 8;
			continue;
		}

		while (c & 0x80) {
			result++;
			c <<= 1;
		}

		break;
	}

	return result;
}

bool hdhomerun_local_ip_info2(int af, hdhomerun_local_ip_info2_callback_t callback, void *callback_arg)
{
	int af6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (af6_sock == -1) {
		return -1;
	}

	struct ifaddrs *ifaddrs;
	if (getifaddrs(&ifaddrs) != 0) {
		close(af6_sock);
		return -1;
	}

	struct ifaddrs *ifa = ifaddrs;
	while (ifa) {
		if (ifa->ifa_addr == NULL) {
			ifa = ifa->ifa_next;
			continue;
		}

		if ((af != AF_UNSPEC) && (ifa->ifa_addr->sa_family != af)) {
			ifa = ifa->ifa_next;
			continue;
		}

		if (!hdhomerun_sock_sockaddr_is_addr(ifa->ifa_addr)) {
			ifa = ifa->ifa_next;
			continue;
		}

		unsigned int flags = ifa->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT | IFF_UP | IFF_RUNNING | IFF_MULTICAST);
		if (flags != (IFF_UP | IFF_RUNNING | IFF_MULTICAST)) {
			ifa = ifa->ifa_next;
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET) {
			uint32_t ifindex = if_nametoindex(ifa->ifa_name);

			struct sockaddr_in *netmask_in = (struct sockaddr_in *)ifa->ifa_netmask;
			uint8_t cidr = hdhomerun_local_ip_netmask_to_cidr((uint8_t *)&netmask_in->sin_addr.s_addr, 4);

			callback(callback_arg, ifindex, ifa->ifa_addr, cidr);

			ifa = ifa->ifa_next;
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET6) {
#if !defined(TARGET_OS_IPHONE)
			struct in6_ifreq ifr6;
			memset(&ifr6, 0, sizeof(ifr6));

			struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *)ifa->ifa_addr;
			strcpy(ifr6.ifr_name, ifa->ifa_name);
			ifr6.ifr_addr = *addr_in;

			if (ioctl(af6_sock, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
				ifa = ifa->ifa_next;
				continue;
			}
			
			if (ifr6.ifr_ifru.ifru_lifetime.ia6t_vltime != 0xFFFFFFFF) {
				ifa = ifa->ifa_next;
				continue;
			}
#endif
			uint32_t ifindex = if_nametoindex(ifa->ifa_name);

			struct sockaddr_in6 *netmask_in = (struct sockaddr_in6 *)ifa->ifa_netmask;
			uint8_t cidr = hdhomerun_local_ip_netmask_to_cidr(netmask_in->sin6_addr.s6_addr, 16);

			callback(callback_arg, ifindex, ifa->ifa_addr, cidr);

			ifa = ifa->ifa_next;
			continue;
		}

		ifa = ifa->ifa_next;
	}

	close(af6_sock);
	freeifaddrs(ifaddrs);
	return true;
}
