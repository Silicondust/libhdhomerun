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

#include <sys/ioctl.h>
#include <net/if.h>

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
	if (af != AF_INET) {
		return false;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		return false;
	}

	int ifreq_buffer_size = 128 * sizeof(struct ifreq);
	char *ifreq_buffer = (char *)calloc(1, ifreq_buffer_size);
	if (!ifreq_buffer) {
		close(sock);
		return false;
	}

	struct ifconf ifc;
	ifc.ifc_len = ifreq_buffer_size;
	ifc.ifc_buf = ifreq_buffer;

	if (ioctl(sock, SIOCGIFCONF, &ifc) != 0) {
		free(ifreq_buffer);
		close(sock);
		return false;
	}

	if (ifc.ifc_len > ifreq_buffer_size) {
		ifc.ifc_len = ifreq_buffer_size;
	}

	char *ptr = ifc.ifc_buf;
	char *end = ifc.ifc_buf + ifc.ifc_len;

	while (ptr + sizeof(struct ifreq) <= end) {
		struct ifreq *ifr = (struct ifreq *)ptr;
		ptr += sizeof(struct ifreq);

		/* Local IP address. */
		struct sockaddr_in ip_addr_in;
		memcpy(&ip_addr_in, &ifr->ifr_addr, sizeof(ip_addr_in));
		if (!hdhomerun_sock_sockaddr_is_addr((const struct sockaddr *)&ip_addr_in)) {
			continue;
		}

		/* Flags. */
		if (ioctl(sock, SIOCGIFFLAGS, ifr) != 0) {
			continue;
		}

		if ((ifr->ifr_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) != 0) {
			continue;
		}
		if ((ifr->ifr_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
			continue;
		}

		/* Subnet mask. */
		if (ioctl(sock, SIOCGIFNETMASK, ifr) != 0) {
			continue;
		}

		struct sockaddr_in *netmask_in = (struct sockaddr_in *)&ifr->ifr_addr;
		uint8_t cidr = hdhomerun_local_ip_netmask_to_cidr((uint8_t *)&netmask_in->sin_addr.s_addr, 4);
		if ((cidr == 0) || (cidr >= 32)) {
			continue;
		}

		/* ifindex. */
		if (ioctl(sock, SIOCGIFINDEX, ifr) != 0) {
			continue;
		}

		uint32_t ifindex = ifr->ifr_ifindex;
		if (ifindex == 0) {
			continue;
		}

		/* Result. */
		callback(callback_arg, ifindex, (const struct sockaddr *)&ip_addr_in, cidr);
	}

	free(ifreq_buffer);
	close(sock);
	return true;
}
