/*
 * hdhomerun_sock_netlink.c
 *
 * Copyright © 2022 Silicondust USA Inc. <www.silicondust.com>.
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define HDHOMERUN_SOCK_NETLINK_BUFFER_SIZE 32768

struct nlmsghdr_ifaddrmsg {
	struct nlmsghdr nlh;
	struct ifaddrmsg msg;
};

static void hdhomerun_local_ip_info2_newaddr(int af_sock, struct nlmsghdr *hdr, hdhomerun_local_ip_info2_callback_t callback, void *callback_arg)
{
	struct ifaddrmsg *addrmsg = (struct ifaddrmsg *)NLMSG_DATA(hdr);

	if ((addrmsg->ifa_family != AF_INET) && (addrmsg->ifa_family != AF_INET6)) {
		return;
	}

	if ((addrmsg->ifa_family == AF_INET6) && (addrmsg->ifa_flags & IFA_F_TEMPORARY)) {
		return; /* skip temporary IPv6 addresses */
	}

	/* ifindex */
	uint32_t ifindex = addrmsg->ifa_index;
	if (ifindex == 0) {
		return;
	}

	/* interface flags */
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if (!if_indextoname(ifindex, ifr.ifr_name)) {
		return;
	}

	if (ioctl(af_sock, SIOCGIFFLAGS, &ifr) < 0) {
		return;
	}

	if ((ifr.ifr_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) != 0) {
		return;
	}
	if ((ifr.ifr_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
		return;
	}
	if ((addrmsg->ifa_family == AF_INET6) && ((ifr.ifr_flags & IFF_MULTICAST) == 0)) {
		return;
	}

	/* addresses */
	size_t ifa_payload_length = IFA_PAYLOAD(hdr);
	struct rtattr *rta = IFA_RTA(addrmsg);
	while (1) {
		if (!RTA_OK(rta, ifa_payload_length)) {
			break;
		}

		if (rta->rta_type != IFA_ADDRESS) {
			rta = RTA_NEXT(rta, ifa_payload_length);
			continue;
		}

		uint8_t cidr = (uint8_t)addrmsg->ifa_prefixlen;
		uint8_t cidr_fail = (addrmsg->ifa_family == AF_INET6) ? 128 : 32;
		if ((cidr == 0) || (cidr >= cidr_fail)) {
			rta = RTA_NEXT(rta, ifa_payload_length);
			continue;
		}

		if (addrmsg->ifa_family == AF_INET) {
			struct sockaddr_in local_ip;
			memset(&local_ip, 0, sizeof(local_ip));

			local_ip.sin_family = AF_INET;
			memcpy(&local_ip.sin_addr.s_addr, RTA_DATA(rta), 4);

			if (!hdhomerun_sock_sockaddr_is_addr((const struct sockaddr *)&local_ip)) {
				rta = RTA_NEXT(rta, ifa_payload_length);
				continue;
			}

			callback(callback_arg, ifindex, (const struct sockaddr *)&local_ip, cidr);
		}

		if (addrmsg->ifa_family == AF_INET6) {
			struct sockaddr_in6 local_ip;
			memset(&local_ip, 0, sizeof(local_ip));

			local_ip.sin6_family = AF_INET6;
			memcpy(local_ip.sin6_addr.s6_addr, RTA_DATA(rta), 16);

			if (!hdhomerun_sock_sockaddr_is_addr((const struct sockaddr *)&local_ip)) {
				rta = RTA_NEXT(rta, ifa_payload_length);
				continue;
			}

			if ((local_ip.sin6_addr.s6_addr[0] == 0xFE) && ((local_ip.sin6_addr.s6_addr[1] & 0xC0) == 0x80)) {
				local_ip.sin6_scope_id = ifindex;
			}

			callback(callback_arg, ifindex, (const struct sockaddr *)&local_ip, cidr);
		}

		rta = RTA_NEXT(rta, ifa_payload_length);
	}
}

bool hdhomerun_local_ip_info2(int af, hdhomerun_local_ip_info2_callback_t callback, void *callback_arg)
{
	uint8_t *nl_buffer = (uint8_t *)malloc(HDHOMERUN_SOCK_NETLINK_BUFFER_SIZE);
	if (!nl_buffer) {
		return false;
	}

	int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	int af_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if ((nl_sock == -1) || (af_sock == -1)) {
		close(af_sock);
		close(nl_sock);
		free(nl_buffer);
		return false;
	}

	struct nlmsghdr_ifaddrmsg req;
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(req)));
	req.nlh.nlmsg_type = RTM_GETADDR;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
	req.msg.ifa_family = af;

	if (send(nl_sock, &req, req.nlh.nlmsg_len, 0) != (ssize_t)req.nlh.nlmsg_len) {
		close(af_sock);
		close(nl_sock);
		free(nl_buffer);
		return false;
	}

	bool again = true;
	while (1) {
		struct pollfd poll_fds[1];
		poll_fds[0].fd = nl_sock;
		poll_fds[0].events = POLLIN;
		poll_fds[0].revents = 0;

		int ret = poll(poll_fds, 1, 25);
		if (ret <= 0) {
			break;
		}
		if ((poll_fds[0].revents & POLLIN) == 0) {
			break;
		}

		int length = (int)recv(nl_sock, nl_buffer, HDHOMERUN_SOCK_NETLINK_BUFFER_SIZE, 0);
		if (length <= 0) {
			break;
		}

		struct nlmsghdr *hdr = (struct nlmsghdr *)nl_buffer;
		while (1) {
			if (!NLMSG_OK(hdr, (unsigned int)length)) {
				break;
			}

			if (hdr->nlmsg_type == NLMSG_DONE) {
				again = false;
				break;
			}

			if (hdr->nlmsg_type == NLMSG_ERROR) {
				again = false;
				break;
			}

			if (hdr->nlmsg_type == RTM_NEWADDR) {
				hdhomerun_local_ip_info2_newaddr(af_sock, hdr, callback, callback_arg);
			}

			hdr = NLMSG_NEXT(hdr, length);
		}

		if (!again) {
			break;
		}
	}

	close(af_sock);
	close(nl_sock);
	free(nl_buffer);
	return true;
}
