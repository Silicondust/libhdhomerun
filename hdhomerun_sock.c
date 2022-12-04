/*
 * hdhomerun_sock.c
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

#if defined(_WIN32)
#include <netioapi.h>
#else
#include <net/if.h>
#endif

#if defined(_WINRT)
static inline uint32_t if_nametoindex(const char *ifname) { return 0; }
#endif

bool hdhomerun_sock_sockaddr_is_addr(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET6) {
		static uint8_t hdhomerun_sock_ipv6_zero_bytes[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)addr;
		return (memcmp(addr_in6->sin6_addr.s6_addr, hdhomerun_sock_ipv6_zero_bytes, 16) != 0);
	}

	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
		return (addr_in->sin_addr.s_addr != 0);
	}

	return false;
}

bool hdhomerun_sock_sockaddr_is_multicast(const struct sockaddr *ip_addr)
{
	if (ip_addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)ip_addr;
		return (addr_in6->sin6_addr.s6_addr[0] == 0xFF);
	}

	if (ip_addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr_in = (const struct sockaddr_in *)ip_addr;
		uint32_t v = ntohl(addr_in->sin_addr.s_addr);
		return (v >= 0xE0000000) && (v < 0xF0000000);
	}

	return false;
}

bool hdhomerun_sock_sockaddr_is_ipv4_localhost(const struct sockaddr *ip_addr)
{
	if (ip_addr->sa_family != AF_INET) {
		return false;
	}

	const struct sockaddr_in *sock_addr_in = (const struct sockaddr_in *)ip_addr;
	uint8_t *addr_bytes = (uint8_t *)&sock_addr_in->sin_addr.s_addr;
	return (addr_bytes[0] == 0x7F);
}

bool hdhomerun_sock_sockaddr_is_ipv4_autoip(const struct sockaddr *ip_addr)
{
	if (ip_addr->sa_family != AF_INET) {
		return false;
	}

	const struct sockaddr_in *sock_addr_in = (const struct sockaddr_in *)ip_addr;
	uint8_t *addr_bytes = (uint8_t *)&sock_addr_in->sin_addr.s_addr;
	return (addr_bytes[0] == 169) && (addr_bytes[1] == 254);
}

bool hdhomerun_sock_sockaddr_is_ipv6_localhost(const struct sockaddr *ip_addr)
{
	if (ip_addr->sa_family != AF_INET6) {
		return false;
	}

	const struct sockaddr_in6 *sock_addr_in6 = (const struct sockaddr_in6 *)ip_addr;
	uint8_t *addr_bytes = (uint8_t *)sock_addr_in6->sin6_addr.s6_addr;

	static uint8_t hdhomerun_discover_ipv6_localhost_bytes[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	return (memcmp(addr_bytes, hdhomerun_discover_ipv6_localhost_bytes, 16) == 0);
}

bool hdhomerun_sock_sockaddr_is_ipv6_linklocal(const struct sockaddr *addr)
{
	if (addr->sa_family != AF_INET6) {
		return false;
	}

	const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)addr;
	uint8_t *addr_bytes = (uint8_t *)addr_in6->sin6_addr.s6_addr;
	return (addr_bytes[0] == 0xFE) && ((addr_bytes[1] & 0xC0) == 0x80);
}

bool hdhomerun_sock_sockaddr_is_ipv6_global(const struct sockaddr *ip_addr)
{
	if (ip_addr->sa_family != AF_INET6) {
		return false;
	}

	const struct sockaddr_in6 *sock_addr_in6 = (const struct sockaddr_in6 *)ip_addr;
	uint8_t *addr_bytes = (uint8_t *)sock_addr_in6->sin6_addr.s6_addr;
	return ((addr_bytes[0] & 0xE0) == 0x20);
}

uint16_t hdhomerun_sock_sockaddr_get_port(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)addr;
		return ntohs(addr_in6->sin6_port);
	}

	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
		return ntohs(addr_in->sin_port);
	}

	return 0;
}

void hdhomerun_sock_sockaddr_set_port(struct sockaddr *addr, uint16_t port)
{
	if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		addr_in6->sin6_port = htons(port);
		return;
	}

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_port = htons(port);
		return;
	}
}

void hdhomerun_sock_sockaddr_copy(struct sockaddr_storage *result, const struct sockaddr *addr)
{
	memset(result, 0, sizeof(struct sockaddr_storage));

	if (addr->sa_family == AF_INET6) {
		memcpy(result, addr, sizeof(struct sockaddr_in6));
	}

	if (addr->sa_family == AF_INET) {
		memcpy(result, addr, sizeof(struct sockaddr_in));
	}
}

void hdhomerun_sock_sockaddr_to_ip_str(char ip_str[64], const struct sockaddr *ip_addr, bool include_ipv6_scope_id)
{
	size_t ip_str_size = 64;

	if (ip_addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *ip_addr_in6 = (const struct sockaddr_in6 *)ip_addr;
		inet_ntop(AF_INET6, ip_addr_in6->sin6_addr.s6_addr, ip_str, ip_str_size);
		if (include_ipv6_scope_id && (ip_addr_in6->sin6_scope_id != 0)) {
			hdhomerun_sprintf(strchr(ip_str, 0), ip_str + ip_str_size, "%%%u", ip_addr_in6->sin6_scope_id);
		}
		return;
	}

	if (ip_addr->sa_family == AF_INET) {
		const struct sockaddr_in *ip_addr_in = (const struct sockaddr_in *)ip_addr;
		inet_ntop(AF_INET, &ip_addr_in->sin_addr.s_addr, ip_str, ip_str_size);
		return;
	}

	ip_str[0] = 0;
}

bool hdhomerun_sock_ip_str_to_sockaddr(const char *ip_str, struct sockaddr_storage *result)
{
	memset(result, 0, sizeof(struct sockaddr_storage));

	struct sockaddr_in *result_in = (struct sockaddr_in *)result;
	if (inet_pton(AF_INET, ip_str, &result_in->sin_addr) == 1) {
		result_in->sin_family = AF_INET;
		return true;
	}

	bool framed = (*ip_str == '[');
	bool ifname_present = (strchr(ip_str, '%') != NULL);

	if (!framed && !ifname_present) {
		struct sockaddr_in6 *result_in6 = (struct sockaddr_in6 *)result;
		if (inet_pton(AF_INET6, ip_str, &result_in6->sin6_addr) == 1) {
			result_in6->sin6_family = AF_INET6;
			return true;
		}
		return false;
	}

	if (framed) {
		ip_str++;
	}

	char ip_str_tmp[64];
	if (!hdhomerun_sprintf(ip_str_tmp, ip_str_tmp + sizeof(ip_str_tmp), "%s", ip_str)) {
		return false;
	}

	if (framed) {
		char *end = strchr(ip_str_tmp, ']');
		if (!end) {
			return false;
		}

		*end++ = 0;
		if (*end) {
			return false;
		}
	}

	char *ifname = NULL;
	if (ifname_present) {
		ifname = strchr(ip_str_tmp, '%');
		*ifname++ = 0;
	}

	struct sockaddr_in6 *result_in6 = (struct sockaddr_in6 *)result;
	if (inet_pton(AF_INET6, ip_str_tmp, &result_in6->sin6_addr) != 1) {
		return false;
	}
	result_in6->sin6_family = AF_INET6;

	if (!ifname_present) {
		return true;
	}

	char *end;
	result_in6->sin6_scope_id = (uint32_t)strtoul(ifname, &end, 10);
	if ((result_in6->sin6_scope_id > 0) && (*end == 0)) {
		return true;
	}

	result_in6->sin6_scope_id = if_nametoindex(ifname);
	return (result_in6->sin6_scope_id > 0);
}

struct hdhomerun_local_ip_info_state_t {
	struct hdhomerun_local_ip_info_t *ip_info;
	int max_count;
	int count;
};

static void hdhomerun_local_ip_info_callback(void *arg, uint32_t ifindex, const struct sockaddr *local_ip, uint8_t cidr)
{
	struct hdhomerun_local_ip_info_state_t *state = (struct hdhomerun_local_ip_info_state_t *)arg;

	if (state->count >= state->max_count) {
		state->count++;
		return;
	}

	const struct sockaddr_in *local_ip_in = (const struct sockaddr_in *)local_ip;
	state->ip_info->ip_addr = ntohl(local_ip_in->sin_addr.s_addr);
	state->ip_info->subnet_mask = 0xFFFFFFFF << (32 - cidr);
	state->ip_info++;
	state->count++;
}

int hdhomerun_local_ip_info(struct hdhomerun_local_ip_info_t ip_info_list[], int max_count)
{
	struct hdhomerun_local_ip_info_state_t state;
	state.ip_info = ip_info_list;
	state.max_count = max_count;
	state.count = 0;

	if (!hdhomerun_local_ip_info2(AF_INET, hdhomerun_local_ip_info_callback, &state)) {
		return -1;
	}

	return state.count;
}

struct hdhomerun_sock_t *hdhomerun_sock_create_udp(void)
{
	return hdhomerun_sock_create_udp_ex(AF_INET);
}

struct hdhomerun_sock_t *hdhomerun_sock_create_tcp(void)
{
	return hdhomerun_sock_create_tcp_ex(AF_INET);
}

uint32_t hdhomerun_sock_getsockname_addr(struct hdhomerun_sock_t *sock)
{
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));

	if (!hdhomerun_sock_getsockname_addr_ex(sock, &sock_addr)) {
		return 0;
	}
	if (sock_addr.ss_family != AF_INET) {
		return 0;
	}

	struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
	return ntohl(sock_addr_in->sin_addr.s_addr);
}

uint32_t hdhomerun_sock_getpeername_addr(struct hdhomerun_sock_t *sock)
{
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));

	if (!hdhomerun_sock_getpeername_addr_ex(sock, &sock_addr)) {
		return 0;
	}
	if (sock_addr.ss_family != AF_INET) {
		return 0;
	}

	struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
	return ntohl(sock_addr_in->sin_addr.s_addr);
}

uint32_t hdhomerun_sock_getaddrinfo_addr(struct hdhomerun_sock_t *sock, const char *name)
{
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));

	if (!hdhomerun_sock_getaddrinfo_addr_ex(AF_INET, name, &sock_addr)) {
		return 0;
	}
	if (sock_addr.ss_family != AF_INET) {
		return 0;
	}

	struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
	return ntohl(sock_addr_in->sin_addr.s_addr);
}

bool hdhomerun_sock_getaddrinfo_addr_ex(int af, const char *name, struct sockaddr_storage *result)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *sock_info;
	if (getaddrinfo(name, NULL, &hints, &sock_info) != 0) {
		return false;
	}

	if ((size_t)sock_info->ai_addrlen > sizeof(struct sockaddr_storage)) {
		return false;
	}

	memcpy(result, sock_info->ai_addr, sock_info->ai_addrlen);
	freeaddrinfo(sock_info);
	return true;
}

bool hdhomerun_sock_join_multicast_group(struct hdhomerun_sock_t *sock, uint32_t multicast_ip, uint32_t local_ip)
{
	struct sockaddr_in multicast_addr;
	memset(&multicast_addr, 0, sizeof(multicast_addr));
	multicast_addr.sin_family = AF_INET;
	multicast_addr.sin_addr.s_addr = htonl(multicast_ip);

	struct sockaddr_in local_addr;
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(local_ip);

	return hdhomerun_sock_join_multicast_group_ex(sock, (const struct sockaddr *)&multicast_addr, (const struct sockaddr *)&local_addr);
}

bool hdhomerun_sock_leave_multicast_group(struct hdhomerun_sock_t *sock, uint32_t multicast_ip, uint32_t local_ip)
{
	struct sockaddr_in multicast_addr;
	memset(&multicast_addr, 0, sizeof(multicast_addr));
	multicast_addr.sin_family = AF_INET;
	multicast_addr.sin_addr.s_addr = htonl(multicast_ip);

	struct sockaddr_in local_addr;
	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(local_ip);

	return hdhomerun_sock_leave_multicast_group_ex(sock, (const struct sockaddr *)&multicast_addr, (const struct sockaddr *)&local_addr);
}

bool hdhomerun_sock_bind(struct hdhomerun_sock_t *sock, uint32_t local_addr, uint16_t local_port, bool allow_reuse)
{
	struct sockaddr_in sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = htonl(local_addr);
	sock_addr.sin_port = htons(local_port);

	return hdhomerun_sock_bind_ex(sock, (const struct sockaddr *)&sock_addr, allow_reuse);
}

bool hdhomerun_sock_connect(struct hdhomerun_sock_t *sock, uint32_t remote_addr, uint16_t remote_port, uint64_t timeout)
{
	struct sockaddr_in sock_addr_in;
	memset(&sock_addr_in, 0, sizeof(sock_addr_in));

	sock_addr_in.sin_family = AF_INET;
	sock_addr_in.sin_addr.s_addr = htonl(remote_addr);
	sock_addr_in.sin_port = htons(remote_port);

	return hdhomerun_sock_connect_ex(sock, (const struct sockaddr *)&sock_addr_in, timeout);
}

bool hdhomerun_sock_sendto(struct hdhomerun_sock_t *sock, uint32_t remote_addr, uint16_t remote_port, const void *data, size_t length, uint64_t timeout)
{
	struct sockaddr_in sock_addr_in;
	memset(&sock_addr_in, 0, sizeof(sock_addr_in));

	sock_addr_in.sin_family = AF_INET;
	sock_addr_in.sin_addr.s_addr = htonl(remote_addr);
	sock_addr_in.sin_port = htons(remote_port);

	return hdhomerun_sock_sendto_ex(sock, (const struct sockaddr *)&sock_addr_in, data, length, timeout);
}

bool hdhomerun_sock_recvfrom(struct hdhomerun_sock_t *sock, uint32_t *remote_addr, uint16_t *remote_port, void *data, size_t *length, uint64_t timeout)
{
	struct sockaddr_storage sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));

	if (!hdhomerun_sock_recvfrom_ex(sock, &sock_addr, data, length, timeout)) {
		return false;
	}
	if (sock_addr.ss_family != AF_INET) {
		return false;
	}

	struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
	*remote_addr = ntohl(sock_addr_in->sin_addr.s_addr);
	*remote_port = ntohs(sock_addr_in->sin_port);
	return true;
}
