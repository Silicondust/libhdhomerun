/*
 * hdhomerun_sock_windows.c
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
#include <iphlpapi.h>

struct hdhomerun_sock_t {
	SOCKET sock;
	HANDLE event;
	long events_selected;
	int af;
	uint8_t ttl_set;
};

bool hdhomerun_local_ip_info2(int af, hdhomerun_local_ip_info2_callback_t callback, void *callback_arg)
{
	IP_ADAPTER_ADDRESSES *adapter_addresses;
	ULONG adapter_addresses_length = sizeof(IP_ADAPTER_ADDRESSES) * 16;

	while (1) {
		adapter_addresses = (IP_ADAPTER_ADDRESSES *)malloc(adapter_addresses_length);
		if (!adapter_addresses) {
			return false;
		}

		ULONG length_needed = adapter_addresses_length;
		DWORD ret = GetAdaptersAddresses(af, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, adapter_addresses, &length_needed);
		if (ret == NO_ERROR) {
			break;
		}

		free(adapter_addresses);

		if (ret != ERROR_BUFFER_OVERFLOW) {
			return false;
		}
		if (adapter_addresses_length >= length_needed) {
			return false;
		}

		adapter_addresses_length = length_needed;
	}

	IP_ADAPTER_ADDRESSES *adapter = adapter_addresses;

	while (adapter) {
		if (adapter->OperStatus != 1) {
			adapter = adapter->Next;
			continue;
		}

		if ((adapter->IfType != MIB_IF_TYPE_ETHERNET) && (adapter->IfType != IF_TYPE_IEEE80211)) {
			adapter = adapter->Next;
			continue;
		}

		if (adapter->PhysicalAddressLength != 6) {
			adapter = adapter->Next;
			continue;
		}

		uint32_t ifindex = adapter->IfIndex;
		if (ifindex == 0) {
			adapter = adapter->Next;
			continue;
		}

		IP_ADAPTER_UNICAST_ADDRESS *adapter_address = adapter->FirstUnicastAddress;
		while (adapter_address) {
			struct sockaddr *local_ip = adapter_address->Address.lpSockaddr;
			if (!hdhomerun_sock_sockaddr_is_addr(local_ip)) {
				adapter_address = adapter_address->Next;
				continue;
			}

			if (adapter_address->Flags & IP_ADAPTER_ADDRESS_TRANSIENT) {
				adapter_address = adapter_address->Next;
				continue;
			}

			uint8_t cidr = adapter_address->OnLinkPrefixLength;
			uint8_t cidr_fail = (local_ip->sa_family == AF_INET6) ? 128 : 32;
			if ((cidr == 0) || (cidr >= cidr_fail)) {
				adapter_address = adapter_address->Next;
				continue;
			}

			callback(callback_arg, ifindex, local_ip, cidr);

			adapter_address = adapter_address->Next;
		}

		adapter = adapter->Next;
	}

	free(adapter_addresses);
	return true;
}

static struct hdhomerun_sock_t *hdhomerun_sock_create_internal(int af, int protocol)
{
	struct hdhomerun_sock_t *sock = (struct hdhomerun_sock_t *)calloc(1, sizeof(struct hdhomerun_sock_t));
	if (!sock) {
		return NULL;
	}

	sock->af = af;

	/* Create socket. */
	sock->sock = socket(af, protocol, 0);
	if (sock->sock == INVALID_SOCKET) {
		free(sock);
		return NULL;
	}

	/* Set non-blocking */
	unsigned long mode = 1;
	if (ioctlsocket(sock->sock, FIONBIO, &mode) != 0) {
		hdhomerun_sock_destroy(sock);
		return NULL;
	}

	/* Set ipv6 */
	if (af == AF_INET6) {
		int sock_opt_ipv6only = 1;
		setsockopt(sock->sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&sock_opt_ipv6only, sizeof(sock_opt_ipv6only));
	}

	/* Event */
	sock->event = CreateEvent(NULL, false, false, NULL);
	if (!sock->event) {
		hdhomerun_sock_destroy(sock);
		return NULL;
	}

	/* Success. */
	return sock;
}

struct hdhomerun_sock_t *hdhomerun_sock_create_udp_ex(int af)
{
	struct hdhomerun_sock_t *sock = hdhomerun_sock_create_internal(af, SOCK_DGRAM);
	if (!sock) {
		return NULL;
	}

	/* Allow broadcast. */
	int sock_opt = 1;
	setsockopt(sock->sock, SOL_SOCKET, SO_BROADCAST, (char *)&sock_opt, sizeof(sock_opt));

	/* Success. */
	return sock;
}

struct hdhomerun_sock_t *hdhomerun_sock_create_tcp_ex(int af)
{
	return hdhomerun_sock_create_internal(af, SOCK_STREAM);
}

void hdhomerun_sock_destroy(struct hdhomerun_sock_t *sock)
{
	if (sock->event) {
		CloseHandle(sock->event);
	}

	closesocket(sock->sock);
	free(sock);
}

void hdhomerun_sock_stop(struct hdhomerun_sock_t *sock)
{
	shutdown(sock->sock, SD_BOTH);
}

void hdhomerun_sock_set_send_buffer_size(struct hdhomerun_sock_t *sock, size_t size)
{
	int size_opt = (int)size;
	setsockopt(sock->sock, SOL_SOCKET, SO_SNDBUF, (char *)&size_opt, sizeof(size_opt));
}

void hdhomerun_sock_set_recv_buffer_size(struct hdhomerun_sock_t *sock, size_t size)
{
	int size_opt = (int)size;
	setsockopt(sock->sock, SOL_SOCKET, SO_RCVBUF, (char *)&size_opt, sizeof(size_opt));
}

void hdhomerun_sock_set_allow_reuse(struct hdhomerun_sock_t *sock)
{
	int sock_opt = 1;
	setsockopt(sock->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt, sizeof(sock_opt));
}

void hdhomerun_sock_set_ttl(struct hdhomerun_sock_t *sock, uint8_t ttl)
{
	if (sock->ttl_set == ttl) {
		return;
	}

	int sock_opt = (int)(unsigned int)ttl;
	if (sock->af == AF_INET) {
		setsockopt(sock->sock, IPPROTO_IP, IP_TTL, (char *)&sock_opt, sizeof(sock_opt));
	}
	if (sock->af == AF_INET6) {
		setsockopt(sock->sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&sock_opt, sizeof(sock_opt));
	}

	sock->ttl_set = ttl;
}

void hdhomerun_sock_set_ipv4_onesbcast(struct hdhomerun_sock_t *sock, int v)
{
}

void hdhomerun_sock_set_ipv6_multicast_ifindex(struct hdhomerun_sock_t *sock, uint32_t ifindex)
{
	setsockopt(sock->sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char *)&ifindex, sizeof(ifindex));
}

int hdhomerun_sock_getlasterror(void)
{
	return WSAGetLastError();
}

bool hdhomerun_sock_getsockname_addr_ex(struct hdhomerun_sock_t *sock, struct sockaddr_storage *result)
{
	socklen_t sockaddr_size = sizeof(struct sockaddr_storage);
	return (getsockname(sock->sock, (struct sockaddr *)result, &sockaddr_size) == 0);
}

uint16_t hdhomerun_sock_getsockname_port(struct hdhomerun_sock_t *sock)
{
	struct sockaddr_storage sock_addr;
	socklen_t sockaddr_size = sizeof(sock_addr);

	if (getsockname(sock->sock, (struct sockaddr *)&sock_addr, &sockaddr_size) != 0) {
		return 0;
	}

	if (sock_addr.ss_family == AF_INET) {
		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&sock_addr;
		return ntohs(sock_addr_in->sin_port);
	}
	if (sock_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *sock_addr_in = (struct sockaddr_in6 *)&sock_addr;
		return ntohs(sock_addr_in->sin6_port);
	}
	return 0;
}

bool hdhomerun_sock_getpeername_addr_ex(struct hdhomerun_sock_t *sock, struct sockaddr_storage *result)
{
	socklen_t sockaddr_size = sizeof(struct sockaddr_storage);
	return (getpeername(sock->sock, (struct sockaddr *)result, &sockaddr_size) == 0);
}

bool hdhomerun_sock_join_multicast_group_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *multicast_addr, const struct sockaddr *local_addr)
{
	if (multicast_addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *multicast_addr_in = (const struct sockaddr_in6 *)multicast_addr;

		struct ipv6_mreq imr;
		memset(&imr, 0, sizeof(imr));
		memcpy(imr.ipv6mr_multiaddr.s6_addr, multicast_addr_in->sin6_addr.s6_addr, 16);
		imr.ipv6mr_interface = multicast_addr_in->sin6_scope_id;

		if (setsockopt(sock->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (const char *)&imr, sizeof(imr)) != 0) {
			return false;
		}

		return true;
	}

	if (multicast_addr->sa_family == AF_INET) {
		const struct sockaddr_in *multicast_addr_in = (const struct sockaddr_in *)multicast_addr;
		const struct sockaddr_in *local_addr_in = (const struct sockaddr_in *)local_addr;

		struct ip_mreq imr;
		memset(&imr, 0, sizeof(imr));
		imr.imr_multiaddr.s_addr = multicast_addr_in->sin_addr.s_addr;
		imr.imr_interface.s_addr = (local_addr->sa_family == AF_INET) ? local_addr_in->sin_addr.s_addr : 0;

		if (setsockopt(sock->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&imr, sizeof(imr)) != 0) {
			return false;
		}

		return true;
	}

	return false;
}

bool hdhomerun_sock_leave_multicast_group_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *multicast_addr, const struct sockaddr *local_addr)
{
	if (multicast_addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *multicast_addr_in = (const struct sockaddr_in6 *)multicast_addr;

		struct ipv6_mreq imr;
		memset(&imr, 0, sizeof(imr));
		memcpy(imr.ipv6mr_multiaddr.s6_addr, multicast_addr_in->sin6_addr.s6_addr, 16);
		imr.ipv6mr_interface = multicast_addr_in->sin6_scope_id;

		if (setsockopt(sock->sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, (const char *)&imr, sizeof(imr)) != 0) {
			return false;
		}

		return true;
	}

	if (multicast_addr->sa_family == AF_INET) {
		const struct sockaddr_in *multicast_addr_in = (const struct sockaddr_in *)multicast_addr;
		const struct sockaddr_in *local_addr_in = (const struct sockaddr_in *)local_addr;

		struct ip_mreq imr;
		memset(&imr, 0, sizeof(imr));
		imr.imr_multiaddr.s_addr = multicast_addr_in->sin_addr.s_addr;
		imr.imr_interface.s_addr = (local_addr->sa_family == AF_INET) ? local_addr_in->sin_addr.s_addr : 0;

		if (setsockopt(sock->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char *)&imr, sizeof(imr)) != 0) {
			return false;
		}

		return true;
	}

	return false;
}

bool hdhomerun_sock_bind_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *local_addr, bool allow_reuse)
{
	socklen_t local_addr_size;
	switch (local_addr->sa_family) {
	case AF_INET6:
		local_addr_size = (socklen_t)sizeof(struct sockaddr_in6);
		break;
	case AF_INET:
		local_addr_size = (socklen_t)sizeof(struct sockaddr_in);
		break;
	default:
		return false;
	}

	int sock_opt = allow_reuse;
	setsockopt(sock->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&sock_opt, sizeof(sock_opt));

	if (bind(sock->sock, (const struct sockaddr *)local_addr, local_addr_size) != 0) {
		return false;
	}

	return true;
}

static bool hdhomerun_sock_event_select(struct hdhomerun_sock_t *sock, long events)
{
	if (sock->events_selected != events) {
		if (WSAEventSelect(sock->sock, sock->event, events) == SOCKET_ERROR) {
			return false;
		}
		sock->events_selected = events;
	}

	ResetEvent(sock->event);
	return true;
}

bool hdhomerun_sock_connect_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *remote_addr, uint64_t timeout)
{
	socklen_t remote_addr_size;
	switch (remote_addr->sa_family) {
	case AF_INET6:
		remote_addr_size = (socklen_t)sizeof(struct sockaddr_in6);
		break;
	case AF_INET:
		remote_addr_size = (socklen_t)sizeof(struct sockaddr_in);
		break;
	default:
		return false;
	}

	if (!hdhomerun_sock_event_select(sock, FD_WRITE | FD_CLOSE)) {
		return false;
	}

	if (connect(sock->sock, remote_addr, remote_addr_size) != 0) {
		if (WSAGetLastError() != WSAEWOULDBLOCK) {
			return false;
		}
	}

	DWORD wait_ret = WaitForSingleObjectEx(sock->event, (DWORD)timeout, false);
	if (wait_ret != WAIT_OBJECT_0) {
		return false;
	}

	WSANETWORKEVENTS network_events;
	if (WSAEnumNetworkEvents(sock->sock, sock->event, &network_events) == SOCKET_ERROR) {
		return false;
	}
	if ((network_events.lNetworkEvents & FD_WRITE) == 0) {
		return false;
	}
	if (network_events.lNetworkEvents & FD_CLOSE) {
		return false;
	}

	return true;
}

bool hdhomerun_sock_send(struct hdhomerun_sock_t *sock, const void *data, size_t length, uint64_t timeout)
{
	if (!hdhomerun_sock_event_select(sock, FD_WRITE | FD_CLOSE)) {
		return false;
	}

	uint64_t stop_time = getcurrenttime() + timeout;
	const uint8_t *ptr = (uint8_t *)data;

	while (1) {
		int ret = send(sock->sock, (char *)ptr, (int)length, 0);
		if (ret >= (int)length) {
			return true;
		}

		if ((ret == SOCKET_ERROR) && (WSAGetLastError() != WSAEWOULDBLOCK)) {
			return false;
		}

		if (ret > 0) {
			ptr += ret;
			length -= ret;
		}

		uint64_t current_time = getcurrenttime();
		if (current_time >= stop_time) {
			return false;
		}

		if (WaitForSingleObjectEx(sock->event, (DWORD)(stop_time - current_time), false) != WAIT_OBJECT_0) {
			return false;
		}
	}
}

bool hdhomerun_sock_sendto_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *remote_addr, const void *data, size_t length, uint64_t timeout)
{
	socklen_t remote_addr_size;
	switch (remote_addr->sa_family) {
	case AF_INET6:
		remote_addr_size = (socklen_t)sizeof(struct sockaddr_in6);
		break;
	case AF_INET:
		remote_addr_size = (socklen_t)sizeof(struct sockaddr_in);
		break;
	default:
		return false;
	}

	if (!hdhomerun_sock_event_select(sock, FD_WRITE | FD_CLOSE)) {
		return false;
	}

	int ret = sendto(sock->sock, (char *)data, (int)length, 0, remote_addr, remote_addr_size);
	if (ret >= (int)length) {
		return true;
	}

	if (ret >= 0) {
		return false;
	}
	if (WSAGetLastError() != WSAEWOULDBLOCK) {
		return false;
	}

	if (WaitForSingleObjectEx(sock->event, (DWORD)timeout, false) != WAIT_OBJECT_0) {
		return false;
	}

	ret = sendto(sock->sock, (char *)data, (int)length, 0, remote_addr, remote_addr_size);
	if (ret >= (int)length) {
		return true;
	}

	return false;
}

bool hdhomerun_sock_recv(struct hdhomerun_sock_t *sock, void *data, size_t *length, uint64_t timeout)
{
	if (!hdhomerun_sock_event_select(sock, FD_READ | FD_CLOSE)) {
		return false;
	}

	int ret = recv(sock->sock, (char *)data, (int)(*length), 0);
	if (ret > 0) {
		*length = ret;
		return true;
	}

	if (ret == 0) {
		return false;
	}
	if (WSAGetLastError() != WSAEWOULDBLOCK) {
		return false;
	}

	if (WaitForSingleObjectEx(sock->event, (DWORD)timeout, false) != WAIT_OBJECT_0) {
		return false;
	}

	ret = recv(sock->sock, (char *)data, (int)(*length), 0);
	if (ret > 0) {
		*length = ret;
		return true;
	}

	return false;
}

bool hdhomerun_sock_recvfrom_ex(struct hdhomerun_sock_t *sock, struct sockaddr_storage *remote_addr, void *data, size_t *length, uint64_t timeout)
{
	if (!hdhomerun_sock_event_select(sock, FD_READ | FD_CLOSE)) {
		return false;
	}

	socklen_t sockaddr_size = sizeof(struct sockaddr_storage);
	int ret = recvfrom(sock->sock, (char *)data, (int)(*length), 0, (struct sockaddr *)remote_addr, &sockaddr_size);
	if (ret > 0) {
		*length = ret;
		return true;
	}

	if (ret == 0) {
		return false;
	}
	if (WSAGetLastError() != WSAEWOULDBLOCK) {
		return false;
	}

	if (WaitForSingleObjectEx(sock->event, (DWORD)timeout, false) != WAIT_OBJECT_0) {
		return false;
	}

	ret = recvfrom(sock->sock, (char *)data, (int)(*length), 0, (struct sockaddr *)remote_addr, &sockaddr_size);
	if (ret > 0) {
		*length = ret;
		return true;
	}

	return false;
}
