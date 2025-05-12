/*
 * hdhomerun_discover.c
 *
 * Copyright © 2006-2022 Silicondust USA Inc. <www.silicondust.com>.
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

struct hdhomerun_discover2_device_type_t {
	struct hdhomerun_discover2_device_type_t *next;
	uint32_t device_type;
};

struct hdhomerun_discover2_device_if_t {
	struct hdhomerun_discover2_device_if_t *next;
	struct sockaddr_storage ip_addr;
	char *base_url;
	char *lineup_url;
	char *storage_url;
	uint8_t priority;
};

struct hdhomerun_discover2_device_t {
	struct hdhomerun_discover2_device_t *next;
	struct hdhomerun_discover2_device_if_t *if_list;
	struct hdhomerun_discover2_device_type_t *type_list;
	uint32_t device_id;
	uint8_t tuner_count;
	char *device_auth;
	char *storage_id;
};

struct hdhomerun_discover_sock_t {
	struct hdhomerun_discover_sock_t *next;
	struct hdhomerun_discover_sock_t *recv_next;
	struct hdhomerun_sock_t *sock;
	struct sockaddr_storage local_ip;
	uint32_t ifindex;
	uint32_t ipv4_subnet_mask;
	bool active;
};

struct hdhomerun_discover_t {
	struct hdhomerun_discover2_device_t *device_list;
	struct hdhomerun_discover_sock_t *ipv6_socks;
	struct hdhomerun_discover_sock_t *ipv4_socks;
	struct hdhomerun_discover_sock_t *ipv6_localhost;
	struct hdhomerun_discover_sock_t *ipv4_localhost;
	struct hdhomerun_pkt_t tx_pkt;
	struct hdhomerun_pkt_t rx_pkt;
	struct hdhomerun_debug_t *dbg;
};

static uint8_t hdhomerun_discover_ipv6_linklocal_multicast_ip[16] = { 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x76 };
static uint8_t hdhomerun_discover_ipv6_sitelocal_multicast_ip[16] = { 0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x76 };

static void hdhomerun_discover_sock_free(struct hdhomerun_discover_sock_t *dss)
{
	hdhomerun_sock_destroy(dss->sock);
	free(dss);
}

static uint16_t hdhomerun_discover_get_local_port(struct hdhomerun_discover_t *ds)
{
	if (ds->ipv6_socks) {
		return hdhomerun_sock_getsockname_port(ds->ipv6_socks->sock);
	}
	if (ds->ipv4_socks) {
		return hdhomerun_sock_getsockname_port(ds->ipv4_socks->sock);
	}
	if (ds->ipv6_localhost) {
		return hdhomerun_sock_getsockname_port(ds->ipv6_localhost->sock);
	}
	if (ds->ipv4_localhost) {
		return hdhomerun_sock_getsockname_port(ds->ipv4_localhost->sock);
	}
	return 0;
}

static void hdhomerun_discover_sock_add_ipv6(void *arg, uint32_t ifindex, const struct sockaddr *local_ip, uint8_t cidr)
{
	if (local_ip->sa_family != AF_INET6) {
		return;
	}

	struct hdhomerun_discover_t *ds = (struct hdhomerun_discover_t *)arg;
	struct sockaddr_in6 *local_ip_in6 = (struct sockaddr_in6 *)local_ip;

	char local_ip_str[64];
	hdhomerun_sock_sockaddr_to_ip_str(local_ip_str, local_ip, true);
	if (hdhomerun_sock_sockaddr_is_addr(local_ip)) {
		hdhomerun_debug_printf(ds->dbg, "discover: local ip %s/%u\n", local_ip_str, cidr);
	}

	struct hdhomerun_discover_sock_t **pprev = &ds->ipv6_socks;
	struct hdhomerun_discover_sock_t *p = ds->ipv6_socks;
	while (p) {
		struct sockaddr_in6 *p_ip = (struct sockaddr_in6 *)&p->local_ip;
		if ((p->ifindex == ifindex) && (memcmp(p_ip->sin6_addr.s6_addr, local_ip_in6->sin6_addr.s6_addr, 16) == 0)) {
			p->active = true;
			return;
		}

		pprev = &p->next;
		p = p->next;
	}

	/* Create socket. */
	struct hdhomerun_discover_sock_t *dss = (struct hdhomerun_discover_sock_t *)calloc(1, sizeof(struct hdhomerun_discover_sock_t));
	if (!dss) {
		hdhomerun_debug_printf(ds->dbg, "discover: resource error\n");
		return;
	}

	dss->sock = hdhomerun_sock_create_udp_ex(AF_INET6);
	if (!dss->sock) {
		hdhomerun_debug_printf(ds->dbg, "discover: failed to allocate socket (%d)\n", hdhomerun_sock_getlasterror());
		free(dss);
		return;
	}

	hdhomerun_sock_set_ttl(dss->sock, 64);

	/* Bind socket. */
	local_ip_in6->sin6_port = htons(hdhomerun_discover_get_local_port(ds));

	if (!hdhomerun_sock_bind_ex(dss->sock, local_ip, true)) {
		hdhomerun_debug_printf(ds->dbg, "discover: failed to bind to local ip %s (%d)\n", local_ip_str, hdhomerun_sock_getlasterror());
		hdhomerun_discover_sock_free(dss);
		return;
	}

	/* Success. */
	memcpy(&dss->local_ip, local_ip_in6, sizeof(struct sockaddr_in6));
	dss->ifindex = ifindex;
	dss->active = true;
	*pprev = dss;
}

static void hdhomerun_discover_sock_add_ipv4(void *arg, uint32_t ifindex, const struct sockaddr *local_ip, uint8_t cidr)
{
	if (local_ip->sa_family != AF_INET) {
		return;
	}

	struct hdhomerun_discover_t *ds = (struct hdhomerun_discover_t *)arg;
	struct sockaddr_in *local_ip_in = (struct sockaddr_in *)local_ip;
	uint32_t detected_subnet_mask = 0xFFFFFFFF << (32 - cidr);

	char local_ip_str[64];
	hdhomerun_sock_sockaddr_to_ip_str(local_ip_str, local_ip, true);
	if (hdhomerun_sock_sockaddr_is_addr(local_ip)) {
		hdhomerun_debug_printf(ds->dbg, "discover: local ip %s/%u\n", local_ip_str, cidr);
	}

	struct hdhomerun_discover_sock_t **pprev = &ds->ipv4_socks;
	struct hdhomerun_discover_sock_t *p = ds->ipv4_socks;
	while (p) {
		struct sockaddr_in *p_ip = (struct sockaddr_in *)&p->local_ip;
		if ((p->ifindex == ifindex) && (p_ip->sin_addr.s_addr == local_ip_in->sin_addr.s_addr) && (p->ipv4_subnet_mask == detected_subnet_mask)) {
			p->active = true;
			return;
		}

		pprev = &p->next;
		p = p->next;
	}

	/* Create socket. */
	struct hdhomerun_discover_sock_t *dss = (struct hdhomerun_discover_sock_t *)calloc(1, sizeof(struct hdhomerun_discover_sock_t));
	if (!dss) {
		hdhomerun_debug_printf(ds->dbg, "discover: resource error\n");
		return;
	}

	dss->sock = hdhomerun_sock_create_udp_ex(AF_INET);
	if (!dss->sock) {
		hdhomerun_debug_printf(ds->dbg, "discover: failed to allocate socket (%d)\n", hdhomerun_sock_getlasterror());
		free(dss);
		return;
	}

	hdhomerun_sock_set_ttl(dss->sock, 64);

	/* Bind socket. */
	local_ip_in->sin_port = htons(hdhomerun_discover_get_local_port(ds));

	if (!hdhomerun_sock_bind_ex(dss->sock, local_ip, true)) {
		hdhomerun_debug_printf(ds->dbg, "discover: failed to bind to local ip %s (%d)\n", local_ip_str, hdhomerun_sock_getlasterror());
		hdhomerun_discover_sock_free(dss);
		return;
	}

	/* Success. */
	memcpy(&dss->local_ip, local_ip_in, sizeof(struct sockaddr_in));
	dss->ifindex = ifindex;
	dss->ipv4_subnet_mask = detected_subnet_mask;
	dss->active = true;
	*pprev = dss;
}

static void hdhomerun_discover_device_if_free(struct hdhomerun_discover2_device_if_t *device_if)
{
	if (device_if->base_url) {
		free(device_if->base_url);
	}
	if (device_if->lineup_url) {
		free(device_if->lineup_url);
	}
	if (device_if->storage_url) {
		free(device_if->storage_url);
	}

	free(device_if);
}

static void hdhomerun_discover_device_free(struct hdhomerun_discover2_device_t *device)
{
	while (device->if_list) {
		struct hdhomerun_discover2_device_if_t *device_if = device->if_list;
		device->if_list = device_if->next;
		hdhomerun_discover_device_if_free(device_if);
	}

	while (device->type_list) {
		struct hdhomerun_discover2_device_type_t *device_type = device->type_list;
		device->type_list = device_type->next;
		free(device_type);
	}

	if (device->device_auth) {
		free(device->device_auth);
	}
	if (device->storage_id) {
		free(device->storage_id);
	}

	free(device);
}

static void hdhomerun_discover_free_device_list(struct hdhomerun_discover_t *ds)
{
	while (ds->device_list) {
		struct hdhomerun_discover2_device_t *device = ds->device_list;
		ds->device_list = device->next;
		hdhomerun_discover_device_free(device);
	}
}

void hdhomerun_discover_destroy(struct hdhomerun_discover_t *ds)
{
	hdhomerun_discover_free_device_list(ds);

	while (ds->ipv6_socks) {
		struct hdhomerun_discover_sock_t *dss = ds->ipv6_socks;
		ds->ipv6_socks = dss->next;
		hdhomerun_discover_sock_free(dss);
	}

	while (ds->ipv4_socks) {
		struct hdhomerun_discover_sock_t *dss = ds->ipv4_socks;
		ds->ipv4_socks = dss->next;
		hdhomerun_discover_sock_free(dss);
	}

	free(ds);
}

struct hdhomerun_discover_t *hdhomerun_discover_create(struct hdhomerun_debug_t *dbg)
{
	struct hdhomerun_discover_t *ds = (struct hdhomerun_discover_t *)calloc(1, sizeof(struct hdhomerun_discover_t));
	if (!ds) {
		return NULL;
	}

	ds->dbg = dbg;
	return ds;
}

static void hdhomerun_discover_sock_detect_ipv6(struct hdhomerun_discover_t *ds)
{
	struct hdhomerun_discover_sock_t *default_dss = ds->ipv6_socks;
	if (!default_dss) {
		/* Create a routable socket (always first entry). */
		struct sockaddr_in6 ipv6_addr;
		memset(&ipv6_addr, 0, sizeof(ipv6_addr));
		ipv6_addr.sin6_family = AF_INET6;
		hdhomerun_discover_sock_add_ipv6(ds, 0, (const struct sockaddr *)&ipv6_addr, 0);

		default_dss = ds->ipv6_socks;
		if (!default_dss) {
			return;
		}
	}

	struct hdhomerun_discover_sock_t *p = default_dss->next;
	while (p) {
		p->active = false;
		p = p->next;
	}

	hdhomerun_local_ip_info2(AF_INET6, hdhomerun_discover_sock_add_ipv6, ds);
}

static void hdhomerun_discover_sock_detect_ipv4(struct hdhomerun_discover_t *ds)
{
	struct hdhomerun_discover_sock_t *default_dss = ds->ipv4_socks;
	if (!default_dss) {
		/* Create a routable socket (always first entry). */
		struct sockaddr_in ipv4_addr;
		memset(&ipv4_addr, 0, sizeof(ipv4_addr));
		ipv4_addr.sin_family = AF_INET;
		hdhomerun_discover_sock_add_ipv4(ds, 0, (const struct sockaddr *)&ipv4_addr, 0);

		default_dss = ds->ipv4_socks;
		if (!default_dss) {
			return;
		}
	}

	struct hdhomerun_discover_sock_t *p = default_dss->next;
	while (p) {
		p->active = false;
		p = p->next;
	}

	hdhomerun_local_ip_info2(AF_INET, hdhomerun_discover_sock_add_ipv4, ds);
}

static void hdhomerun_discover_sock_detect_ipv6_localhost(struct hdhomerun_discover_t *ds)
{
	if (ds->ipv6_localhost) {
		return;
	}

	struct hdhomerun_discover_sock_t *dss = (struct hdhomerun_discover_sock_t *)calloc(1, sizeof(struct hdhomerun_discover_sock_t));
	if (!dss) {
		return;
	}

	dss->sock = hdhomerun_sock_create_udp_ex(AF_INET6);
	if (!dss->sock) {
		free(dss);
		return;
	}

	struct sockaddr_in6 *sock_addr = (struct sockaddr_in6 *)&dss->local_ip;
	sock_addr->sin6_family = AF_INET6;
	sock_addr->sin6_addr.s6_addr[15] = 1;
	sock_addr->sin6_port = htons(hdhomerun_discover_get_local_port(ds));

	if (!hdhomerun_sock_bind_ex(dss->sock, (const struct sockaddr *)sock_addr, true)) {
		hdhomerun_discover_sock_free(dss);
		return;
	}

	dss->active = true;
	ds->ipv6_localhost = dss;
}

static void hdhomerun_discover_sock_detect_ipv4_localhost(struct hdhomerun_discover_t *ds)
{
	if (ds->ipv4_localhost) {
		return;
	}

	struct hdhomerun_discover_sock_t *dss = (struct hdhomerun_discover_sock_t *)calloc(1, sizeof(struct hdhomerun_discover_sock_t));
	if (!dss) {
		return;
	}

	dss->sock = hdhomerun_sock_create_udp_ex(AF_INET);
	if (!dss->sock) {
		free(dss);
		return;
	}

	struct sockaddr_in *sock_addr = (struct sockaddr_in *)&dss->local_ip;
	sock_addr->sin_family = AF_INET;
	sock_addr->sin_addr.s_addr = htonl(0x7F000001);
	sock_addr->sin_port = htons(hdhomerun_discover_get_local_port(ds));
	dss->ipv4_subnet_mask = 0xFF000000;

	if (!hdhomerun_sock_bind_ex(dss->sock, (const struct sockaddr *)sock_addr, true)) {
		hdhomerun_discover_sock_free(dss);
		return;
	}

	dss->active = true;
	ds->ipv4_localhost = dss;
}

static void hdhomerun_discover_sock_detect_all_from_flags(struct hdhomerun_discover_t *ds, uint32_t flags)
{
	if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV6_LOCALHOST) {
		hdhomerun_discover_sock_detect_ipv6_localhost(ds);
	}
	if (flags & (HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL)) {
		hdhomerun_discover_sock_detect_ipv6(ds);
	}
	if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV4_LOCALHOST) {
		hdhomerun_discover_sock_detect_ipv4_localhost(ds);
	}
	if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL) {
		hdhomerun_discover_sock_detect_ipv4(ds);
	}
}

static void hdhomerun_discover_sock_flush_list(struct hdhomerun_discover_t *ds, struct hdhomerun_discover_sock_t *list)
{
	struct hdhomerun_pkt_t *rx_pkt = &ds->rx_pkt;
	hdhomerun_pkt_reset(rx_pkt);

	struct hdhomerun_discover_sock_t *dss = list;
	while (dss) {
		if (!dss->active) {
			dss = dss->next;
			continue;
		}

		while (1) {
			struct sockaddr_storage remote_addr;
			size_t length = rx_pkt->limit - rx_pkt->end;
			if (!hdhomerun_sock_recvfrom_ex(dss->sock, &remote_addr, rx_pkt->end, &length, 0)) {
				break;
			}
		}

		dss = dss->next;
	}
}

static void hdhomerun_discover_sock_recv_list_append_list(struct hdhomerun_discover_sock_t **recv_list, struct hdhomerun_discover_sock_t *list)
{
	struct hdhomerun_discover_sock_t *dss = list;
	while (dss) {
		if (!dss->active) {
			dss = dss->next;
			continue;
		}

		dss->recv_next = *recv_list;
		*recv_list = dss;
		dss = dss->next;
	}
}

static bool hdhomerun_discover_send_request(struct hdhomerun_discover_t *ds, struct hdhomerun_discover_sock_t *dss, const struct sockaddr *remote_addr, const uint32_t device_types[], size_t device_types_count, uint32_t device_id)
{
	if (device_types_count == 0) {
		return false;
	}

	struct hdhomerun_pkt_t *tx_pkt = &ds->tx_pkt;
	hdhomerun_pkt_reset(tx_pkt);

	if (device_types_count == 1) {
		hdhomerun_pkt_write_u8(tx_pkt, HDHOMERUN_TAG_DEVICE_TYPE);
		hdhomerun_pkt_write_var_length(tx_pkt, 4);
		hdhomerun_pkt_write_u32(tx_pkt, device_types[0]);
	} else {
		hdhomerun_pkt_write_u8(tx_pkt, HDHOMERUN_TAG_MULTI_TYPE);
		hdhomerun_pkt_write_var_length(tx_pkt, device_types_count * 4);
		while (device_types_count--) {
			hdhomerun_pkt_write_u32(tx_pkt, *device_types++);
		}
	}

	if (device_id != HDHOMERUN_DEVICE_ID_WILDCARD) {
		hdhomerun_pkt_write_u8(tx_pkt, HDHOMERUN_TAG_DEVICE_ID);
		hdhomerun_pkt_write_var_length(tx_pkt, 4);
		hdhomerun_pkt_write_u32(tx_pkt, device_id);
	}

	hdhomerun_pkt_seal_frame(tx_pkt, HDHOMERUN_TYPE_DISCOVER_REQ);

	char local_ip_str[64];
	char remote_ip_str[64];
	hdhomerun_sock_sockaddr_to_ip_str(local_ip_str, (const struct sockaddr *)&dss->local_ip, true);
	hdhomerun_sock_sockaddr_to_ip_str(remote_ip_str, remote_addr, true);
	hdhomerun_debug_printf(ds->dbg, "discover: send to %s via %s\n", remote_ip_str, local_ip_str);

	return hdhomerun_sock_sendto_ex(dss->sock, remote_addr, tx_pkt->start, tx_pkt->end - tx_pkt->start, 0);
}

static void hdhomerun_discover_send_ipv6_targeted(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, uint32_t flags, const uint32_t device_types[], size_t device_types_count, uint32_t device_id, struct hdhomerun_discover_sock_t **recv_list)
{
	struct hdhomerun_discover_sock_t *default_dss = ds->ipv6_socks;
	if (!default_dss) {
		return;
	}

	hdhomerun_discover_sock_flush_list(ds, ds->ipv6_socks);
	hdhomerun_discover_sock_recv_list_append_list(recv_list, ds->ipv6_socks);

	struct sockaddr_in6 target_addr_in;
	memcpy(&target_addr_in, target_addr, sizeof(target_addr_in));
	target_addr_in.sin6_port = htons(HDHOMERUN_DISCOVER_UDP_PORT);

	/* ipv6 linklocal - send out every interface if the scope id isn't provided */
	if (hdhomerun_sock_sockaddr_is_ipv6_linklocal(target_addr) && (target_addr_in.sin6_scope_id == 0)) {
		struct hdhomerun_discover_sock_t *dss = default_dss->next;
		while (dss) {
			if (!dss->active) {
				dss = dss->next;
				continue;
			}

			if (!hdhomerun_sock_sockaddr_is_ipv6_linklocal((const struct sockaddr *)&dss->local_ip)) {
				dss = dss->next;
				continue;
			}

			struct sockaddr_in6 *local_addr_in = (struct sockaddr_in6 *)&dss->local_ip;
			target_addr_in.sin6_scope_id = local_addr_in->sin6_scope_id;

			if (!hdhomerun_discover_send_request(ds, dss, (const struct sockaddr *)&target_addr_in, device_types, device_types_count, device_id)) {
				dss = dss->next;
				continue;
			}

			dss = dss->next;
		}

		return;
	}

	hdhomerun_discover_send_request(ds, default_dss, (const struct sockaddr *)&target_addr_in, device_types, device_types_count, device_id);
}

static void hdhomerun_discover_send_ipv4_targeted(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, uint32_t flags, const uint32_t device_types[], size_t device_types_count, uint32_t device_id, struct hdhomerun_discover_sock_t **recv_list)
{
	struct hdhomerun_discover_sock_t *default_dss = ds->ipv4_socks;
	if (!default_dss) {
		return;
	}

	hdhomerun_discover_sock_flush_list(ds, ds->ipv4_socks);
	hdhomerun_discover_sock_recv_list_append_list(recv_list, ds->ipv4_socks);

	struct sockaddr_in target_addr_in;
	memcpy(&target_addr_in, target_addr, sizeof(target_addr_in));
	target_addr_in.sin_port = htons(HDHOMERUN_DISCOVER_UDP_PORT);

	uint32_t target_ipv4 = ntohl(target_addr_in.sin_addr.s_addr);
	bool local_subnet_send = false;

	struct hdhomerun_discover_sock_t *dss = default_dss->next;
	while (dss) {
		if (!dss->active) {
			dss = dss->next;
			continue;
		}

		if (dss->ipv4_subnet_mask == 0) {
			dss = dss->next;
			continue;
		}

		struct sockaddr_in *local_ip_in = (struct sockaddr_in *)&dss->local_ip;
		uint32_t local_ipv4 = ntohl(local_ip_in->sin_addr.s_addr);

		if ((target_ipv4 & dss->ipv4_subnet_mask) != (local_ipv4 & dss->ipv4_subnet_mask)) {
			dss = dss->next;
			continue;
		}

		if (!hdhomerun_discover_send_request(ds, dss, (const struct sockaddr *)&target_addr_in, device_types, device_types_count, device_id)) {
			dss = dss->next;
			continue;
		}

		local_subnet_send = true;
		dss = dss->next;
	}

	if (local_subnet_send) {
		return;
	}

	if (hdhomerun_sock_sockaddr_is_ipv4_autoip(target_addr)) {
		return;
	}

	hdhomerun_discover_send_request(ds, default_dss, (const struct sockaddr *)&target_addr_in, device_types, device_types_count, device_id);
}

static void hdhomerun_discover_send_ipv6_multicast(struct hdhomerun_discover_t *ds, uint32_t flags, const uint32_t device_types[], size_t device_types_count, uint32_t device_id, struct hdhomerun_discover_sock_t **recv_list)
{
	struct hdhomerun_discover_sock_t *default_dss = ds->ipv6_socks;
	if (!default_dss) {
		return;
	}

	hdhomerun_discover_sock_flush_list(ds, ds->ipv6_socks);
	hdhomerun_discover_sock_recv_list_append_list(recv_list, ds->ipv6_socks);

	if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL) {
		struct sockaddr_in6 sock_addr_in;
		memset(&sock_addr_in, 0, sizeof(sock_addr_in));
		sock_addr_in.sin6_family = AF_INET6;
		memcpy(sock_addr_in.sin6_addr.s6_addr, hdhomerun_discover_ipv6_linklocal_multicast_ip, 16);
		sock_addr_in.sin6_port = htons(HDHOMERUN_DISCOVER_UDP_PORT);

		struct hdhomerun_discover_sock_t *dss = default_dss->next;
		while (dss) {
			if (!dss->active) {
				dss = dss->next;
				continue;
			}

			if (!hdhomerun_sock_sockaddr_is_ipv6_linklocal((const struct sockaddr *)&dss->local_ip)) {
				dss = dss->next;
				continue;
			}

			hdhomerun_sock_set_ipv6_multicast_ifindex(dss->sock, dss->ifindex);

			struct sockaddr_in6 *local_ip_in = (struct sockaddr_in6 *)&dss->local_ip;
			sock_addr_in.sin6_scope_id = local_ip_in->sin6_scope_id;

			if (!hdhomerun_discover_send_request(ds, dss, (const struct sockaddr *)&sock_addr_in, device_types, device_types_count, device_id)) {
				dss = dss->next;
				continue;
			}

			dss = dss->next;
		}
	}

	if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL) {
		struct sockaddr_in6 sock_addr_in;
		memset(&sock_addr_in, 0, sizeof(sock_addr_in));
		sock_addr_in.sin6_family = AF_INET6;
		memcpy(sock_addr_in.sin6_addr.s6_addr, hdhomerun_discover_ipv6_sitelocal_multicast_ip, 16);
		sock_addr_in.sin6_port = htons(HDHOMERUN_DISCOVER_UDP_PORT);

		struct hdhomerun_discover_sock_t *dss = default_dss->next;
		while (dss) {
			if (!dss->active) {
				dss = dss->next;
				continue;
			}

			if (hdhomerun_sock_sockaddr_is_ipv6_linklocal((const struct sockaddr *)&dss->local_ip)) {
				dss = dss->next;
				continue;
			}

			hdhomerun_sock_set_ipv6_multicast_ifindex(dss->sock, dss->ifindex);

			struct sockaddr_in6 *local_ip_in = (struct sockaddr_in6 *)&dss->local_ip;
			sock_addr_in.sin6_scope_id = local_ip_in->sin6_scope_id;

			if (!hdhomerun_discover_send_request(ds, dss, (const struct sockaddr *)&sock_addr_in, device_types, device_types_count, device_id)) {
				dss = dss->next;
				continue;
			}

			dss = dss->next;
		}
	}
}

static void hdhomerun_discover_send_ipv4_broadcast(struct hdhomerun_discover_t *ds, uint32_t flags, const uint32_t device_types[], size_t device_types_count, uint32_t device_id, struct hdhomerun_discover_sock_t **recv_list)
{
	struct hdhomerun_discover_sock_t *default_dss = ds->ipv4_socks;
	if (!default_dss) {
		return;
	}

	hdhomerun_discover_sock_flush_list(ds, ds->ipv4_socks);
	hdhomerun_discover_sock_recv_list_append_list(recv_list, ds->ipv4_socks);

	struct sockaddr_in sock_addr_in;
	memset(&sock_addr_in, 0, sizeof(sock_addr_in));
	sock_addr_in.sin_family = AF_INET;
	sock_addr_in.sin_addr.s_addr = htonl(0xFFFFFFFF);
	sock_addr_in.sin_port = htons(HDHOMERUN_DISCOVER_UDP_PORT);

	struct hdhomerun_discover_sock_t *dss = default_dss->next;
	while (dss) {
		if (!dss->active) {
			dss = dss->next;
			continue;
		}

#if defined(IP_ONESBCAST)
		struct sockaddr_in *local_ip_in = (struct sockaddr_in *)&dss->local_ip;
		uint32_t local_ip_val = ntohl(local_ip_in->sin_addr.s_addr);

		uint32_t subnet_broadcast = local_ip_val | ~dss->ipv4_subnet_mask;
		if ((subnet_broadcast == 0) || (subnet_broadcast >= 0xE0000000)) {
			dss = dss->next;
			continue;
		}

		hdhomerun_sock_set_ipv4_onesbcast(dss->sock, 1);
		sock_addr_in.sin_addr.s_addr = htonl(subnet_broadcast);
#endif

		bool send_ok = hdhomerun_discover_send_request(ds, dss, (const struct sockaddr *)&sock_addr_in, device_types, device_types_count, device_id);
		hdhomerun_sock_set_ipv4_onesbcast(dss->sock, 0);
		if (!send_ok) {
			dss = dss->next;
			continue;
		}

		dss = dss->next;
	}
}

static void hdhomerun_discover_send_ipv6_localhost(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, uint32_t flags, const uint32_t device_types[], size_t device_types_count, uint32_t device_id, struct hdhomerun_discover_sock_t **recv_list)
{
	struct hdhomerun_discover_sock_t *localhost_dss = ds->ipv6_localhost;
	if (!localhost_dss) {
		return;
	}

	hdhomerun_discover_sock_flush_list(ds, localhost_dss);
	hdhomerun_discover_sock_recv_list_append_list(recv_list, localhost_dss);

	struct sockaddr_in6 sock_addr_in;
	if (target_addr) {
		memcpy(&sock_addr_in, target_addr, sizeof(sock_addr_in));
	} else {
		memset(&sock_addr_in, 0, sizeof(sock_addr_in));
		sock_addr_in.sin6_family = AF_INET6;
		sock_addr_in.sin6_addr.s6_addr[15] = 1;
	}

	sock_addr_in.sin6_port = htons(HDHOMERUN_DISCOVER_UDP_PORT);
	hdhomerun_discover_send_request(ds, localhost_dss, (const struct sockaddr *)&sock_addr_in, device_types, device_types_count, device_id);
}

static void hdhomerun_discover_send_ipv4_localhost(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, uint32_t flags, const uint32_t device_types[], size_t device_types_count, uint32_t device_id, struct hdhomerun_discover_sock_t **recv_list)
{
	struct hdhomerun_discover_sock_t *localhost_dss = ds->ipv4_localhost;
	if (!localhost_dss) {
		return;
	}

	hdhomerun_discover_sock_flush_list(ds, localhost_dss);
	hdhomerun_discover_sock_recv_list_append_list(recv_list, localhost_dss);

	struct sockaddr_in sock_addr_in;
	if (target_addr) {
		memcpy(&sock_addr_in, target_addr, sizeof(sock_addr_in));
	} else {
		memset(&sock_addr_in, 0, sizeof(sock_addr_in));
		sock_addr_in.sin_family = AF_INET;
		sock_addr_in.sin_addr.s_addr = htonl(0x7F000001);
	}

	sock_addr_in.sin_port = htons(HDHOMERUN_DISCOVER_UDP_PORT);
	hdhomerun_discover_send_request(ds, localhost_dss, (const struct sockaddr *)&sock_addr_in, device_types, device_types_count, device_id);
}

static uint8_t hdhomerun_discover_compute_device_if_priority(struct hdhomerun_discover2_device_if_t *device_if)
{
	if (device_if->ip_addr.ss_family == AF_INET) {
		if (hdhomerun_sock_sockaddr_is_ipv4_localhost((const struct sockaddr *)&device_if->ip_addr)) {
			return 1; /* localhost ipv4 */
		}

		if (!hdhomerun_sock_sockaddr_is_ipv4_autoip((const struct sockaddr *)&device_if->ip_addr)) {
			return 2; /* dhcp or static ipv4 */
		}

		return 6; /* auto ip */
	} else {
		if (hdhomerun_sock_sockaddr_is_ipv6_localhost((const struct sockaddr *)&device_if->ip_addr)) {
			return 0; /* localhost ipv6 = highest priority */
		}

		if (hdhomerun_sock_sockaddr_is_ipv6_global((const struct sockaddr *)&device_if->ip_addr)) {
			return 3; /* global ipv6 */
		}

		if (!hdhomerun_sock_sockaddr_is_ipv6_linklocal((const struct sockaddr *)&device_if->ip_addr)) {
			return 4; /* site ipv6 */
		}

		return 5; /* link-local ipv6 */
	}
}

static void hdhomerun_discover_recv_internal_device_type(struct hdhomerun_discover2_device_t *device, struct hdhomerun_pkt_t *rx_pkt)
{
	uint32_t device_type = hdhomerun_pkt_read_u32(rx_pkt);
	if ((device_type == 0) || (device_type == HDHOMERUN_DEVICE_TYPE_WILDCARD)) {
		return;
	}

	struct hdhomerun_discover2_device_type_t **pprev = &device->type_list;
	struct hdhomerun_discover2_device_type_t *p = device->type_list;
	while (p) {
		if (p->device_type >= device_type) {
			if (p->device_type > device_type) {
				break;
			}
			return;
		}

		pprev = &p->next;
		p = p->next;
	}

	struct hdhomerun_discover2_device_type_t *new_type = (struct hdhomerun_discover2_device_type_t *)calloc(1, sizeof(struct hdhomerun_discover2_device_type_t));
	if (!new_type) {
		return;
	}

	new_type->device_type = device_type;
	new_type->next = *pprev;
	*pprev = new_type;
}

static void hdhomerun_discover_recv_internal_string(char **poutput, struct hdhomerun_pkt_t *rx_pkt, size_t len)
{
	if (*poutput) {
		return;
	}

	char *str = (char *)malloc(len + 1);
	if (!str) {
		return;
	}

	hdhomerun_pkt_read_mem(rx_pkt, str, len);
	str[len] = 0;

	*poutput = str;
}

static void hdhomerun_discover_recv_internal_auth_bin(char **poutput, struct hdhomerun_pkt_t *rx_pkt, size_t len)
{
	if (*poutput) {
		return;
	}
	if (len != 18) {
		return;
	}

	char *str = (char *)malloc(24 + 1);
	if (!str) {
		return;
	}

	int i;
	for (i = 0; i < 24; i += 4) {
		static const char hdhomerun_discover_recv_base64_encode_table[64 + 1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

		uint32_t raw24;
		raw24 = (uint32_t)hdhomerun_pkt_read_u8(rx_pkt) << 16;
		raw24 |= (uint32_t)hdhomerun_pkt_read_u8(rx_pkt) << 8;
		raw24 |= (uint32_t)hdhomerun_pkt_read_u8(rx_pkt) << 0;
		str[i + 0] = hdhomerun_discover_recv_base64_encode_table[(raw24 >> 18) & 0x3F];
		str[i + 1] = hdhomerun_discover_recv_base64_encode_table[(raw24 >> 12) & 0x3F];
		str[i + 2] = hdhomerun_discover_recv_base64_encode_table[(raw24 >> 6) & 0x3F];
		str[i + 3] = hdhomerun_discover_recv_base64_encode_table[(raw24 >> 0) & 0x3F];
	}

	str[24] = 0;

	*poutput = str;
}

static void hdhomerun_discover_recv_fixup_tuner_count(struct hdhomerun_discover_t *ds, struct hdhomerun_discover2_device_t *device)
{
	if (!hdhomerun_discover2_device_is_type(device, HDHOMERUN_DEVICE_TYPE_TUNER)) {
		return;
	}

	if (device->tuner_count > 0) {
		return;
	}

	switch (device->device_id >> 20) {
	case 0x102:
		device->tuner_count = 1;
		break;

	case 0x100:
	case 0x101:
	case 0x121:
		device->tuner_count = 2;
		break;

	default:
		break;
	}
}

static void hdhomerun_discover_recv_fixup_base_url(struct hdhomerun_discover_t *ds, struct hdhomerun_discover2_device_t *device)
{
	if (!hdhomerun_discover2_device_is_type(device, HDHOMERUN_DEVICE_TYPE_TUNER)) {
		return;
	}

	struct hdhomerun_discover2_device_if_t *device_if = device->if_list;
	if (device_if->base_url) {
		return;
	}

	if (device_if->ip_addr.ss_family != AF_INET) {
		return;
	}

	device_if->base_url = (char *)malloc(32);
	if (!device_if->base_url) {
		return;
	}

	struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&device_if->ip_addr;
	uint32_t ip = ntohl(sock_addr_in->sin_addr.s_addr);

	hdhomerun_sprintf(device_if->base_url, device_if->base_url + 32, "http://%u.%u.%u.%u:80",
		(ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, (ip >> 0) & 0xFF
	);
}

static bool hdhomerun_discover_recv_internal(struct hdhomerun_discover_t *ds, struct hdhomerun_pkt_t *rx_pkt, struct hdhomerun_discover2_device_t *device)
{
	uint16_t type;
	if (hdhomerun_pkt_open_frame(rx_pkt, &type) <= 0) {
		return false;
	}
	if (type != HDHOMERUN_TYPE_DISCOVER_RPY) {
		return false;
	}

	struct hdhomerun_discover2_device_if_t *device_if = device->if_list;

	while (1) {
		uint8_t tag;
		size_t len;
		uint8_t *next = hdhomerun_pkt_read_tlv(rx_pkt, &tag, &len);
		if (!next) {
			break;
		}

		switch (tag) {
		case HDHOMERUN_TAG_DEVICE_TYPE:
			if (len != 4) {
				break;
			}
			hdhomerun_discover_recv_internal_device_type(device, rx_pkt);
			break;

		case HDHOMERUN_TAG_MULTI_TYPE:
			while (len >= 4) {
				hdhomerun_discover_recv_internal_device_type(device, rx_pkt);
				len -= 4;
			}
			break;

		case HDHOMERUN_TAG_DEVICE_ID:
			if (len != 4) {
				break;
			}
			device->device_id = hdhomerun_pkt_read_u32(rx_pkt);
			break;

		case HDHOMERUN_TAG_TUNER_COUNT:
			if (len != 1) {
				break;
			}
			device->tuner_count = hdhomerun_pkt_read_u8(rx_pkt);
			break;

		case HDHOMERUN_TAG_DEVICE_AUTH_STR:
			hdhomerun_discover_recv_internal_string(&device->device_auth, rx_pkt, len);
			break;

		case HDHOMERUN_TAG_DEVICE_AUTH_BIN_DEPRECATED:
			hdhomerun_discover_recv_internal_auth_bin(&device->device_auth, rx_pkt, len);
			break;

		case HDHOMERUN_TAG_BASE_URL:
			hdhomerun_discover_recv_internal_string(&device_if->base_url, rx_pkt, len);
			break;

		case HDHOMERUN_TAG_STORAGE_ID:
			hdhomerun_discover_recv_internal_string(&device->storage_id, rx_pkt, len);
			break;

		case HDHOMERUN_TAG_LINEUP_URL:
			hdhomerun_discover_recv_internal_string(&device_if->lineup_url, rx_pkt, len);
			break;

		case HDHOMERUN_TAG_STORAGE_URL:
			hdhomerun_discover_recv_internal_string(&device_if->storage_url, rx_pkt, len);
			break;

		default:
			break;
		}

		rx_pkt->pos = next;
	}

	if (!device->type_list) {
		return false;
	}

	/*
	 * Fixup for old firmware.
	 */
	hdhomerun_discover_recv_fixup_tuner_count(ds, device);
	hdhomerun_discover_recv_fixup_base_url(ds, device);

	/*
	 * Success
	 */
	device_if->priority = hdhomerun_discover_compute_device_if_priority(device_if);
	return true;
}

static void hdhomerun_discover_recv_merge_device_type(struct hdhomerun_discover2_device_t *device, struct hdhomerun_discover2_device_type_t *new_type)
{
	struct hdhomerun_discover2_device_type_t **pprev = &device->type_list;
	struct hdhomerun_discover2_device_type_t *p = device->type_list;
	while (p) {
		if (p->device_type >= new_type->device_type) {
			if (p->device_type > new_type->device_type) {
				break;
			}
			free(new_type);
			return;
		}

		pprev = &p->next;
		p = p->next;
	}

	new_type->next = *pprev;
	*pprev = new_type;
}

static void hdhomerun_discover_recv_merge_device_types(struct hdhomerun_discover2_device_t *device, struct hdhomerun_discover2_device_type_t *type_list)
{
	while (type_list) {
		struct hdhomerun_discover2_device_type_t *new_type = type_list;
		type_list = new_type->next;
		hdhomerun_discover_recv_merge_device_type(device, new_type);
	}
}

static void hdhomerun_discover_recv_merge_device_if(struct hdhomerun_discover2_device_t *device, struct hdhomerun_discover2_device_if_t *device_if)
{
	struct hdhomerun_discover2_device_if_t **pprev = &device->if_list;
	struct hdhomerun_discover2_device_if_t *p = device->if_list;
	while (p) {
		if (p->priority < device_if->priority) {
			pprev = &p->next;
			p = p->next;
			continue;
		}
		if (p->priority > device_if->priority) {
			break;
		}

		char *p_base_url = p->base_url;
		char *device_if_base_url = device_if->base_url;
		if (!p_base_url) {
			p_base_url = "";
		}
		if (!device_if_base_url) {
			device_if_base_url = "";
		}

		int cmp = strcmp(p_base_url, device_if_base_url);
		if (cmp < 0) {
			pprev = &p->next;
			p = p->next;
			continue;
		}
		if (cmp > 0) {
			break;
		}

		/* Duplicate */
		hdhomerun_discover_device_if_free(device_if);
		return;
	}

	device_if->next = *pprev;
	*pprev = device_if;
}

static void hdhomerun_discover_recv_merge_device(struct hdhomerun_discover_t *ds, struct hdhomerun_discover2_device_t *device)
{
	struct hdhomerun_discover2_device_t **pprev = &ds->device_list;
	struct hdhomerun_discover2_device_t *p = ds->device_list;
	while (p) {
		if (p->device_id < device->device_id) {
			pprev = &p->next;
			p = p->next;
			continue;
		}
		if (p->device_id > device->device_id) {
			break;
		}

		char *p_storage_id = p->storage_id;
		char *device_storage_id = device->storage_id;
		if (!p_storage_id) {
			p_storage_id = "";
		}
		if (!device_storage_id) {
			device_storage_id = "";
		}

		int cmp = strcmp(p_storage_id, device_storage_id);
		if (cmp < 0) {
			pprev = &p->next;
			p = p->next;
			continue;
		}
		if (cmp > 0) {
			break;
		}

		/* Merge */
		struct hdhomerun_discover2_device_type_t *type_list = device->type_list;
		device->type_list = NULL;
		hdhomerun_discover_recv_merge_device_types(p, type_list);

		struct hdhomerun_discover2_device_if_t *device_if = device->if_list;
		device->if_list = NULL;
		hdhomerun_discover_recv_merge_device_if(p, device_if);

		hdhomerun_discover_device_free(device);
		return;
	}

	device->next = *pprev;
	*pprev = device;
}

static bool hdhomerun_discover_recvfrom_match_flags(const struct sockaddr *remote_addr, uint32_t flags)
{
	if (remote_addr->sa_family == AF_INET6) {
		if (hdhomerun_sock_sockaddr_is_ipv6_localhost(remote_addr)) {
			return (flags & HDHOMERUN_DISCOVER_FLAGS_IPV6_LOCALHOST) != 0;
		}

		if (hdhomerun_sock_sockaddr_is_ipv6_linklocal(remote_addr)) {
			return (flags & HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL) != 0;
		}

		return (flags & HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL) != 0;
	}

	if (remote_addr->sa_family == AF_INET) {
		if (hdhomerun_sock_sockaddr_is_ipv4_localhost(remote_addr)) {
			return (flags & HDHOMERUN_DISCOVER_FLAGS_IPV4_LOCALHOST) != 0;
		}

		return (flags & HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL) != 0;
	}

	return false;
}

static bool hdhomerun_discover_recvfrom_match_device_type(struct hdhomerun_discover2_device_t *device, const uint32_t device_types_match[], size_t device_types_count)
{
	if (device_types_count == 0) {
		return false;
	}

	if (device_types_match[0] == HDHOMERUN_DEVICE_TYPE_WILDCARD) {
		return true;
	}

	while (device_types_count--) {
		if (hdhomerun_discover2_device_is_type(device, *device_types_match++)) {
			return true;
		}
	}

	return false;
}

static bool hdhomerun_discover_recvfrom_match_device_id(struct hdhomerun_discover2_device_t *device, uint32_t device_id_match)
{
	if (device_id_match == HDHOMERUN_DEVICE_ID_WILDCARD) {
		return true;
	}
	
	return (device->device_id == device_id_match);
}

static bool hdhomerun_discover_recvfrom(struct hdhomerun_discover_t *ds, struct hdhomerun_discover_sock_t *dss, uint32_t flags, const uint32_t device_types_match[], size_t device_types_count, uint32_t device_id_match)
{
	struct hdhomerun_pkt_t *rx_pkt = &ds->rx_pkt;
	hdhomerun_pkt_reset(rx_pkt);
	bool activity = false;

	struct sockaddr_storage remote_addr;
	size_t length = rx_pkt->limit - rx_pkt->end;
	if (!hdhomerun_sock_recvfrom_ex(dss->sock, &remote_addr, rx_pkt->end, &length, 0)) {
		return activity;
	}

	rx_pkt->end += length;
	activity = true;

	char local_ip_str[64];
	char remote_ip_str[64];
	hdhomerun_sock_sockaddr_to_ip_str(local_ip_str, (const struct sockaddr *)&dss->local_ip, true);
	hdhomerun_sock_sockaddr_to_ip_str(remote_ip_str, (const struct sockaddr *)&remote_addr, true);
	hdhomerun_debug_printf(ds->dbg, "discover: recv from %s via %s\n", remote_ip_str, local_ip_str);

	if (!hdhomerun_discover_recvfrom_match_flags((const struct sockaddr *)&remote_addr, flags)) {
		return activity;
	}

	struct hdhomerun_discover2_device_t *device = (struct hdhomerun_discover2_device_t *)calloc(1, sizeof(struct hdhomerun_discover2_device_t));
	struct hdhomerun_discover2_device_if_t *device_if = (struct hdhomerun_discover2_device_if_t *)calloc(1, sizeof(struct hdhomerun_discover2_device_if_t));
	if (!device || !device_if) {
		if (device) {
			free(device);
		}
		if (device_if) {
			free(device_if);
		}
		return activity;
	}

	device->if_list = device_if;
	device_if->ip_addr = remote_addr;

	if (!hdhomerun_discover_recv_internal(ds, rx_pkt, device)) {
		hdhomerun_discover_device_free(device);
		return activity;
	}

	if (!hdhomerun_discover_recvfrom_match_device_type(device, device_types_match, device_types_count)) {
		hdhomerun_discover_device_free(device);
		return activity;
	}

	if (!hdhomerun_discover_recvfrom_match_device_id(device, device_id_match)) {
		hdhomerun_discover_device_free(device);
		return activity;
	}

	hdhomerun_discover_recv_merge_device(ds, device);
	return activity;
}

static void hdhomerun_discover2_find_devices_debug_log_results(struct hdhomerun_discover_t *ds)
{
	if (!ds->dbg) {
		return;
	}

	struct hdhomerun_discover2_device_t *device = ds->device_list;
	while (device) {
		struct hdhomerun_discover2_device_if_t *device_if = device->if_list;
		if (device->device_id) {
			hdhomerun_debug_printf(ds->dbg, "discover: found %08X %s\n", device->device_id, device_if->base_url);
			device = device->next;
			continue;
		}

		if (device->storage_id) {
			hdhomerun_debug_printf(ds->dbg, "discover: found %s %s\n", device->storage_id, device_if->base_url);
			device = device->next;
			continue;
		}

		hdhomerun_debug_printf(ds->dbg, "discover: found %s\n", device_if->base_url);
		device = device->next;
	}
}

static uint32_t hdhomerun_discover2_find_devices_targeted_flags(const struct sockaddr *target_addr)
{
	if (target_addr->sa_family == AF_INET6) {
		if (hdhomerun_sock_sockaddr_is_ipv6_localhost(target_addr)) {
			return HDHOMERUN_DISCOVER_FLAGS_IPV6_LOCALHOST;
		}

		if (hdhomerun_sock_sockaddr_is_ipv6_linklocal(target_addr)) {
			return HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL;
		}

		return HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL;
	}

	if (target_addr->sa_family == AF_INET) {
		if (hdhomerun_sock_sockaddr_is_ipv4_localhost(target_addr)) {
			return HDHOMERUN_DISCOVER_FLAGS_IPV4_LOCALHOST;
		}

		return HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL;
	}

	return 0;
}

static int hdhomerun_discover2_find_devices_targeted_internal(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, const uint32_t device_types[], size_t device_types_count, uint32_t device_id)
{
	uint32_t flags = hdhomerun_discover2_find_devices_targeted_flags(target_addr);
	if (flags == 0) {
		return -1;
	}

	hdhomerun_discover_free_device_list(ds);
	hdhomerun_discover_sock_detect_all_from_flags(ds, flags);

	int attempt;
	for (attempt = 0; attempt < 2; attempt++) {
		struct hdhomerun_discover_sock_t *recv_list = NULL;
		if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV6_LOCALHOST) {
			hdhomerun_discover_send_ipv6_localhost(ds, target_addr, flags, device_types, device_types_count, device_id, &recv_list);
		}
		if (flags & (HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL)) {
			hdhomerun_discover_send_ipv6_targeted(ds, target_addr, flags, device_types, device_types_count, device_id, &recv_list);
		}
		if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV4_LOCALHOST) {
			hdhomerun_discover_send_ipv4_localhost(ds, target_addr, flags, device_types, device_types_count, device_id, &recv_list);
		}
		if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL) {
			hdhomerun_discover_send_ipv4_targeted(ds, target_addr, flags, device_types, device_types_count, device_id, &recv_list);
		}
		if (!recv_list) {
			return -1;
		}

		uint64_t timeout = getcurrenttime() + 200;

		while (1) {
			bool activity = false;

			struct hdhomerun_discover_sock_t *dss = recv_list;
			while (dss) {
				activity |= hdhomerun_discover_recvfrom(ds, dss, flags, device_types, device_types_count, device_id);
				dss = dss->recv_next;
			}

			if (ds->device_list) {
				hdhomerun_discover2_find_devices_debug_log_results(ds);
				return 1;
			}
			if (activity) {
				continue;
			}
			if (getcurrenttime() >= timeout) {
				break;
			}
			msleep_approx(16);
		}
	}

	hdhomerun_discover2_find_devices_debug_log_results(ds);
	return (ds->device_list) ? 1 : 0;
}

static int hdhomerun_discover2_find_devices_broadcast_internal(struct hdhomerun_discover_t *ds, uint32_t flags, const uint32_t device_types[], size_t device_types_count, uint32_t device_id)
{
	hdhomerun_discover_free_device_list(ds);
	hdhomerun_discover_sock_detect_all_from_flags(ds, flags);

	int attempt;
	for (attempt = 0; attempt < 2; attempt++) {
		struct hdhomerun_discover_sock_t *recv_list = NULL;
		if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV6_LOCALHOST) {
			hdhomerun_discover_send_ipv6_localhost(ds, NULL, flags, device_types, device_types_count, device_id, &recv_list);
		}
		if (flags & (HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL)) {
			hdhomerun_discover_send_ipv6_multicast(ds, flags, device_types, device_types_count, device_id, &recv_list);
		}
		if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV4_LOCALHOST) {
			hdhomerun_discover_send_ipv4_localhost(ds, NULL, flags, device_types, device_types_count, device_id, &recv_list);
		}
		if (flags & HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL) {
			hdhomerun_discover_send_ipv4_broadcast(ds, flags, device_types, device_types_count, device_id, &recv_list);
		}
		if (!recv_list) {
			return -1;
		}

		uint64_t timeout = getcurrenttime() + 200;

		while (1) {
			bool activity = false;

			struct hdhomerun_discover_sock_t *dss = recv_list;
			while (dss) {
				activity |= hdhomerun_discover_recvfrom(ds, dss, flags, device_types, device_types_count, device_id);
				dss = dss->recv_next;
			}

			if ((device_id != HDHOMERUN_DEVICE_ID_WILDCARD) && ds->device_list) {
				hdhomerun_discover2_find_devices_debug_log_results(ds);
				return 1;
			}
			if (activity) {
				continue;
			}
			if (getcurrenttime() >= timeout) {
				break;
			}
			msleep_approx(16);
		}
	}

	hdhomerun_discover2_find_devices_debug_log_results(ds);
	return (ds->device_list) ? 1 : 0;
}

int hdhomerun_discover2_find_devices_targeted(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, const uint32_t device_types[], size_t device_types_count)
{
	return hdhomerun_discover2_find_devices_targeted_internal(ds, target_addr, device_types, device_types_count, HDHOMERUN_DEVICE_ID_WILDCARD);
}

int hdhomerun_discover2_find_devices_broadcast(struct hdhomerun_discover_t *ds, uint32_t flags, const uint32_t device_types[], size_t device_types_count)
{
	return hdhomerun_discover2_find_devices_broadcast_internal(ds, flags, device_types, device_types_count, HDHOMERUN_DEVICE_ID_WILDCARD);
}

int hdhomerun_discover2_find_device_id_targeted(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, uint32_t device_id)
{
	if ((device_id == 0) || (device_id == HDHOMERUN_DEVICE_ID_WILDCARD)) {
		return -1;
	}
	if (!hdhomerun_discover_validate_device_id(device_id)) {
		return - 1;
	}

	uint32_t device_types[1];
	device_types[0] = HDHOMERUN_DEVICE_TYPE_WILDCARD;

	return hdhomerun_discover2_find_devices_targeted_internal(ds, target_addr, device_types, 1, device_id);
}

int hdhomerun_discover2_find_device_id_broadcast(struct hdhomerun_discover_t *ds, uint32_t flags, uint32_t device_id)
{
	if ((device_id == 0) || (device_id == HDHOMERUN_DEVICE_ID_WILDCARD)) {
		return -1;
	}
	if (!hdhomerun_discover_validate_device_id(device_id)) {
		return -1;
	}

	uint32_t device_types[1];
	device_types[0] = HDHOMERUN_DEVICE_TYPE_WILDCARD;

	return hdhomerun_discover2_find_devices_broadcast_internal(ds, flags, device_types, 1, device_id);
}

struct hdhomerun_discover2_device_t *hdhomerun_discover2_iter_device_first(struct hdhomerun_discover_t *ds)
{
	return ds->device_list;
}

struct hdhomerun_discover2_device_t *hdhomerun_discover2_iter_device_next(struct hdhomerun_discover2_device_t *device)
{
	return device->next;
}

struct hdhomerun_discover2_device_if_t *hdhomerun_discover2_iter_device_if_first(struct hdhomerun_discover2_device_t *device)
{
	return device->if_list;
}

struct hdhomerun_discover2_device_if_t *hdhomerun_discover2_iter_device_if_next(struct hdhomerun_discover2_device_if_t *device_if)
{
	return device_if->next;
}

bool hdhomerun_discover2_device_is_legacy(struct hdhomerun_discover2_device_t *device)
{
	switch (device->device_id >> 20) {
	case 0x100: /* TECH-US/TECH3-US */
		return (device->device_id < 0x10040000);

	case 0x120: /* TECH3-EU */
		return (device->device_id < 0x12030000);

	case 0x101: /* HDHR-US */
	case 0x102: /* HDHR-T1-US */
	case 0x103: /* HDHR3-US */
	case 0x111: /* HDHR3-DT */
	case 0x121: /* HDHR-EU */
	case 0x122: /* HDHR3-EU */
		return true;

	default:
		return false;
	}
}

bool hdhomerun_discover2_device_is_type(struct hdhomerun_discover2_device_t *device, uint32_t device_type)
{
	struct hdhomerun_discover2_device_type_t *p = device->type_list;
	while (p) {
		if (p->device_type == device_type) {
			return true;
		}
		p = p->next;
	}

	return false;
}

uint32_t hdhomerun_discover2_device_get_device_id(struct hdhomerun_discover2_device_t *device)
{
	return device->device_id;
}

const char *hdhomerun_discover2_device_get_storage_id(struct hdhomerun_discover2_device_t *device)
{
	return device->storage_id;
}

uint8_t hdhomerun_discover2_device_get_tuner_count(struct hdhomerun_discover2_device_t *device)
{
	return device->tuner_count;
}

const char *hdhomerun_discover2_device_get_device_auth(struct hdhomerun_discover2_device_t *device)
{
	return device->device_auth;
}

bool hdhomerun_discover2_device_if_addr_is_ipv4(struct hdhomerun_discover2_device_if_t *device_if)
{
	return (device_if->ip_addr.ss_family == AF_INET);
}

bool hdhomerun_discover2_device_if_addr_is_ipv6_linklocal(struct hdhomerun_discover2_device_if_t *device_if)
{
	return hdhomerun_sock_sockaddr_is_ipv6_linklocal((const struct sockaddr *)&device_if->ip_addr);
}

uint32_t hdhomerun_discover2_device_if_get_ipv6_linklocal_scope_id(struct hdhomerun_discover2_device_if_t *device_if)
{
	if (!hdhomerun_sock_sockaddr_is_ipv6_linklocal((const struct sockaddr *)&device_if->ip_addr)) {
		return 0;
	}

	const struct sockaddr_in6 *ip_addr_in6 = (const struct sockaddr_in6 *)&device_if->ip_addr;
	return ip_addr_in6->sin6_scope_id;
}

void hdhomerun_discover2_device_if_get_ip_addr(struct hdhomerun_discover2_device_if_t *device_if, struct sockaddr_storage *ip_addr)
{
	*ip_addr = device_if->ip_addr;
}

const char *hdhomerun_discover2_device_if_get_base_url(struct hdhomerun_discover2_device_if_t *device_if)
{
	return device_if->base_url;
}

const char *hdhomerun_discover2_device_if_get_lineup_url(struct hdhomerun_discover2_device_if_t *device_if)
{
	return device_if->lineup_url;
}

const char *hdhomerun_discover2_device_if_get_storage_url(struct hdhomerun_discover2_device_if_t *device_if)
{
	return device_if->storage_url;
}

static void hdhomerun_discover_v2v3_strcpy(char *output, size_t size, const char *src)
{
	if (!src) {
		output[0] = 0;
		return;
	}

	size_t src_len = strlen(src);
	if (src_len >= size) {
		output[0] = 0;
		return;
	}

	memcpy(output, src, src_len + 1);
}

static uint32_t hdhomerun_discover_v2v3_device_type(struct hdhomerun_discover2_device_t *device, uint32_t device_type_match)
{
	if (device_type_match == HDHOMERUN_DEVICE_TYPE_WILDCARD) {
		return device->type_list->device_type;
	}

	if (hdhomerun_discover2_device_is_type(device, device_type_match)) {
		return device_type_match;
	}

	return device->type_list->device_type;
}

int hdhomerun_discover_find_devices_v3(struct hdhomerun_discover_t *ds, uint32_t target_ip, uint32_t device_type_match, uint32_t device_id_match, struct hdhomerun_discover_device_v3_t result_list[], int max_count)
{
	if (target_ip == 0) {
		target_ip = 0xFFFFFFFF;
	}
	if (device_type_match == 0) {
		device_type_match = HDHOMERUN_DEVICE_TYPE_WILDCARD;
	}
	if (device_id_match == 0) {
		device_id_match = HDHOMERUN_DEVICE_ID_WILDCARD;
	}
	if (!hdhomerun_discover_validate_device_id(device_id_match)) {
		return -1;
	}

	uint32_t device_types[1];
	device_types[0] = device_type_match;

	int ret;
	if (target_ip == 0xFFFFFFFF) {
		ret = hdhomerun_discover2_find_devices_broadcast_internal(ds, HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL, device_types, 1, device_id_match);
	} else {
		struct sockaddr_in sock_addr_in;
		memset(&sock_addr_in, 0, sizeof(sock_addr_in));
		sock_addr_in.sin_family = AF_INET;
		sock_addr_in.sin_addr.s_addr = htonl(target_ip);
		ret = hdhomerun_discover2_find_devices_targeted_internal(ds, (const struct sockaddr *)&sock_addr_in, device_types, 1, device_id_match);
	}
	if (ret <= 0) {
		return ret;
	}

	struct hdhomerun_discover_device_v3_t *result = result_list;
	struct hdhomerun_discover2_device_t *device = ds->device_list;
	int count = 0;

	while (device && (count < max_count)) {
		struct hdhomerun_discover2_device_if_t *device_if = device->if_list;
		while (device_if) {
			if (device_if->ip_addr.ss_family == AF_INET) {
				break;
			}
			device_if = device_if->next;
		}
		if (!device_if) {
			device = device->next;
			continue;
		}

		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&device_if->ip_addr;
		result->ip_addr = ntohl(sock_addr_in->sin_addr.s_addr);
		result->device_type = hdhomerun_discover_v2v3_device_type(device, device_type_match);
		result->device_id = device->device_id;
		result->tuner_count = device->tuner_count;
		result->is_legacy = hdhomerun_discover2_device_is_legacy(device);
		hdhomerun_discover_v2v3_strcpy(result->storage_id, sizeof(result->storage_id), device->storage_id);
		hdhomerun_discover_v2v3_strcpy(result->device_auth, sizeof(result->device_auth), device->device_auth);
		hdhomerun_discover_v2v3_strcpy(result->base_url, sizeof(result->base_url), device_if->base_url);
		hdhomerun_discover_v2v3_strcpy(result->lineup_url, sizeof(result->lineup_url), device_if->lineup_url);
		hdhomerun_discover_v2v3_strcpy(result->storage_url, sizeof(result->storage_url), device_if->storage_url);

		count++;
		result++;
		device = device->next;
	}

	return count;
}

int hdhomerun_discover_find_devices_v2(struct hdhomerun_discover_t *ds, uint32_t target_ip, uint32_t device_type_match, uint32_t device_id_match, struct hdhomerun_discover_device_t result_list[], int max_count)
{
	if (target_ip == 0) {
		target_ip = 0xFFFFFFFF;
	}
	if (device_type_match == 0) {
		device_type_match = HDHOMERUN_DEVICE_TYPE_WILDCARD;
	}
	if (device_id_match == 0) {
		device_id_match = HDHOMERUN_DEVICE_ID_WILDCARD;
	}
	if (!hdhomerun_discover_validate_device_id(device_id_match)) {
		return -1;
	}

	uint32_t device_types[1];
	device_types[0] = device_type_match;

	int ret;
	if (target_ip == 0xFFFFFFFF) {
		ret = hdhomerun_discover2_find_devices_broadcast_internal(ds, HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL, device_types, 1, device_id_match);
	} else {
		struct sockaddr_in sock_addr_in;
		memset(&sock_addr_in, 0, sizeof(sock_addr_in));
		sock_addr_in.sin_family = AF_INET;
		sock_addr_in.sin_addr.s_addr = htonl(target_ip);
		ret = hdhomerun_discover2_find_devices_targeted_internal(ds, (const struct sockaddr *)&sock_addr_in, device_types, 1, device_id_match);
	}
	if (ret <= 0) {
		return ret;
	}

	struct hdhomerun_discover_device_t *result = result_list;
	struct hdhomerun_discover2_device_t *device = ds->device_list;
	int count = 0;

	while (device && (count < max_count)) {
		struct hdhomerun_discover2_device_if_t *device_if = device->if_list;
		while (device_if) {
			if (device_if->ip_addr.ss_family == AF_INET) {
				break;
			}
			device_if = device_if->next;
		}
		if (!device_if) {
			device = device->next;
			continue;
		}

		struct sockaddr_in *sock_addr_in = (struct sockaddr_in *)&device_if->ip_addr;
		result->ip_addr = ntohl(sock_addr_in->sin_addr.s_addr);
		result->device_type = hdhomerun_discover_v2v3_device_type(device, device_type_match);
		result->device_id = device->device_id;
		result->tuner_count = device->tuner_count;
		result->is_legacy = hdhomerun_discover2_device_is_legacy(device);
		hdhomerun_discover_v2v3_strcpy(result->device_auth, sizeof(result->device_auth), device->device_auth);
		hdhomerun_discover_v2v3_strcpy(result->base_url, sizeof(result->base_url), device_if->base_url);

		count++;
		result++;
		device = device->next;
	}

	return count;
}

int hdhomerun_discover_find_devices_custom_v3(uint32_t target_ip, uint32_t device_type_match, uint32_t device_id_match, struct hdhomerun_discover_device_v3_t result_list[], int max_count)
{
	struct hdhomerun_discover_t *ds = hdhomerun_discover_create(NULL);
	if (!ds) {
		return -1;
	}

	int ret = hdhomerun_discover_find_devices_v3(ds, target_ip, device_type_match, device_id_match, result_list, max_count);
	hdhomerun_discover_destroy(ds);
	return ret;
}

int hdhomerun_discover_find_devices_custom_v2(uint32_t target_ip, uint32_t device_type_match, uint32_t device_id_match, struct hdhomerun_discover_device_t result_list[], int max_count)
{
	struct hdhomerun_discover_t *ds = hdhomerun_discover_create(NULL);
	if (!ds) {
		return -1;
	}

	int ret = hdhomerun_discover_find_devices_v2(ds, target_ip, device_type_match, device_id_match, result_list, max_count);
	hdhomerun_discover_destroy(ds);
	return ret;
}

bool hdhomerun_discover_validate_device_id(uint32_t device_id)
{
	static uint8_t lookup_table[16] = {0xA, 0x5, 0xF, 0x6, 0x7, 0xC, 0x1, 0xB, 0x9, 0x2, 0x8, 0xD, 0x4, 0x3, 0xE, 0x0};

	uint8_t checksum = 0;

	checksum ^= lookup_table[(device_id >> 28) & 0x0F];
	checksum ^= (device_id >> 24) & 0x0F;
	checksum ^= lookup_table[(device_id >> 20) & 0x0F];
	checksum ^= (device_id >> 16) & 0x0F;
	checksum ^= lookup_table[(device_id >> 12) & 0x0F];
	checksum ^= (device_id >> 8) & 0x0F;
	checksum ^= lookup_table[(device_id >> 4) & 0x0F];
	checksum ^= (device_id >> 0) & 0x0F;

	return (checksum == 0);
}

bool hdhomerun_discover_is_ip_multicast(uint32_t ip_addr)
{
	struct sockaddr_in addr_in;
	memset(&addr_in, 0, sizeof(struct sockaddr_in));
	addr_in.sin_family = AF_INET;
	addr_in.sin_addr.s_addr = htonl(ip_addr);

	return hdhomerun_sock_sockaddr_is_multicast((const struct sockaddr *)&addr_in);
}

bool hdhomerun_discover_is_ip_multicast_ex(const struct sockaddr *ip_addr)
{
	return hdhomerun_sock_sockaddr_is_multicast(ip_addr);
}
