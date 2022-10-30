/*
 * hdhomerun_control.c
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

#define HDHOMERUN_CONTROL_CONNECT_TIMEOUT 2500
#define HDHOMERUN_CONTROL_SEND_TIMEOUT 2500
#define HDHOMERUN_CONTROL_RECV_TIMEOUT 2500
#define HDHOMERUN_CONTROL_UPGRADE_TIMEOUT 40000

struct hdhomerun_control_sock_t {
	uint32_t desired_device_id;
	uint32_t actual_device_id;
	struct sockaddr_storage desired_device_addr;
	struct sockaddr_storage actual_device_addr;
	struct hdhomerun_sock_t *sock;
	struct hdhomerun_debug_t *dbg;
	struct hdhomerun_pkt_t tx_pkt;
	struct hdhomerun_pkt_t rx_pkt;
};

static void hdhomerun_control_close_sock(struct hdhomerun_control_sock_t *cs)
{
	if (!cs->sock) {
		return;
	}

	hdhomerun_sock_destroy(cs->sock);
	cs->sock = NULL;
}

void hdhomerun_control_set_device(struct hdhomerun_control_sock_t *cs, uint32_t device_id, uint32_t device_ip)
{
	struct sockaddr_in device_addr;
	memset(&device_addr, 0, sizeof(device_addr));
	device_addr.sin_family = AF_INET;
	device_addr.sin_addr.s_addr = htonl(device_ip);

	hdhomerun_control_set_device_ex(cs, device_id, (const struct sockaddr *)&device_addr);
}

void hdhomerun_control_set_device_ex(struct hdhomerun_control_sock_t *cs, uint32_t device_id, const struct sockaddr *device_addr)
{
	hdhomerun_control_close_sock(cs);

	cs->desired_device_id = device_id;
	cs->actual_device_id = 0;
	hdhomerun_sock_sockaddr_copy(&cs->desired_device_addr, device_addr);
	memset(&cs->actual_device_addr, 0, sizeof(cs->actual_device_addr));
}

struct hdhomerun_control_sock_t *hdhomerun_control_create(uint32_t device_id, uint32_t device_ip, struct hdhomerun_debug_t *dbg)
{
	struct sockaddr_in device_addr;
	memset(&device_addr, 0, sizeof(device_addr));
	device_addr.sin_family = AF_INET;
	device_addr.sin_addr.s_addr = htonl(device_ip);

	return hdhomerun_control_create_ex(device_id, (const struct sockaddr *)&device_addr, dbg);
}

struct hdhomerun_control_sock_t *hdhomerun_control_create_ex(uint32_t device_id, const struct sockaddr *device_addr, struct hdhomerun_debug_t *dbg)
{
	struct hdhomerun_control_sock_t *cs = (struct hdhomerun_control_sock_t *)calloc(1, sizeof(struct hdhomerun_control_sock_t));
	if (!cs) {
		hdhomerun_debug_printf(dbg, "hdhomerun_control_create: failed to allocate control object\n");
		return NULL;
	}

	cs->dbg = dbg;
	hdhomerun_control_set_device_ex(cs, device_id, device_addr);

	return cs;
}

void hdhomerun_control_destroy(struct hdhomerun_control_sock_t *cs)
{
	hdhomerun_control_close_sock(cs);
	free(cs);
}

static bool hdhomerun_control_connect_sock_discover(struct hdhomerun_control_sock_t *cs)
{
	struct hdhomerun_discover_t *ds = hdhomerun_discover_create(cs->dbg);
	if (!ds) {
		return false;
	}

	uint32_t device_types[1];
	device_types[0] = HDHOMERUN_DEVICE_TYPE_WILDCARD;

	uint32_t device_id = cs->desired_device_id;
	if (device_id == 0) {
		device_id = HDHOMERUN_DEVICE_ID_WILDCARD;
	}

	int ret;
	if (hdhomerun_sock_sockaddr_is_addr((struct sockaddr *)&cs->desired_device_addr)) {
		if (device_id == HDHOMERUN_DEVICE_ID_WILDCARD) {
			ret = hdhomerun_discover2_find_devices_targeted(ds, (struct sockaddr *)&cs->desired_device_addr, device_types, 1);
		} else {
			ret = hdhomerun_discover2_find_device_id_targeted(ds, (struct sockaddr *)&cs->desired_device_addr, device_id);
		}
	} else {
		uint32_t flags = HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL;
		if (device_id == HDHOMERUN_DEVICE_ID_WILDCARD) {
			ret = hdhomerun_discover2_find_devices_broadcast(ds, flags, device_types, 1);
		} else {
			ret = hdhomerun_discover2_find_device_id_broadcast(ds, flags, device_id);
		}
	}
	if (ret <= 0) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_connect_sock: device not found\n");
		hdhomerun_discover_destroy(ds);
		return false;
	}

	struct hdhomerun_discover2_device_t *device = hdhomerun_discover2_iter_device_first(ds);
	cs->actual_device_id = hdhomerun_discover2_device_get_device_id(device);

	struct hdhomerun_discover2_device_if_t *device_if = hdhomerun_discover2_iter_device_if_first(device);
	hdhomerun_discover2_device_if_get_ip_addr(device_if, &cs->actual_device_addr);

	hdhomerun_discover_destroy(ds);
	return true;
}

static bool hdhomerun_control_connect_sock(struct hdhomerun_control_sock_t *cs)
{
	if (cs->sock) {
		return true;
	}

	if ((cs->desired_device_id == 0) && !hdhomerun_sock_sockaddr_is_addr((struct sockaddr *)&cs->desired_device_addr)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_connect_sock: no device specified\n");
		return false;
	}
	if (hdhomerun_sock_sockaddr_is_multicast((struct sockaddr *)&cs->desired_device_addr)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_connect_sock: cannot use multicast ip address for device operations\n");
		return false;
	}

	/* Find device. */
	if (!hdhomerun_control_connect_sock_discover(cs)) {
		return false;
	}

	/* Create socket. */
	cs->sock = hdhomerun_sock_create_tcp_ex(cs->actual_device_addr.ss_family);
	if (!cs->sock) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_connect_sock: failed to create socket (%d)\n", hdhomerun_sock_getlasterror());
		return false;
	}

	/* Initiate connection. */
	hdhomerun_sock_sockaddr_set_port((struct sockaddr *)&cs->actual_device_addr, HDHOMERUN_CONTROL_TCP_PORT);
	if (!hdhomerun_sock_connect_ex(cs->sock, (struct sockaddr *)&cs->actual_device_addr, HDHOMERUN_CONTROL_CONNECT_TIMEOUT)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_connect_sock: failed to connect (%d)\n", hdhomerun_sock_getlasterror());
		hdhomerun_control_close_sock(cs);
		return false;
	}

	/* Success. */
	return true;
}

uint32_t hdhomerun_control_get_device_id(struct hdhomerun_control_sock_t *cs)
{
	if (!hdhomerun_control_connect_sock(cs)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_device_id: connect failed\n");
		return 0;
	}

	return cs->actual_device_id;
}

uint32_t hdhomerun_control_get_device_ip(struct hdhomerun_control_sock_t *cs)
{
	if (!hdhomerun_control_connect_sock(cs)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_device_ip: connect failed\n");
		return 0;
	}

	if (cs->actual_device_addr.ss_family != AF_INET) {
		return 0;
	}

	struct sockaddr_in *actual_device_addr_in = (struct sockaddr_in *)&cs->actual_device_addr;
	return ntohl(actual_device_addr_in->sin_addr.s_addr);
}

bool hdhomerun_control_get_device_addr(struct hdhomerun_control_sock_t *cs, struct sockaddr_storage *result)
{
	if (!hdhomerun_control_connect_sock(cs)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_device_ip: connect failed\n");
		memset(result, 0, sizeof(struct sockaddr_storage));
		return false;
	}

	*result = cs->actual_device_addr;
	return hdhomerun_sock_sockaddr_is_addr((struct sockaddr *)result);
}

uint32_t hdhomerun_control_get_device_id_requested(struct hdhomerun_control_sock_t *cs)
{
	return cs->desired_device_id;
}

uint32_t hdhomerun_control_get_device_ip_requested(struct hdhomerun_control_sock_t *cs)
{
	if (cs->desired_device_addr.ss_family != AF_INET) {
		return 0;
	}

	struct sockaddr_in *desired_device_addr_in = (struct sockaddr_in *)&cs->desired_device_addr;
	return ntohl(desired_device_addr_in->sin_addr.s_addr);
}

bool hdhomerun_control_get_device_addr_requested(struct hdhomerun_control_sock_t *cs, struct sockaddr_storage *result)
{
	*result = cs->desired_device_addr;
	return hdhomerun_sock_sockaddr_is_addr((struct sockaddr *)result);
}

uint32_t hdhomerun_control_get_local_addr(struct hdhomerun_control_sock_t *cs)
{
	struct sockaddr_storage local_addr;
	if (!hdhomerun_control_get_local_addr_ex(cs, &local_addr)) {
		return 0;
	}
	if (local_addr.ss_family != AF_INET) {
		return 0;
	}

	struct sockaddr_in *local_addr_in = (struct sockaddr_in *)&local_addr;
	return ntohl(local_addr_in->sin_addr.s_addr);
}

bool hdhomerun_control_get_local_addr_ex(struct hdhomerun_control_sock_t *cs, struct sockaddr_storage *result)
{
	if (!hdhomerun_control_connect_sock(cs)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_local_addr: connect failed\n");
		return false;
	}

	if (!hdhomerun_sock_getsockname_addr_ex(cs->sock, result)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_local_addr: getsockname failed (%d)\n", hdhomerun_sock_getlasterror());
		return false;
	}

	return true;
}

static bool hdhomerun_control_send_sock(struct hdhomerun_control_sock_t *cs, struct hdhomerun_pkt_t *tx_pkt)
{
	if (!hdhomerun_sock_send(cs->sock, tx_pkt->start, tx_pkt->end - tx_pkt->start, HDHOMERUN_CONTROL_SEND_TIMEOUT)) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_send_sock: send failed (%d)\n", hdhomerun_sock_getlasterror());
		hdhomerun_control_close_sock(cs);
		return false;
	}

	return true;
}

static bool hdhomerun_control_recv_sock(struct hdhomerun_control_sock_t *cs, struct hdhomerun_pkt_t *rx_pkt, uint16_t *ptype, uint64_t recv_timeout)
{
	uint64_t stop_time = getcurrenttime() + recv_timeout;
	hdhomerun_pkt_reset(rx_pkt);

	while (1) {
		uint64_t current_time = getcurrenttime();
		if (current_time >= stop_time) {
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_recv_sock: timeout\n");
			hdhomerun_control_close_sock(cs);
			return false;
		}

		size_t length = rx_pkt->limit - rx_pkt->end;
		if (!hdhomerun_sock_recv(cs->sock, rx_pkt->end, &length, stop_time - current_time)) {
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_recv_sock: recv failed (%d)\n", hdhomerun_sock_getlasterror());
			hdhomerun_control_close_sock(cs);
			return false;
		}

		rx_pkt->end += length;

		int ret = hdhomerun_pkt_open_frame(rx_pkt, ptype);
		if (ret < 0) {
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_recv_sock: frame error\n");
			hdhomerun_control_close_sock(cs);
			return false;
		}
		if (ret > 0) {
			return true;
		}
	}
}

static int hdhomerun_control_send_recv_internal(struct hdhomerun_control_sock_t *cs, struct hdhomerun_pkt_t *tx_pkt, struct hdhomerun_pkt_t *rx_pkt, uint16_t type, uint64_t recv_timeout)
{
	hdhomerun_pkt_seal_frame(tx_pkt, type);

	int i;
	for (i = 0; i < 2; i++) {
		if (!cs->sock) {
			if (!hdhomerun_control_connect_sock(cs)) {
				hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_send_recv: connect failed\n");
				return -1;
			}
		}

		if (!hdhomerun_control_send_sock(cs, tx_pkt)) {
			continue;
		}
		if (!rx_pkt) {
			return 1;
		}

		uint16_t rsp_type;
		if (!hdhomerun_control_recv_sock(cs, rx_pkt, &rsp_type, recv_timeout)) {
			continue;
		}
		if (rsp_type != type + 1) {
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_send_recv: unexpected frame type\n");
			hdhomerun_control_close_sock(cs);
			continue;
		}

		return 1;
	}

	hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_send_recv: failed\n");
	return -1;
}

int hdhomerun_control_send_recv(struct hdhomerun_control_sock_t *cs, struct hdhomerun_pkt_t *tx_pkt, struct hdhomerun_pkt_t *rx_pkt, uint16_t type)
{
	return hdhomerun_control_send_recv_internal(cs, tx_pkt, rx_pkt, type, HDHOMERUN_CONTROL_RECV_TIMEOUT);
}

static int hdhomerun_control_get_set(struct hdhomerun_control_sock_t *cs, const char *name, const char *value, uint32_t lockkey, char **pvalue, char **perror)
{
	struct hdhomerun_pkt_t *tx_pkt = &cs->tx_pkt;
	struct hdhomerun_pkt_t *rx_pkt = &cs->rx_pkt;

	/* Request. */
	hdhomerun_pkt_reset(tx_pkt);

	size_t name_len = strlen(name) + 1;
	if (tx_pkt->end + 3 + name_len > tx_pkt->limit) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_set: request too long\n");
		return -1;
	}
	hdhomerun_pkt_write_u8(tx_pkt, HDHOMERUN_TAG_GETSET_NAME);
	hdhomerun_pkt_write_var_length(tx_pkt, name_len);
	hdhomerun_pkt_write_mem(tx_pkt, (const void *)name, name_len);

	if (value) {
		size_t value_len = strlen(value) + 1;
		if (tx_pkt->end + 3 + value_len > tx_pkt->limit) {
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_set: request too long\n");
			return -1;
		}
		hdhomerun_pkt_write_u8(tx_pkt, HDHOMERUN_TAG_GETSET_VALUE);
		hdhomerun_pkt_write_var_length(tx_pkt, value_len);
		hdhomerun_pkt_write_mem(tx_pkt, (const void *)value, value_len);
	}

	if (lockkey != 0) {
		if (tx_pkt->end + 6 > tx_pkt->limit) {
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_set: request too long\n");
			return -1;
		}
		hdhomerun_pkt_write_u8(tx_pkt, HDHOMERUN_TAG_GETSET_LOCKKEY);
		hdhomerun_pkt_write_var_length(tx_pkt, 4);
		hdhomerun_pkt_write_u32(tx_pkt, lockkey);
	}

	/* Send/Recv. */
	if (hdhomerun_control_send_recv_internal(cs, tx_pkt, rx_pkt, HDHOMERUN_TYPE_GETSET_REQ, HDHOMERUN_CONTROL_RECV_TIMEOUT) < 0) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_set: send/recv error\n");
		return -1;
	}

	/* Response. */
	while (1) {
		uint8_t tag;
		size_t len;
		uint8_t *next = hdhomerun_pkt_read_tlv(rx_pkt, &tag, &len);
		if (!next) {
			break;
		}

		switch (tag) {
		case HDHOMERUN_TAG_GETSET_VALUE:
			if (pvalue) {
				*pvalue = (char *)rx_pkt->pos;
				rx_pkt->pos[len] = 0;
			}
			if (perror) {
				*perror = NULL;
			}
			return 1;

		case HDHOMERUN_TAG_ERROR_MESSAGE:
			rx_pkt->pos[len] = 0;
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_set: %s\n", rx_pkt->pos);

			if (pvalue) {
				*pvalue = NULL;
			}
			if (perror) {
				*perror = (char *)rx_pkt->pos;
			}

			return 0;

		default:
			break;
		}

		rx_pkt->pos = next;
	}

	hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_get_set: missing response tags\n");
	return -1;
}

int hdhomerun_control_get(struct hdhomerun_control_sock_t *cs, const char *name, char **pvalue, char **perror)
{
	return hdhomerun_control_get_set(cs, name, NULL, 0, pvalue, perror);
}

int hdhomerun_control_set(struct hdhomerun_control_sock_t *cs, const char *name, const char *value, char **pvalue, char **perror)
{
	return hdhomerun_control_get_set(cs, name, value, 0, pvalue, perror);
}

int hdhomerun_control_set_with_lockkey(struct hdhomerun_control_sock_t *cs, const char *name, const char *value, uint32_t lockkey, char **pvalue, char **perror)
{
	return hdhomerun_control_get_set(cs, name, value, lockkey, pvalue, perror);
}

int hdhomerun_control_upgrade(struct hdhomerun_control_sock_t *cs, FILE *upgrade_file)
{
	struct hdhomerun_pkt_t *tx_pkt = &cs->tx_pkt;
	struct hdhomerun_pkt_t *rx_pkt = &cs->rx_pkt;
	bool upload_delay = false;
	uint32_t sequence = 0;

	/* Special case detection. */
	char *version_str;
	int ret = hdhomerun_control_get(cs, "/sys/version", &version_str, NULL);
	if (ret > 0) {
		upload_delay = strcmp(version_str, "20120704beta1") == 0;
	}

	/* Upload. */
	while (1) {
		uint8_t data[1024];
		size_t length = fread(data, 1, 1024, upgrade_file);
		if (length == 0) {
			break;
		}

		hdhomerun_pkt_reset(tx_pkt);
		hdhomerun_pkt_write_u32(tx_pkt, sequence);
		hdhomerun_pkt_write_mem(tx_pkt, data, length);

		if (hdhomerun_control_send_recv_internal(cs, tx_pkt, NULL, HDHOMERUN_TYPE_UPGRADE_REQ, 0) < 0) {
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_upgrade: send/recv failed\n");
			return -1;
		}

		sequence += (uint32_t)length;

		if (upload_delay) {
			msleep_approx(25);
		}
	}

	if (sequence == 0) {
		/* No data in file. Error, but no need to close connection. */
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_upgrade: zero length file\n");
		return 0;
	}

	/* Execute upgrade. */
	hdhomerun_pkt_reset(tx_pkt);
	hdhomerun_pkt_write_u32(tx_pkt, 0xFFFFFFFF);

	if (hdhomerun_control_send_recv_internal(cs, tx_pkt, rx_pkt, HDHOMERUN_TYPE_UPGRADE_REQ, HDHOMERUN_CONTROL_UPGRADE_TIMEOUT) < 0) {
		hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_upgrade: send/recv failed\n");
		return -1;
	}

	/* Check response. */
	while (1) {
		uint8_t tag;
		size_t len;
		uint8_t *next = hdhomerun_pkt_read_tlv(rx_pkt, &tag, &len);
		if (!next) {
			break;
		}

		switch (tag) {
		case HDHOMERUN_TAG_ERROR_MESSAGE:
			rx_pkt->pos[len] = 0;
			hdhomerun_debug_printf(cs->dbg, "hdhomerun_control_upgrade: %s\n", (char *)rx_pkt->pos);
			return 0;

		default:
			break;
		}

		rx_pkt->pos = next;
	}

	return 1;
}
