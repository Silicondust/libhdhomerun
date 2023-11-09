/*
 * hdhomerun_discover_example.c
 *
 * Copyright © 2023 Silicondust USA Inc. <www.silicondust.com>.
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

int main(int argc, char *argv[])
{
#if defined(_WIN32)
	WORD wVersionRequested = MAKEWORD(2, 0);
	WSADATA wsaData;
	(void)WSAStartup(wVersionRequested, &wsaData);
#endif

	/*
	 * Create discover object
	 */
	struct hdhomerun_discover_t *ds = hdhomerun_discover_create(NULL);
	if (!ds) {
		fprintf(stderr, "hdhomerun_discover_create failed\n");
		return 1;
	}

	/*
	 * Execute discover
	 *
	 * Remove HDHOMERUN_DISCOVER_FLAGS_IPV4_LOCALHOST and HDHOMERUN_DISCOVER_FLAGS_IPV6_LOCALHOST if the app platform cannot have the record engine installed.
	 * Remove HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL if the app does not support ipv6 scope_id required for all link-local network operations.
	 */
	uint32_t flags = HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV4_LOCALHOST | HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_LOCALHOST;

	uint32_t device_types[2];
	device_types[0] = HDHOMERUN_DEVICE_TYPE_TUNER;
	device_types[1] = HDHOMERUN_DEVICE_TYPE_STORAGE;

	if (hdhomerun_discover2_find_devices_broadcast(ds, flags, device_types, 2) < 0) {
		fprintf(stderr, "hdhomerun_discover2_find_devices_broadcast failed\n");
		return 1;
	}

	/*
	 * Print results
	 */
	struct hdhomerun_discover2_device_t *device = hdhomerun_discover2_iter_device_first(ds);
	while (device) {
		uint32_t device_id = hdhomerun_discover2_device_get_device_id(device);
		const char *storage_id = hdhomerun_discover2_device_get_storage_id(device);
		const char *device_auth = hdhomerun_discover2_device_get_device_auth(device);
		bool is_tuner = hdhomerun_discover2_device_is_type(device, HDHOMERUN_DEVICE_TYPE_TUNER);
		bool is_storage = hdhomerun_discover2_device_is_type(device, HDHOMERUN_DEVICE_TYPE_STORAGE);
		bool is_legacy = hdhomerun_discover2_device_is_legacy(device);
		uint8_t tuner_count = hdhomerun_discover2_device_get_tuner_count(device);

		struct hdhomerun_discover2_device_if_t *device_if = hdhomerun_discover2_iter_device_if_first(device);

		struct sockaddr_storage ip_address;
		hdhomerun_discover2_device_if_get_ip_addr(device_if, &ip_address);
		char ip_address_str[64];
		hdhomerun_sock_sockaddr_to_ip_str(ip_address_str, (struct sockaddr *)&ip_address, true);

		const char *base_url = hdhomerun_discover2_device_if_get_base_url(device_if);
		const char *lineup_url = hdhomerun_discover2_device_if_get_lineup_url(device_if);
		const char *storage_url = hdhomerun_discover2_device_if_get_storage_url(device_if);

		printf("found:\n");

		printf("\tip_address: %s\n", ip_address_str);
		printf("\tbase_url: %s\n", base_url);
		printf("\tlineup_url: %s\n", lineup_url);
		printf("\tstorage_url: %s\n", storage_url);

		printf("\tdevice_id: %08X\n", device_id);
		printf("\tstorage_id: %s\n", storage_id);
		printf("\tdevice_auth: %s\n", device_auth);
		printf("\tis_tuner: %u\n", is_tuner);
		printf("\tis_storage: %u\n", is_storage);
		printf("\tis_legacy: %u\n", is_legacy);
		printf("\ttuner_count: %u\n", tuner_count);

		printf("\n");

		device = hdhomerun_discover2_iter_device_next(device);
	}

	/*
	 * Free discover object
	 */
	hdhomerun_discover_destroy(ds);
	return 0;
}
