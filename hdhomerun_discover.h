/*
 * hdhomerun_discover.h
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
#ifdef __cplusplus
extern "C" {
#endif

#define HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL (1 << 0)
#define HDHOMERUN_DISCOVER_FLAGS_IPV4_LOCALHOST (1 << 1)
#define HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL (1 << 2)
#define HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL (1 << 3)
#define HDHOMERUN_DISCOVER_FLAGS_IPV6_LOCALHOST (1 << 4)

struct hdhomerun_discover2_device_t;
struct hdhomerun_discover2_device_if_t;

/*
 * Discover object.
 *
 * May be maintained and reused across the lifespan of the app or may be created and destroyed for each discover.
 * If the app polls discover the same discover instance should be reused to avoid burning through local IP ports.
 */
extern LIBHDHOMERUN_API struct hdhomerun_discover_t *hdhomerun_discover_create(struct hdhomerun_debug_t *dbg);
extern LIBHDHOMERUN_API void hdhomerun_discover_destroy(struct hdhomerun_discover_t *ds);

/*
 * Discover API:
 *
 * Use hdhomerun_discover2_find_devices_broadcast() to find all devices on the local subnet.
 * flags: IPv4 only use HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL
 * flags: IPv4 and IPv6 use HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL
 * flags: Linklocal IPv6 requires special handling (scope id) - only include HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL if the app tracks scope id needed for linklocal IPv6.
 * device_types: do not use HDHOMERUN_DEVICE_TYPE_WILDCARD, instead provide an array of types the app wants to discover, for example:
 *		uint32_t device_types[2];
 *		device_types[0] = HDHOMERUN_DEVICE_TYPE_TUNER;
 *		device_types[1] = HDHOMERUN_DEVICE_TYPE_STORAGE;
 * Returns 1 when one or more devices are found.
 * Results 0 when no devices are found.
 * Returns -1 on error.
 */
extern LIBHDHOMERUN_API int hdhomerun_discover2_find_devices_targeted(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, const uint32_t device_types[], size_t device_types_count);
extern LIBHDHOMERUN_API int hdhomerun_discover2_find_devices_broadcast(struct hdhomerun_discover_t *ds, uint32_t flags, uint32_t const device_types[], size_t device_types_count);
extern LIBHDHOMERUN_API int hdhomerun_discover2_find_device_id_targeted(struct hdhomerun_discover_t *ds, const struct sockaddr *target_addr, uint32_t device_id);
extern LIBHDHOMERUN_API int hdhomerun_discover2_find_device_id_broadcast(struct hdhomerun_discover_t *ds, uint32_t flags, uint32_t device_id);

/*
 * Discover result access API.
 * 
 * Use hdhomerun_discover2_iter_device_first() and hdhomerun_discover2_iter_device_next() to iterate through discover results.
 * Use hdhomerun_discover2_device_xxx() APIs to query properties of the device.
 * 
 * Use hdhomerun_discover2_iter_device_if_first() to select the first (best) set of device URLs.
 * Use hdhomerun_discover2_device_if_xxx() to query specific device URLs.
 * 
 * In most cases hdhomerun_discover2_iter_device_if_next() will not be used as the app should use the first set of URLs.
 * 
 * Results are available until a new discover is run on the same discover object or until the discover object is destroyed. Strings shoud be copied.
 */
extern LIBHDHOMERUN_API struct hdhomerun_discover2_device_t *hdhomerun_discover2_iter_device_first(struct hdhomerun_discover_t *ds);
extern LIBHDHOMERUN_API struct hdhomerun_discover2_device_t *hdhomerun_discover2_iter_device_next(struct hdhomerun_discover2_device_t *device);
extern LIBHDHOMERUN_API struct hdhomerun_discover2_device_if_t *hdhomerun_discover2_iter_device_if_first(struct hdhomerun_discover2_device_t *device);
extern LIBHDHOMERUN_API struct hdhomerun_discover2_device_if_t *hdhomerun_discover2_iter_device_if_next(struct hdhomerun_discover2_device_if_t *device_if);

extern LIBHDHOMERUN_API bool hdhomerun_discover2_device_is_legacy(struct hdhomerun_discover2_device_t *device);
extern LIBHDHOMERUN_API bool hdhomerun_discover2_device_is_type(struct hdhomerun_discover2_device_t *device, uint32_t device_type);
extern LIBHDHOMERUN_API uint32_t hdhomerun_discover2_device_get_device_id(struct hdhomerun_discover2_device_t *device);
extern LIBHDHOMERUN_API const char *hdhomerun_discover2_device_get_storage_id(struct hdhomerun_discover2_device_t *device);
extern LIBHDHOMERUN_API uint8_t hdhomerun_discover2_device_get_tuner_count(struct hdhomerun_discover2_device_t *device);
extern LIBHDHOMERUN_API const char *hdhomerun_discover2_device_get_device_auth(struct hdhomerun_discover2_device_t *device);

extern LIBHDHOMERUN_API bool hdhomerun_discover2_device_if_addr_is_ipv4(struct hdhomerun_discover2_device_if_t *device_if);
extern LIBHDHOMERUN_API bool hdhomerun_discover2_device_if_addr_is_ipv6_linklocal(struct hdhomerun_discover2_device_if_t *device_if);
extern LIBHDHOMERUN_API void hdhomerun_discover2_device_if_get_ip_addr(struct hdhomerun_discover2_device_if_t *device_if, struct sockaddr_storage *ip_addr);
extern LIBHDHOMERUN_API const char *hdhomerun_discover2_device_if_get_base_url(struct hdhomerun_discover2_device_if_t *device_if);
extern LIBHDHOMERUN_API const char *hdhomerun_discover2_device_if_get_lineup_url(struct hdhomerun_discover2_device_if_t *device_if);
extern LIBHDHOMERUN_API const char *hdhomerun_discover2_device_if_get_storage_url(struct hdhomerun_discover2_device_if_t *device_if);

/*
 * Verify that the device ID given is valid.
 *
 * The device ID contains a self-check sequence that detects common user input errors including
 * single-digit errors and two digit transposition errors.
 *
 * Returns true if valid.
 * Returns false if not valid.
 */
extern LIBHDHOMERUN_API bool hdhomerun_discover_validate_device_id(uint32_t device_id);

/*
 * Detect if an IP address is multicast.
 *
 * Returns true if multicast.
 * Returns false if zero, unicast, expermental, or broadcast.
 */
extern LIBHDHOMERUN_API bool hdhomerun_discover_is_ip_multicast(uint32_t ip_addr);
extern LIBHDHOMERUN_API bool hdhomerun_discover_is_ip_multicast_ex(const struct sockaddr *ip_addr);

/*
 * Legacy API - not for new applications.
 *
 * The device information is stored in caller-supplied array of hdhomerun_discover_device_t vars.
 * Multiple attempts are made to find devices.
 * Execution time is typically 400ms unless max_count is reached.
 *
 * Set target_ip to zero to auto-detect the IP address.
 * Set device_type to HDHOMERUN_DEVICE_TYPE_TUNER to detect HDHomeRun tuner devices.
 * Set device_id to HDHOMERUN_DEVICE_ID_WILDCARD to detect all device ids.
 *
 * Returns the number of devices found.
 * Retruns -1 on error.
 */

struct hdhomerun_discover_device_t {
	uint32_t ip_addr;
	uint32_t device_type;
	uint32_t device_id;
	uint8_t tuner_count;
	bool is_legacy;
	char device_auth[25];
	char base_url[29];
};

struct hdhomerun_discover_device_v3_t {
	uint32_t ip_addr;
	uint32_t device_type;
	uint32_t device_id;
	uint8_t tuner_count;
	bool is_legacy;
	char device_auth[25];
	char base_url[29];

	char storage_id[37];
	char lineup_url[128];
	char storage_url[128];
};

extern LIBHDHOMERUN_API int hdhomerun_discover_find_devices_custom_v2(uint32_t target_ip, uint32_t device_type_match, uint32_t device_id_match, struct hdhomerun_discover_device_t result_list[], int max_count);
extern LIBHDHOMERUN_API int hdhomerun_discover_find_devices_custom_v3(uint32_t target_ip, uint32_t device_type_match, uint32_t device_id_match, struct hdhomerun_discover_device_v3_t result_list[], int max_count);

extern LIBHDHOMERUN_API int hdhomerun_discover_find_devices_v2(struct hdhomerun_discover_t *ds, uint32_t target_ip, uint32_t device_type_match, uint32_t device_id_match, struct hdhomerun_discover_device_t result_list[], int max_count);
extern LIBHDHOMERUN_API int hdhomerun_discover_find_devices_v3(struct hdhomerun_discover_t *ds, uint32_t target_ip, uint32_t device_type_match, uint32_t device_id_match, struct hdhomerun_discover_device_v3_t result_list[], int max_count);

#ifdef __cplusplus
}
#endif
