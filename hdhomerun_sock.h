/*
 * hdhomerun_sock.h
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
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Windows:
 *		hdhomerun_sock.c
 *		hdhomerun_sock_windows.c
 *
 * Linux/Android:
 *		hdhomerun_sock.c
 *		hdhomerun_sock_netlink.c
 *		hdhomerun_sock_posix.c
 *
 * Mac/BSD:
 *		hdhomerun_sock.c
 *		hdhomerun_sock_getifaddrs.c
 *		hdhomerun_sock_posix.c
 */

extern LIBHDHOMERUN_API bool hdhomerun_sock_sockaddr_is_addr(const struct sockaddr *addr);
extern LIBHDHOMERUN_API uint16_t hdhomerun_sock_sockaddr_get_port(const struct sockaddr *addr);
extern LIBHDHOMERUN_API void hdhomerun_sock_sockaddr_set_port(struct sockaddr *addr, uint16_t port);
extern LIBHDHOMERUN_API void hdhomerun_sock_sockaddr_copy(struct sockaddr_storage *result, const struct sockaddr *addr);
extern LIBHDHOMERUN_API void hdhomerun_sock_sockaddr_to_ip_str(char ip_str[64], const struct sockaddr *ip_addr, bool include_ipv6_scope_id);
extern LIBHDHOMERUN_API bool hdhomerun_sock_ip_str_to_sockaddr(const char *ip_str, struct sockaddr_storage *result);

struct hdhomerun_local_ip_info_t {
	uint32_t ip_addr;
	uint32_t subnet_mask;
};

typedef void (*hdhomerun_local_ip_info2_callback_t)(void *arg, uint32_t ifindex, const struct sockaddr *local_ip, uint8_t cidr);

extern LIBHDHOMERUN_API int hdhomerun_local_ip_info(struct hdhomerun_local_ip_info_t ip_info_list[], int max_count);
extern LIBHDHOMERUN_API bool hdhomerun_local_ip_info2(int af, hdhomerun_local_ip_info2_callback_t callback, void *callback_arg);

struct hdhomerun_sock_t;

extern LIBHDHOMERUN_API struct hdhomerun_sock_t *hdhomerun_sock_create_udp(void);
extern LIBHDHOMERUN_API struct hdhomerun_sock_t *hdhomerun_sock_create_tcp(void);
extern LIBHDHOMERUN_API struct hdhomerun_sock_t *hdhomerun_sock_create_udp_ex(int af);
extern LIBHDHOMERUN_API struct hdhomerun_sock_t *hdhomerun_sock_create_tcp_ex(int af);
extern LIBHDHOMERUN_API void hdhomerun_sock_stop(struct hdhomerun_sock_t *sock);
extern LIBHDHOMERUN_API void hdhomerun_sock_destroy(struct hdhomerun_sock_t *sock);

extern LIBHDHOMERUN_API void hdhomerun_sock_set_send_buffer_size(struct hdhomerun_sock_t *sock, size_t size);
extern LIBHDHOMERUN_API void hdhomerun_sock_set_recv_buffer_size(struct hdhomerun_sock_t *sock, size_t size);
extern LIBHDHOMERUN_API void hdhomerun_sock_set_allow_reuse(struct hdhomerun_sock_t *sock);
extern LIBHDHOMERUN_API void hdhomerun_sock_set_ipv4_onesbcast(struct hdhomerun_sock_t *sock, int v);
extern LIBHDHOMERUN_API void hdhomerun_sock_set_ipv6_multicast_ifindex(struct hdhomerun_sock_t *sock, uint32_t ifindex);

extern LIBHDHOMERUN_API int hdhomerun_sock_getlasterror(void);
extern LIBHDHOMERUN_API uint32_t hdhomerun_sock_getsockname_addr(struct hdhomerun_sock_t *sock);
extern LIBHDHOMERUN_API bool hdhomerun_sock_getsockname_addr_ex(struct hdhomerun_sock_t *sock, struct sockaddr_storage *result);
extern LIBHDHOMERUN_API uint16_t hdhomerun_sock_getsockname_port(struct hdhomerun_sock_t *sock);
extern LIBHDHOMERUN_API uint32_t hdhomerun_sock_getpeername_addr(struct hdhomerun_sock_t *sock);
extern LIBHDHOMERUN_API bool hdhomerun_sock_getpeername_addr_ex(struct hdhomerun_sock_t *sock, struct sockaddr_storage *result);

extern LIBHDHOMERUN_API uint32_t hdhomerun_sock_getaddrinfo_addr(struct hdhomerun_sock_t *sock, const char *name);
extern LIBHDHOMERUN_API bool hdhomerun_sock_getaddrinfo_addr_ex(int af, const char *name, struct sockaddr_storage *result);

extern LIBHDHOMERUN_API bool hdhomerun_sock_join_multicast_group(struct hdhomerun_sock_t *sock, uint32_t multicast_ip, uint32_t local_ip);
extern LIBHDHOMERUN_API bool hdhomerun_sock_join_multicast_group_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *multicast_addr, const struct sockaddr *local_addr);
extern LIBHDHOMERUN_API bool hdhomerun_sock_leave_multicast_group(struct hdhomerun_sock_t *sock, uint32_t multicast_ip, uint32_t local_ip);
extern LIBHDHOMERUN_API bool hdhomerun_sock_leave_multicast_group_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *multicast_addr, const struct sockaddr *local_addr);

extern LIBHDHOMERUN_API bool hdhomerun_sock_bind(struct hdhomerun_sock_t *sock, uint32_t local_addr, uint16_t local_port, bool allow_reuse);
extern LIBHDHOMERUN_API bool hdhomerun_sock_bind_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *local_addr, bool allow_reuse);
extern LIBHDHOMERUN_API bool hdhomerun_sock_connect(struct hdhomerun_sock_t *sock, uint32_t remote_addr, uint16_t remote_port, uint64_t timeout);
extern LIBHDHOMERUN_API bool hdhomerun_sock_connect_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *remote_addr, uint64_t timeout);

extern LIBHDHOMERUN_API bool hdhomerun_sock_send(struct hdhomerun_sock_t *sock, const void *data, size_t length, uint64_t timeout);
extern LIBHDHOMERUN_API bool hdhomerun_sock_sendto(struct hdhomerun_sock_t *sock, uint32_t remote_addr, uint16_t remote_port, const void *data, size_t length, uint64_t timeout);
extern LIBHDHOMERUN_API bool hdhomerun_sock_sendto_ex(struct hdhomerun_sock_t *sock, const struct sockaddr *remote_addr, const void *data, size_t length, uint64_t timeout);

extern LIBHDHOMERUN_API bool hdhomerun_sock_recv(struct hdhomerun_sock_t *sock, void *data, size_t *length, uint64_t timeout);
extern LIBHDHOMERUN_API bool hdhomerun_sock_recvfrom(struct hdhomerun_sock_t *sock, uint32_t *remote_addr, uint16_t *remote_port, void *data, size_t *length, uint64_t timeout);
extern LIBHDHOMERUN_API bool hdhomerun_sock_recvfrom_ex(struct hdhomerun_sock_t *sock, struct sockaddr_storage *remote_addr, void *data, size_t *length, uint64_t timeout);

#ifdef __cplusplus
}
#endif
