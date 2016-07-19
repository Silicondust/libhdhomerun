/*
 * hdhomerun_os_windows.h
 *
 * Copyright © 2006-2015 Silicondust USA Inc. <www.silicondust.com>.
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

#ifdef _WINRT
#include <SDKDDKVer.h>
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <wspiapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>

#ifdef LIBHDHOMERUN_DLLEXPORT
#define LIBHDHOMERUN_API __declspec(dllexport)
#endif
#ifdef LIBHDHOMERUN_DLLIMPORT
#define LIBHDHOMERUN_API __declspec(dllimport)
#endif
#ifndef LIBHDHOMERUN_API
#define LIBHDHOMERUN_API
#endif

typedef uint8_t bool_t;
typedef void (*sig_t)(int);
typedef HANDLE pthread_t;
typedef HANDLE pthread_mutex_t;
typedef HANDLE thread_cond_t;

#if !defined(va_copy)
#define va_copy(x, y) x = y
#endif

#define atoll _atoi64
#define strdup _strdup
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define fseeko _fseeki64
#define ftello _ftelli64
#define THREAD_FUNC_PREFIX DWORD WINAPI
#define THREAD_FUNC_RESULT 0

#ifdef __cplusplus
extern "C" {
#endif

extern LIBHDHOMERUN_API uint32_t random_get32(void);
extern LIBHDHOMERUN_API uint64_t getcurrenttime(void);
extern LIBHDHOMERUN_API void msleep_approx(uint64_t ms);
extern LIBHDHOMERUN_API void msleep_minimum(uint64_t ms);

extern LIBHDHOMERUN_API int pthread_create(pthread_t *tid, void *attr, LPTHREAD_START_ROUTINE start, void *arg);
extern LIBHDHOMERUN_API int pthread_join(pthread_t tid, void **value_ptr);
extern LIBHDHOMERUN_API void pthread_mutex_init(pthread_mutex_t *mutex, void *attr);
extern LIBHDHOMERUN_API void pthread_mutex_dispose(pthread_mutex_t *mutex);
extern LIBHDHOMERUN_API void pthread_mutex_lock(pthread_mutex_t *mutex);
extern LIBHDHOMERUN_API void pthread_mutex_unlock(pthread_mutex_t *mutex);

extern LIBHDHOMERUN_API void thread_cond_init(thread_cond_t *cond);
extern LIBHDHOMERUN_API void thread_cond_dispose(thread_cond_t *cond);
extern LIBHDHOMERUN_API void thread_cond_signal(thread_cond_t *cond);
extern LIBHDHOMERUN_API void thread_cond_wait(thread_cond_t *cond);
extern LIBHDHOMERUN_API void thread_cond_wait_with_timeout(thread_cond_t *cond, uint64_t max_wait_time);

extern LIBHDHOMERUN_API bool_t hdhomerun_vsprintf(char *buffer, char *end, const char *fmt, va_list ap);
extern LIBHDHOMERUN_API bool_t hdhomerun_sprintf(char *buffer, char *end, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
