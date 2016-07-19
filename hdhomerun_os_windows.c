/*
 * hdhomerun_os_windows.c
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

#include "hdhomerun.h"

#if defined(_WINRT)
uint32_t random_get32(void)
{
	return (uint32_t)getcurrenttime();
}
#else
uint32_t random_get32(void)
{
	static DWORD random_get32_context_tls = 0xFFFFFFFF;
	if (random_get32_context_tls == 0xFFFFFFFF) {
		random_get32_context_tls = TlsAlloc();
	}

	HCRYPTPROV *phProv = (HCRYPTPROV *)TlsGetValue(random_get32_context_tls);
	if (!phProv) {
		phProv = (HCRYPTPROV *)calloc(1, sizeof(HCRYPTPROV));
		CryptAcquireContext(phProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
		TlsSetValue(random_get32_context_tls, phProv);
	}

	uint32_t Result;
	if (!CryptGenRandom(*phProv, sizeof(Result), (BYTE *)&Result)) {
		return (uint32_t)getcurrenttime();
	}

	return Result;
}
#endif

uint64_t getcurrenttime(void)
{
	return GetTickCount64();
}

void msleep_approx(uint64_t ms)
{
	Sleep((DWORD)ms);
}

void msleep_minimum(uint64_t ms)
{
	uint64_t stop_time = getcurrenttime() + ms;

	while (1) {
		uint64_t current_time = getcurrenttime();
		if (current_time >= stop_time) {
			return;
		}

		msleep_approx(stop_time - current_time);
	}
}

int pthread_create(pthread_t *tid, void *attr, LPTHREAD_START_ROUTINE start, void *arg)
{
	*tid = CreateThread(NULL, 0, start, arg, 0, NULL);
	if (!*tid) {
		return (int)GetLastError();
	}
	return 0;
}

int pthread_join(pthread_t tid, void **value_ptr)
{
	while (1) {
		DWORD ExitCode = 0;
		if (!GetExitCodeThread(tid, &ExitCode)) {
			return (int)GetLastError();
		}
		if (ExitCode != STILL_ACTIVE) {
			return 0;
		}
	}
}

void pthread_mutex_init(pthread_mutex_t *mutex, void *attr)
{
	*mutex = CreateMutex(NULL, FALSE, NULL);
}

void pthread_mutex_dispose(pthread_mutex_t *mutex)
{
	CloseHandle(*mutex);
}

void pthread_mutex_lock(pthread_mutex_t *mutex)
{
	WaitForSingleObject(*mutex, INFINITE);
}

void pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	ReleaseMutex(*mutex);
}

void thread_cond_init(thread_cond_t *cond)
{
	*cond = CreateEvent(NULL, FALSE, FALSE, NULL);
}

void thread_cond_dispose(thread_cond_t *cond)
{
	CloseHandle(*cond);
}

void thread_cond_signal(thread_cond_t *cond)
{
	SetEvent(*cond);
}

void thread_cond_wait(thread_cond_t *cond)
{
	WaitForSingleObject(*cond, INFINITE);
}

void thread_cond_wait_with_timeout(thread_cond_t *cond, uint64_t max_wait_time)
{
	WaitForSingleObject(*cond, (DWORD)max_wait_time);
}

bool_t hdhomerun_vsprintf(char *buffer, char *end, const char *fmt, va_list ap)
{
	if (buffer >= end) {
		return FALSE;
	}

	int length = _vsnprintf(buffer, end - buffer - 1, fmt, ap);
	if (length < 0) {
		*buffer = 0;
		return FALSE;
	}

	if (buffer + length + 1 > end) {
		*(end - 1) = 0;
		return FALSE;

	}

	return TRUE;
}

bool_t hdhomerun_sprintf(char *buffer, char *end, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	bool_t result = hdhomerun_vsprintf(buffer, end, fmt, ap);
	va_end(ap);
	return result;
}
