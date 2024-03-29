/*
 * hdhomerun_config.c
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

static const char *appname;

struct hdhomerun_device_t *hd;

static int help(void)
{
	printf("Usage:\n");
	printf("\t%s discover [-4] [-6] [--dedupe] [<ip>]\n", appname);
	printf("\t%s <id> get help\n", appname);
	printf("\t%s <id> get <item>\n", appname);
	printf("\t%s <id> set <item> <value>\n", appname);
	printf("\t%s <id> scan <tuner> [<filename>]\n", appname);
	printf("\t%s <id> save <tuner> <filename>\n", appname);
	printf("\t%s <id> upgrade <filename>\n", appname);
	return -1;
}

static void extract_appname(const char *argv0)
{
	const char *ptr = strrchr(argv0, '/');
	if (ptr) {
		argv0 = ptr + 1;
	}
	ptr = strrchr(argv0, '\\');
	if (ptr) {
		argv0 = ptr + 1;
	}
	appname = argv0;
}

static bool contains(const char *arg, const char *cmpstr)
{
	if (strcmp(arg, cmpstr) == 0) {
		return true;
	}

	if (*arg++ != '-') {
		return false;
	}
	if (*arg++ != '-') {
		return false;
	}
	if (strcmp(arg, cmpstr) == 0) {
		return true;
	}

	return false;
}

static int discover_print(int argc, char *argv[])
{
	const char *target_ip_str = NULL;
	uint32_t flags = 0;
	bool dedupe = false;

	while (argc--) {
		char *param = *argv++;
		if (param[0] != '-') {
			target_ip_str = param;
			continue;
		}

		if (contains(param, "-4")) {
			flags |= HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL;
			continue;
		}
		if (contains(param, "-6")) {
			flags |= HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL;
			continue;
		}

		if (contains(param, "dedupe")) {
			dedupe = true;
			continue;
		}
	}

	if (flags == 0) {
		flags = HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_GENERAL | HDHOMERUN_DISCOVER_FLAGS_IPV6_LINKLOCAL;
	}

	struct hdhomerun_discover_t *ds = hdhomerun_discover_create(NULL);
	if (!ds) {
		fprintf(stderr, "resource error\n");
		return -1;
	}

	/* Most applications will specify a list of specific types rather than wildcard */
	uint32_t device_types[1];
	device_types[0] = HDHOMERUN_DEVICE_TYPE_WILDCARD;

	int ret;
	if (target_ip_str) {
		struct sockaddr_storage target_addr;
		if (!hdhomerun_sock_ip_str_to_sockaddr(target_ip_str , &target_addr)) {
			fprintf(stderr, "invalid ip address: %s\n", target_ip_str);
			hdhomerun_discover_destroy(ds);
			return -1;
		}
		ret = hdhomerun_discover2_find_devices_targeted(ds, (struct sockaddr *)&target_addr, device_types, 1);
	} else {
		ret = hdhomerun_discover2_find_devices_broadcast(ds, flags, device_types, 1);
	}

	if (ret < 0) {
		fprintf(stderr, "error sending discover request\n");
		hdhomerun_discover_destroy(ds);
		return -1;
	}

	if (ret == 0) {
		printf("no devices found\n");
		hdhomerun_discover_destroy(ds);
		return 0;
	}

	struct hdhomerun_discover2_device_t *device = hdhomerun_discover2_iter_device_first(ds);
	while (device) {
		uint32_t device_id = hdhomerun_discover2_device_get_device_id(device);
		if (device_id == 0) {
			device = hdhomerun_discover2_iter_device_next(device);
			continue;
		}

		struct hdhomerun_discover2_device_if_t *device_if = hdhomerun_discover2_iter_device_if_first(device);
		while (device_if) {
			struct sockaddr_storage ip_addr;
			hdhomerun_discover2_device_if_get_ip_addr(device_if, &ip_addr);

			char ip_str[64];
			hdhomerun_sock_sockaddr_to_ip_str(ip_str, (struct sockaddr *)&ip_addr, true);
			printf("hdhomerun device %08X found at %s\n", device_id, ip_str);

			if (dedupe) {
				break;
			}

			device_if = hdhomerun_discover2_iter_device_if_next(device_if);
		}

		device = hdhomerun_discover2_iter_device_next(device);
	}

	hdhomerun_discover_destroy(ds);
	return 1;
}

static int cmd_get(const char *item)
{
	char *ret_value;
	char *ret_error;
	if (hdhomerun_device_get_var(hd, item, &ret_value, &ret_error) < 0) {
		fprintf(stderr, "communication error sending request to hdhomerun device\n");
		return -1;
	}

	if (ret_error) {
		printf("%s\n", ret_error);
		return 0;
	}

	printf("%s\n", ret_value);
	return 1;
}

static int cmd_set_internal(const char *item, const char *value)
{
	char *ret_error;
	if (hdhomerun_device_set_var(hd, item, value, NULL, &ret_error) < 0) {
		fprintf(stderr, "communication error sending request to hdhomerun device\n");
		return -1;
	}

	if (ret_error) {
		printf("%s\n", ret_error);
		return 0;
	}

	return 1;
}

static int cmd_set(const char *item, const char *value)
{
	if (strcmp(value, "-") == 0) {
		char *buffer = NULL;
		size_t pos = 0;

		while (1) {
			char *new_buffer = (char *)realloc(buffer, pos + 1024);
			if (!new_buffer) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}

			buffer = new_buffer;
			size_t size = fread(buffer + pos, 1, 1024, stdin);
			pos += size;

			if (size < 1024) {
				break;
			}
		}

		buffer[pos] = 0;

		int ret = cmd_set_internal(item, buffer);

		free(buffer);
		return ret;
	}

	return cmd_set_internal(item, value);
}

static volatile sig_atomic_t sigabort_flag = false;
static volatile sig_atomic_t siginfo_flag = false;
 
static void sigabort_handler(int arg)
{
	sigabort_flag = true;
}

static void siginfo_handler(int arg)
{
	siginfo_flag = true;
}

static void register_signal_handlers(sig_t sigpipe_handler, sig_t sigint_handler, sig_t siginfo_handler)
{
#if defined(SIGPIPE)
	signal(SIGPIPE, sigpipe_handler);
#endif
#if defined(SIGINT)
	signal(SIGINT, sigint_handler);
#endif
#if defined(SIGINFO)
	signal(SIGINFO, siginfo_handler);
#endif
}

static void cmd_scan_printf(FILE *fp, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (fp) {
		va_list apc;
		va_copy(apc, ap);

		vfprintf(fp, fmt, apc);
		fflush(fp);

		va_end(apc);
	}

	vprintf(fmt, ap);
	fflush(stdout);

	va_end(ap);
}

static int cmd_scan(const char *tuner_str, const char *filename)
{
	if (hdhomerun_device_set_tuner_from_str(hd, tuner_str) <= 0) {
		fprintf(stderr, "invalid tuner number\n");
		return -1;
	}

	char *ret_error;
	if (hdhomerun_device_tuner_lockkey_request(hd, &ret_error) <= 0) {
		fprintf(stderr, "failed to lock tuner\n");
		if (ret_error) {
			fprintf(stderr, "%s\n", ret_error);
		}
		return -1;
	}

	hdhomerun_device_set_tuner_target(hd, "none");

	char *channelmap;
	if (hdhomerun_device_get_tuner_channelmap(hd, &channelmap) <= 0) {
		fprintf(stderr, "failed to query channelmap from device\n");
		return -1;
	}

	const char *channelmap_scan_group = hdhomerun_channelmap_get_channelmap_scan_group(channelmap);
	if (!channelmap_scan_group) {
		fprintf(stderr, "unknown channelmap '%s'\n", channelmap);
		return -1;
	}

	if (hdhomerun_device_channelscan_init(hd, channelmap_scan_group) <= 0) {
		fprintf(stderr, "failed to initialize channel scan\n");
		return -1;
	}

	FILE *fp = NULL;
	if (filename) {
		fp = fopen(filename, "w");
		if (!fp) {
			fprintf(stderr, "unable to create file: %s\n", filename);
			return -1;
		}
	}

	register_signal_handlers(sigabort_handler, sigabort_handler, siginfo_handler);

	int ret = 0;
	while (!sigabort_flag) {
		struct hdhomerun_channelscan_result_t result;
		ret = hdhomerun_device_channelscan_advance(hd, &result);
		if (ret <= 0) {
			break;
		}

		cmd_scan_printf(fp, "SCANNING: %u (%s)\n",
			(unsigned int)result.frequency, result.channel_str
		);

		ret = hdhomerun_device_channelscan_detect(hd, &result);
		if (ret < 0) {
			break;
		}
		if (ret == 0) {
			continue;
		}

		cmd_scan_printf(fp, "LOCK: %s (ss=%u snq=%u seq=%u)\n",
			result.status.lock_str, result.status.signal_strength,
			result.status.signal_to_noise_quality, result.status.symbol_error_quality
		);

		if (result.transport_stream_id_detected) {
			cmd_scan_printf(fp, "TSID: 0x%04X\n", result.transport_stream_id);
		}
		if (result.original_network_id_detected) {
			cmd_scan_printf(fp, "ONID: 0x%04X\n", result.original_network_id);
		}

		int i;
		for (i = 0; i < result.program_count; i++) {
			struct hdhomerun_channelscan_program_t *program = &result.programs[i];
			cmd_scan_printf(fp, "PROGRAM %s\n", program->program_str);
		}
	}

	hdhomerun_device_tuner_lockkey_release(hd);

	if (fp) {
		fclose(fp);
	}
	if (ret < 0) {
		fprintf(stderr, "communication error sending request to hdhomerun device\n");
	}
	return ret;
}

static void cmd_save_print_stats(void)
{
	struct hdhomerun_video_stats_t stats;
	hdhomerun_device_get_video_stats(hd, &stats);

	fprintf(stderr, "%u packets received, %u overflow errors, %u network errors, %u transport errors, %u sequence errors\n",
		(unsigned int)stats.packet_count, 
		(unsigned int)stats.overflow_error_count,
		(unsigned int)stats.network_error_count, 
		(unsigned int)stats.transport_error_count, 
		(unsigned int)stats.sequence_error_count
	);
}

static int cmd_save(const char *tuner_str, const char *filename)
{
	if (hdhomerun_device_set_tuner_from_str(hd, tuner_str) <= 0) {
		fprintf(stderr, "invalid tuner number\n");
		return -1;
	}

	FILE *fp;
	if (strcmp(filename, "null") == 0) {
		fp = NULL;
	} else if (strcmp(filename, "-") == 0) {
		fp = stdout;
	} else {
		fp = fopen(filename, "wb");
		if (!fp) {
			fprintf(stderr, "unable to create file %s\n", filename);
			return -1;
		}
	}

	int ret = hdhomerun_device_stream_start(hd);
	if (ret <= 0) {
		fprintf(stderr, "unable to start stream\n");
		if (fp && fp != stdout) {
			fclose(fp);
		}
		return ret;
	}

	register_signal_handlers(sigabort_handler, sigabort_handler, siginfo_handler);

	struct hdhomerun_video_stats_t stats_old, stats_cur;
	hdhomerun_device_get_video_stats(hd, &stats_old);

	uint64_t next_progress = getcurrenttime() + 1000;

	while (!sigabort_flag) {
		uint64_t loop_start_time = getcurrenttime();

		if (siginfo_flag) {
			fprintf(stderr, "\n");
			cmd_save_print_stats();
			siginfo_flag = false;
		}

		size_t actual_size;
		uint8_t *ptr = hdhomerun_device_stream_recv(hd, VIDEO_DATA_BUFFER_SIZE_1S, &actual_size);
		if (!ptr) {
			msleep_approx(64);
			continue;
		}

		if (fp) {
			if (fwrite(ptr, 1, actual_size, fp) != actual_size) {
				fprintf(stderr, "error writing output\n");
				return -1;
			}
		}

		if (loop_start_time >= next_progress) {
			next_progress += 1000;
			if (loop_start_time >= next_progress) {
				next_progress = loop_start_time + 1000;
			}

			/* Windows - indicate activity to suppress auto sleep mode. */
			#if defined(_WIN32)
			SetThreadExecutionState(ES_SYSTEM_REQUIRED);
			#endif

			/* Video stats. */
			hdhomerun_device_get_video_stats(hd, &stats_cur);

			if (stats_cur.overflow_error_count > stats_old.overflow_error_count) {
				fprintf(stderr, "o");
			} else if (stats_cur.network_error_count > stats_old.network_error_count) {
				fprintf(stderr, "n");
			} else if (stats_cur.transport_error_count > stats_old.transport_error_count) {
				fprintf(stderr, "t");
			} else if (stats_cur.sequence_error_count > stats_old.sequence_error_count) {
				fprintf(stderr, "s");
			} else {
				fprintf(stderr, ".");
			}

			stats_old = stats_cur;
			fflush(stderr);
		}

		int32_t delay = 64 - (int32_t)(getcurrenttime() - loop_start_time);
		if (delay <= 0) {
			continue;
		}

		msleep_approx(delay);
	}

	if (fp) {
		fclose(fp);
	}

	hdhomerun_device_stream_stop(hd);

	fprintf(stderr, "\n");
	fprintf(stderr, "-- Video statistics --\n");
	cmd_save_print_stats();

	return 0;
}

static int cmd_upgrade(const char *filename)
{
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "unable to open file %s\n", filename);
		return -1;
	}

	printf("uploading firmware...\n");
	if (hdhomerun_device_upgrade(hd, fp) <= 0) {
		fprintf(stderr, "error sending upgrade file to hdhomerun device\n");
		fclose(fp);
		return -1;
	}

	fclose(fp);
	msleep_minimum(2000);

	printf("upgrading firmware...\n");
	msleep_minimum(8000);

	printf("rebooting...\n");
	int count = 0;
	char *version_str;
	while (1) {
		if (hdhomerun_device_get_version(hd, &version_str, NULL) >= 0) {
			break;
		}

		count++;
		if (count > 30) {
			fprintf(stderr, "error finding device after firmware upgrade\n");
			return -1;
		}

		msleep_minimum(1000);
	}

	printf("upgrade complete - now running firmware %s\n", version_str);
	return 0;
}

static int cmd_execute(void)
{
	char *ret_value;
	char *ret_error;
	if (hdhomerun_device_get_var(hd, "/sys/boot", &ret_value, &ret_error) < 0) {
		fprintf(stderr, "communication error sending request to hdhomerun device\n");
		return -1;
	}

	if (ret_error) {
		printf("%s\n", ret_error);
		return 0;
	}

	char *end = ret_value + strlen(ret_value);
	char *pos = ret_value;

	while (1) {
		if (pos >= end) {
			break;
		}

		char *eol_r = strchr(pos, '\r');
		if (!eol_r) {
			eol_r = end;
		}

		char *eol_n = strchr(pos, '\n');
		if (!eol_n) {
			eol_n = end;
		}

		char *eol = eol_r;
		if (eol_n < eol) {
			eol = eol_n;
		}

		char *sep = strchr(pos, ' ');
		if (!sep || sep > eol) {
			pos = eol + 1;
			continue;
		}

		*sep = 0;
		*eol = 0;

		char *item = pos;
		char *value = sep + 1;

		printf("set %s \"%s\"\n", item, value);

		cmd_set_internal(item, value);

		pos = eol + 1;
	}

	return 1;
}

static int main_cmd(int argc, char *argv[])
{
	if (argc < 1) {
		return help();
	}

	char *cmd = *argv++; argc--;

	if (contains(cmd, "key")) {
		if (argc < 2) {
			return help();
		}
		uint32_t lockkey = (uint32_t)strtoul(argv[0], NULL, 0);
		hdhomerun_device_tuner_lockkey_use_value(hd, lockkey);

		cmd = argv[1];
		argv+=2; argc-=2;
	}

	if (contains(cmd, "get")) {
		if (argc < 1) {
			return help();
		}
		return cmd_get(argv[0]);
	}

	if (contains(cmd, "set")) {
		if (argc < 2) {
			return help();
		}
		return cmd_set(argv[0], argv[1]);
	}

	if (contains(cmd, "scan")) {
		if (argc < 1) {
			return help();
		}
		if (argc < 2) {
			return cmd_scan(argv[0], NULL);
		} else {
			return cmd_scan(argv[0], argv[1]);
		}
	}

	if (contains(cmd, "save")) {
		if (argc < 2) {
			return help();
		}
		return cmd_save(argv[0], argv[1]);
	}

	if (contains(cmd, "upgrade")) {
		if (argc < 1) {
			return help();
		}
		return cmd_upgrade(argv[0]);
	}

	if (contains(cmd, "execute")) {
		return cmd_execute();
	}

	return help();
}

static int main_internal(int argc, char *argv[])
{
#if defined(_WIN32)
	/* Configure console for UTF-8. */
	SetConsoleOutputCP(CP_UTF8);
	/* Initialize network socket support. */
	WORD wVersionRequested = MAKEWORD(2, 0);
	WSADATA wsaData;
	(void)WSAStartup(wVersionRequested, &wsaData);
#endif

	extract_appname(argv[0]);
	argv++;
	argc--;

	if (argc == 0) {
		return help();
	}

	char *id_str = *argv++; argc--;
	if (contains(id_str, "help")) {
		return help();
	}
	if (contains(id_str, "discover")) {
		return discover_print(argc, argv);
	}

	/* Device object. */
	hd = hdhomerun_device_create_from_str(id_str, NULL);
	if (!hd) {
		fprintf(stderr, "invalid device id: %s\n", id_str);
		return -1;
	}

	/* Device ID check. */
	uint32_t device_id_requested = hdhomerun_device_get_device_id_requested(hd);
	if (!hdhomerun_discover_validate_device_id(device_id_requested)) {
		fprintf(stderr, "invalid device id: %08X\n", (unsigned int)device_id_requested);
	}

	/* Connect to device and check model. */
	const char *model = hdhomerun_device_get_model_str(hd);
	if (!model) {
		fprintf(stderr, "unable to connect to device\n");
		hdhomerun_device_destroy(hd);
		return -1;
	}

	/* Command. */
	int ret = main_cmd(argc, argv);

	/* Cleanup. */
	hdhomerun_device_destroy(hd);

	/* Complete. */
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = main_internal(argc, argv);
	if (ret <= 0) {
		return 1;
	}
	return 0;
}
