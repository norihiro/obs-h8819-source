#include <inttypes.h>
#include <obs-module.h>
#include <util/platform.h>
#include <util/threading.h>
#include <util/darray.h>
#include "plugin-macros.generated.h"
#include "source.h"
#include "capdev.h"
#include "capdev-proc.h"
#include "h8819-pipe.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static capdev_t *devices = NULL;

#define N_CHANNELS 40
#ifndef OS_WINDOWS
#define PROC_4219 "obs-h8819-proc"
#else
#define PROC_4219 "obs-h8819-proc.exe"
#endif

#define LIST_DELIM '\n'

#define N_IGNORE_FIRST_PACKET 1024
#define K_OFFSET_DECAY (256 * 16)

#define DEBUG_PROC

struct source_list_s
{
	source_t *src;
	uint64_t channel_mask;
	size_t n_channels;
	int channels[N_CHANNELS];

	struct source_list_s *next;
	struct source_list_s **prev_next;
};

struct capdev_s
{
	char *name;
	capdev_t *next;
	capdev_t **prev_next;
	volatile long refcnt;

	pthread_mutex_t mutex;
	pthread_t thread;
	volatile uint64_t channel_mask;
	struct source_list_s *sources;

	int64_t ts_offset;

	int packets_received;
	int packets_missed;
};

capdev_t *capdev_get_ref(capdev_t *dev)
{
	// This function is equivalent to this code but thread-safe.
	// if (dev->refcnt > -1) {
	//   dev->refcnt ++;
	//   return dev;
	// } else {
	//   return NULL;
	// }
	long owners = os_atomic_load_long(&dev->refcnt);
	while (owners > -1) {
		// Code block below is equivalent to this code.
		// if (dev->refcnt == owners) {
		//   dev->refcnt = owners + 1;
		//   return dev;
		// } else {
		//   owners = dev->refcnt;
		// }
		if (os_atomic_compare_exchange_long(&dev->refcnt, &owners, owners + 1))
			return dev;
	}
	return NULL;
}

static capdev_t *capdev_find_unlocked(const char *device_name)
{
	for (capdev_t *dev = devices; dev; dev = dev->next) {
		if (strcmp(dev->name, device_name) == 0)
			return capdev_get_ref(dev);
	}
	return NULL;
}

static void capdev_remove_from_devices_unlocked(capdev_t *dev)
{
	if (dev && dev->prev_next) {
		*dev->prev_next = dev->next;
		if (dev->next)
			dev->next->prev_next = dev->prev_next;
		dev->prev_next = NULL;
		dev->next = NULL;
	}
}

static capdev_t *capdev_create_unlocked(const char *device_name);
static void capdev_destroy(capdev_t *dev);

capdev_t *capdev_find_or_create(const char *device_name)
{
	pthread_mutex_lock(&mutex);
	capdev_t *dev = capdev_find_unlocked(device_name);
	if (dev) {
		pthread_mutex_unlock(&mutex);
		return dev;
	}

	dev = capdev_create_unlocked(device_name);

	pthread_mutex_unlock(&mutex);

	return dev;
}

void capdev_release(capdev_t *dev)
{
	if (os_atomic_dec_long(&dev->refcnt) == -1)
		capdev_destroy(dev);
}

static void *thread_main(void *);

static capdev_t *capdev_create_unlocked(const char *device_name)
{
	capdev_t *dev = bzalloc(sizeof(struct capdev_s));
	dev->name = bstrdup(device_name);
	dev->next = devices;
	dev->prev_next = &devices;
	if (dev->next)
		dev->next->prev_next = &dev->next;
	devices = dev;

	// main construction code

	pthread_mutex_init(&dev->mutex, NULL);
	pthread_create(&dev->thread, NULL, thread_main, dev);

	return dev;
}

static void capdev_destroy(capdev_t *dev)
{
	pthread_mutex_lock(&mutex);
	capdev_remove_from_devices_unlocked(dev);
	pthread_mutex_unlock(&mutex);

	// main destroy code

	pthread_join(dev->thread, NULL);
	if (dev->sources)
		blog(LOG_ERROR, "capdev_destroy: sources are remaining");
	pthread_mutex_destroy(&dev->mutex);

	bfree(dev->name);
	bfree(dev);
}

static uint64_t channels_to_mask(const int *channels)
{
	uint64_t channel_mask = 0;
	for (size_t ix = 0; channels[ix] >= 0; ix++)
		channel_mask |= 1LL << channels[ix];
	return channel_mask;
}

void capdev_link_source(capdev_t *dev, source_t *src, const int *channels)
{
	struct source_list_s *item = bzalloc(sizeof(struct source_list_s));
	item->src = src;
	item->channel_mask = channels_to_mask(channels);
	for (item->n_channels = 0; item->n_channels < N_CHANNELS; item->n_channels++) {
		if (channels[item->n_channels] < 0)
			break;
		item->channels[item->n_channels] = channels[item->n_channels];
	}

	pthread_mutex_lock(&dev->mutex);
	item->next = dev->sources;
	item->prev_next = &dev->sources;
	dev->sources = item;
	if (item->next)
		item->next->prev_next = &item->next;
	dev->channel_mask |= item->channel_mask;

	pthread_mutex_unlock(&dev->mutex);
}

static void recalculate_channel_mask_unlocked(capdev_t *dev)
{
	uint64_t channel_mask = 0;
	for (struct source_list_s *item = dev->sources; item; item = item->next) {
		channel_mask |= item->channel_mask;
	}
	dev->channel_mask = channel_mask;
}

void capdev_update_source(capdev_t *dev, source_t *src, const int *channels)
{
	pthread_mutex_lock(&dev->mutex);

	for (struct source_list_s *item = dev->sources; item; item = item->next) {
		if (item->src != src)
			continue;

		item->channel_mask = channels_to_mask(channels);
		for (item->n_channels = 0; item->n_channels < N_CHANNELS; item->n_channels++) {
			if (channels[item->n_channels] < 0)
				break;
			item->channels[item->n_channels] = channels[item->n_channels];
		}
		break;
	}

	recalculate_channel_mask_unlocked(dev);

	pthread_mutex_unlock(&dev->mutex);
}

void capdev_unlink_source(capdev_t *dev, source_t *src)
{
	pthread_mutex_lock(&dev->mutex);

	for (struct source_list_s *item = dev->sources; item; item = item->next) {
		if (item->src != src)
			continue;

		*item->prev_next = item->next;
		if (item->next)
			item->next->prev_next = item->prev_next;
		bfree(item);
		break;
	}

	recalculate_channel_mask_unlocked(dev);

	pthread_mutex_unlock(&dev->mutex);
}

static os_process_pipe_t *thread_start_proc(struct capdev_s *dev)
{
	char *proc_path = obs_module_file(PROC_4219);
	if (!proc_path) {
		blog(LOG_ERROR, "thread_start_proc: Cannot find '" PROC_4219 "'");
		return NULL;
	}
	char proc_4219[] = PROC_4219;

	char *const cmdline[] = {proc_4219, dev ? dev->name : NULL, NULL};

#ifdef DEBUG_PROC
	blog(LOG_INFO, "thread_start_proc: '%s' '%s' '%s'", proc_path, cmdline[0], cmdline[1]);
#endif

	os_process_pipe_t *proc = os_process_pipe_create_v(proc_path, cmdline, "rwe");
	if (!proc) {
		blog(LOG_ERROR, "failed to start process '%s'", proc_path);
	}

	bfree(proc_path);

	return proc;
}

static inline void s24lep_to_fltp(float *ptr_dst, const uint8_t *ptr_src, size_t n_samples)
{
	for (size_t n = n_samples; n > 0; n--) {
		uint32_t u = ptr_src[0] | ptr_src[1] << 8 | ptr_src[2] << 16;
		int s = u & 0x800000 ? u - 0x1000000 : u;
		*ptr_dst = (float)s / 8388608.0f;
		ptr_src += 3;
		ptr_dst += 1;
	}
}

static inline int64_t sample_time(int n_samples)
{
	return n_samples * 62500 / 3; // * 1000000000 / 48000
}

static void send_blank_audio_to_all_unlocked(struct capdev_s *dev, int n, uint64_t timestamp)
{
	if (n <= 0)
		return;

	// If 2 seconds or more (n >= 96000), libobs starts to add offset, which we should avoid.
	// TS_SMOOTHING_THRESHOLD (>= 70 ms, n >= 3360) is another threshold to smooth.
	// If the blank is larger than TS_SMOOTHING_THRESHOLD, let libobs to flush the buffer.
	// Added ~10% to the threshold to ensure exceeding the threshold.
	if (n > 3700)
		return;

	float *buf = bmalloc(sizeof(float) * n);
	for (int i = 0; i < n; i++)
		buf[i] = 0.0f;

	float *fltp[N_CHANNELS];
	for (int i = 0; i < N_CHANNELS; i++)
		fltp[i] = buf;

	for (struct source_list_s *item = dev->sources; item; item = item->next)
		source_add_audio(item->src, fltp, n, timestamp - sample_time(n));

	bfree(buf);
}

static int64_t estimate_timestamp(struct capdev_s *dev, const struct capdev_proc_header_s *pkt, int n_samples)
{
	int64_t ts_obs = (int64_t)os_gettime_ns() - sample_time(n_samples);
	if (dev->packets_received == 0 || pkt->timestamp + dev->ts_offset >= ts_obs ||
	    pkt->timestamp + dev->ts_offset + 70000000 < ts_obs) {
		dev->ts_offset = ts_obs - (int64_t)pkt->timestamp;
	}
	else {
		int64_t e = ts_obs - (int64_t)pkt->timestamp - dev->ts_offset;
		dev->ts_offset += e / K_OFFSET_DECAY;
	}

	int64_t ts = pkt->timestamp + dev->ts_offset;

#if 0
	blog(LOG_INFO, "timestamp: obs: %0.6f pcap: %0.6f ts_offset: %0.6f timestamp: %0.6f", ts_obs * 1e-9,
			pkt->timestamp * 1e-9, dev->ts_offset * 1e-9, ts * 1e-9);
#endif

	return ts;
}

static void *thread_main(void *data)
{
	os_set_thread_name("h8819");
	struct capdev_s *dev = data;

	os_process_pipe_t *proc = thread_start_proc(dev);
	if (!proc) {
		return NULL;
	}

	struct capdev_proc_request_s req = {0};

	while (dev->refcnt > -1) {
		if (dev->channel_mask != req.channel_mask) {
			req.channel_mask = dev->channel_mask;
			blog(LOG_INFO, "requesting channel_mask=%" PRIx64, req.channel_mask);
			size_t ret = os_process_pipe_write(proc, (void *)&req, sizeof(req));
			if (ret != sizeof(req)) {
				blog(LOG_ERROR, "write returns %d.", (int)ret);
				break;
			}
		}

		uint32_t pipe_mask = h8819_process_pipe_wait_read(proc, 6, 70);

		if (pipe_mask & 4) {
			char buf[128];
			size_t ret = os_process_pipe_read_err(proc, (void *)buf, sizeof(buf) - 1);
			if (ret > 0) {
				if (buf[ret - 1] == '\n')
					ret--;
				if (buf[ret - 1] == '\r')
					ret--;
				buf[ret] = 0;
				blog(LOG_INFO, "%s: %s", PROC_4219, buf);
			}
			else {
				blog(LOG_INFO, "%s: Failed to read stderr", PROC_4219);
			}
		}

		if (!(pipe_mask & 2))
			continue;

		blog(LOG_INFO, "attempting to read data from the proc");

		struct capdev_proc_header_s header_data;
		size_t ret = os_process_pipe_read(proc, (void *)&header_data, sizeof(header_data));
		if (ret != sizeof(header_data)) {
			blog(LOG_ERROR, "capdev thread_main: read returns %d.", (int)ret);
			break;
		}

		uint8_t buf[1500];
		float fltp_buf[500];
		if (header_data.n_data_bytes > (int)sizeof(buf)) {
			blog(LOG_ERROR, "header_data.n_data_bytes = %d is too large.", header_data.n_data_bytes);
			break;
		}
		ret = os_process_pipe_read(proc, buf, header_data.n_data_bytes);
		if (ret != (size_t)header_data.n_data_bytes) {
			blog(LOG_ERROR, "capdev thread_main: read returns %d expected %d.", (int)ret,
			     (int)header_data.n_data_bytes);
			break;
		}

		s24lep_to_fltp(fltp_buf, buf, header_data.n_data_bytes / 3);

		const int n_channels = countones_uint64(header_data.channel_mask);
		// TODO: 12 is the expected number of samples.
		const int n_samples = n_channels ? header_data.n_data_bytes / 3 / n_channels : 12;

		float *fltp_all[N_CHANNELS];
		float *ptr = fltp_buf;
		for (int i = 0; i < N_CHANNELS; i++) {
			if (header_data.channel_mask & (1LL << i)) {
				fltp_all[i] = ptr;
				ptr += n_samples;
			}
			else
				fltp_all[i] = NULL;
		}

		// send muted audio if the data is unavailable
		for (int i = 0; i < n_samples; i++)
			ptr[i] = 0.0f;

		int64_t timestamp = estimate_timestamp(dev, &header_data, n_samples);

		if (dev->packets_received >= N_IGNORE_FIRST_PACKET) {
			pthread_mutex_lock(&dev->mutex);
			if (header_data.n_skipped_packets)
				send_blank_audio_to_all_unlocked(dev, header_data.n_skipped_packets * n_samples,
								 timestamp);

			for (struct source_list_s *item = dev->sources; item; item = item->next) {
				float *fltp[N_CHANNELS];
				for (int i = 0; i < N_CHANNELS && item->channels[i] >= 0; i++) {
					float *p = fltp_all[item->channels[i]];
					fltp[i] = p ? p : ptr;
				}

				source_add_audio(item->src, fltp, n_samples, timestamp);
			}
			pthread_mutex_unlock(&dev->mutex);
		}

		dev->packets_received++;
		dev->packets_missed += header_data.n_skipped_packets;
		if (dev->packets_received % 262144 == 0)
			blog(LOG_INFO, "h8819[%s] current status: %d packets received, %d packets dropped", dev->name,
			     dev->packets_received, dev->packets_missed);
	}

	blog(dev->packets_missed ? LOG_ERROR : LOG_INFO, "h8819[%s]: %d packets received, %d packets dropped",
	     dev->name, dev->packets_received, dev->packets_missed);

	if (proc) {
		req.flags |= CAPDEV_REQ_FLAG_EXIT;
		size_t ret = os_process_pipe_write(proc, (void *)&req, sizeof(req));
		if (ret != sizeof(req)) {
			blog(LOG_ERROR, "write returns %d.", (int)ret);
		}
	}

	while (true) {
		char buf[128];
		size_t ret = os_process_pipe_read_err(proc, (void *)buf, sizeof(buf) - 1);
		if (!ret)
			break;

		if (buf[ret - 1] == '\n')
			ret--;
		if (buf[ret - 1] == '\r')
			ret--;
		buf[ret] = 0;
		blog(LOG_INFO, "%s: %s", PROC_4219, buf);
	}

	int retval = os_process_pipe_destroy(proc);
	blog(retval ? LOG_ERROR : LOG_INFO, "exit h8819 proc %d", retval);

	return NULL;
}

void capdev_enum_devices(void (*cb)(const char *name, const char *description, void *param), void *param)
{
	os_process_pipe_t *proc = thread_start_proc(NULL);
	if (!proc)
		return;

	DARRAY(char) da;
	da_init(da);

	while (true) {
		size_t n_read = 8;
		size_t offset = da.num;
		da_resize(da, offset + n_read);
		n_read = os_process_pipe_read(proc, (void *)(da.array + offset), n_read);
		da_resize(da, offset + n_read);
		if (!n_read)
			break;
	}

	os_process_pipe_destroy(proc);

	blog(LOG_INFO, "Available devices:");
	for (size_t offset = 0; offset < da.num;) {
		const char delim[] = {LIST_DELIM};
		size_t d1 = da_find(da, delim, offset);
		if (d1 == DARRAY_INVALID)
			break;
		size_t d2 = da_find(da, delim, d1 + 1);
		if (d2 == DARRAY_INVALID)
			break;

		da.array[d1] = '\0';
		da.array[d2] = '\0';
#ifdef OS_WINDOWS
		if (d1 > offset && da.array[d1 - 1] == '\r')
			da.array[d1 - 1] = '\0';
		if (d2 > d1 + 1 && da.array[d2 - 1] == '\r')
			da.array[d2 - 1] = '\0';
#endif
		const char *name = da.array + offset;
		const char *description = da.array + d1 + 1;

		bool unlist = false;
#ifdef OS_LINUX
		if (strncmp(name, "usbmon", 6) == 0)
			unlist = true;
		else if (strcmp(name, "nflog") == 0)
			unlist = true;
		else if (strcmp(name, "nfqueue") == 0)
			unlist = true;
#endif

		blog(LOG_INFO, " '%s' '%s'%s", name, description, unlist ? " unlisted" : "");
		if (!unlist)
			cb(name, description, param);

		offset = d2 + 1;
	}

	da_free(da);
}
