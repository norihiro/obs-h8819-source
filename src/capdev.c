#include <unistd.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <obs-module.h>
#include <util/threading.h>
#include "plugin-macros.generated.h"
#include "source.h"
#include "capdev.h"
#include "capdev-proc.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static capdev_t *devices = NULL;

#define N_CHANNELS 40
#define PROC_4219 "obs-h8819-proc"

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

	int packets_received;
	int packets_missed;

	pid_t pid;
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

bool thread_start_proc(struct capdev_s *dev, int *fd_req, int *fd_data)
{
	int pipe_req[2];
	int pipe_data[2];

	if (pipe(pipe_req) < 0) {
		blog(LOG_ERROR, "failed to create pipe");
		return false;
	}

	if (pipe(pipe_data) < 0) {
		blog(LOG_ERROR, "failed to create pipe");
		close(pipe_req[0]);
		close(pipe_req[1]);
		return false;
	}

	// TODO: consider using vfork
	pid_t pid = fork();
	if (pid < 0) {
		blog(LOG_ERROR, "failed to fork");
		close(pipe_req[0]);
		close(pipe_req[1]);
		close(pipe_data[0]);
		close(pipe_data[1]);
		return false;
	}

	if (pid == 0) {
		// I'm a child
		dup2(pipe_req[0], 0);
		dup2(pipe_data[1], 1);
		close(pipe_req[0]);
		close(pipe_req[1]);
		close(pipe_data[0]);
		close(pipe_data[1]);
		char *proc_path = obs_module_file(PROC_4219);
		if (execlp(proc_path, PROC_4219, dev->name, NULL) < 0) {
			fprintf(stderr, "Error: failed to exec \"%s\"\n", proc_path);
			close(0);
			close(1);
			exit(1);
		}
	}

	*fd_req = pipe_req[1];
	*fd_data = pipe_data[0];
	dev->pid = pid;

	return true;
}

struct data_info_s
{
	const char *buf[N_CHANNELS];
	int n_samples;
};

static void calculate_data_info(struct capdev_proc_header_s *h, const char *buf, struct data_info_s *info)
{
	const char *ptr = buf;
	const int n_channels = countones_uint64(h->channel_mask);
	size_t inc = n_channels ? h->n_data_bytes / n_channels : 0;
	info->n_samples = inc / 3;
	for (size_t i = 0; i < N_CHANNELS; i++) {
		if (h->channel_mask & (1LL << i)) {
			info->buf[i] = ptr;
			ptr += inc;
		}
		else {
			info->buf[i] = NULL;
		}
	}
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

static void send_blank_audio_to_all_unlocked(struct capdev_s *dev, int n)
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
		source_add_audio(item->src, fltp, n);

	bfree(buf);
}

static void *thread_main(void *data)
{
	os_set_thread_name("h8819");
	struct capdev_s *dev = data;

	int fd_req = -1, fd_data = -1;
	if (!thread_start_proc(dev, &fd_req, &fd_data)) {
		return NULL;
	}

	struct capdev_proc_request_s req = {0};

	while (dev->refcnt > -1) {
		if (dev->channel_mask != req.channel_mask) {
			req.channel_mask = dev->channel_mask;
			blog(LOG_INFO, "requesting channel_mask=%" PRIx64, req.channel_mask);
			write(fd_req, &req, sizeof(req));
		}

		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(fd_data, &readfds);
		struct timeval timeout = {.tv_sec = 0, .tv_usec = 50 * 1000};
		int ret_select = select(fd_data + 1, &readfds, NULL, NULL, &timeout);

		if (ret_select <= 0)
			continue;

		struct capdev_proc_header_s header_data;
		struct data_info_s info;
		ssize_t ret = read(fd_data, &header_data, sizeof(header_data));
		if (ret != sizeof(header_data)) {
			blog(LOG_ERROR, "capdev thread_main: read returns %d.", (int)ret);
			break;
		}

		uint8_t buf[1500];
		float fltp_buf[500];
		if (header_data.n_data_bytes > sizeof(buf)) {
			blog(LOG_ERROR, "header_data.n_data_bytes = %d is too large.", header_data.n_data_bytes);
			break;
		}
		ret = read(fd_data, buf, header_data.n_data_bytes);
		if (ret != header_data.n_data_bytes) {
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

		pthread_mutex_lock(&dev->mutex);
		if (header_data.n_skipped_packets)
			send_blank_audio_to_all_unlocked(dev, header_data.n_skipped_packets * n_samples);

		for (struct source_list_s *item = dev->sources; item; item = item->next) {
			float *fltp[N_CHANNELS];
			for (int i = 0; i < N_CHANNELS && item->channels[i] >= 0; i++) {
				float *p = fltp_all[item->channels[i]];
				fltp[i] = p ? p : ptr;
			}

			source_add_audio(item->src, fltp, n_samples);
		}
		pthread_mutex_unlock(&dev->mutex);

		dev->packets_received++;
		dev->packets_missed += header_data.n_skipped_packets;
		if (dev->packets_received % 262144 == 0)
			blog(LOG_INFO, "h8819[%s] current status: %d packets received, %d packets dropped", dev->name,
			     dev->packets_received, dev->packets_missed);
	}

	blog(LOG_INFO, "exiting h8819 thread");

	close(fd_req);
	close(fd_data);

	int retval;
	waitpid(dev->pid, &retval, 0);
	blog(retval ? LOG_ERROR : LOG_INFO, "exit h8819 proc %d", retval);
	blog(dev->packets_missed ? LOG_ERROR : LOG_INFO, "h8819[%s]: %d packets received, %d packets dropped",
	     dev->name, dev->packets_received, dev->packets_missed);

	return NULL;
}
