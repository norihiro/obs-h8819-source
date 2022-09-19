#include <unistd.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <obs-module.h>
#include <util/platform.h>
#include <util/threading.h>
#include <util/darray.h>
#include "plugin-macros.generated.h"
#include "source.h"
#include "capdev.h"
#include "capdev-internal.h"
#include "capdev-proc.h"

#define PROC_4219 "obs-h8819-proc"

#define LIST_DELIM '\n'

#define K_OFFSET_DECAY (256 * 16)

static pid_t thread_start_proc(const char *name, int *fd_req, int *fd_data)
{
	int pipe_req[2] = {-1, -1};
	int pipe_data[2];

	if (fd_req && pipe(pipe_req) < 0) {
		blog(LOG_ERROR, "failed to create pipe");
		return -1;
	}

	if (pipe(pipe_data) < 0) {
		blog(LOG_ERROR, "failed to create pipe");
		if (pipe_req[0] >= 0) {
			close(pipe_req[0]);
			close(pipe_req[1]);
		}
		return -1;
	}

	char *proc_path = obs_module_file(PROC_4219);

	// TODO: consider using vfork
	pid_t pid = fork();
	if (pid < 0) {
		blog(LOG_ERROR, "failed to fork");
		if (pipe_req[0] >= 0) {
			close(pipe_req[0]);
			close(pipe_req[1]);
		}
		close(pipe_data[0]);
		close(pipe_data[1]);
		bfree(proc_path);
		return -1;
	}

	if (pid == 0) {
		// I'm a child
		if (pipe_req[0] >= 0) {
			dup2(pipe_req[0], 0);
			close(pipe_req[0]);
			close(pipe_req[1]);
		}
		dup2(pipe_data[1], 1);
		close(pipe_data[0]);
		close(pipe_data[1]);
		if (execlp(proc_path, PROC_4219, name, NULL) < 0) {
			fprintf(stderr, "Error: failed to exec \"%s\"\n", proc_path);
			close(0);
			close(1);
			exit(1);
		}
	}

	if (fd_req) {
		*fd_req = pipe_req[1];
		close(pipe_req[0]);
	}
	*fd_data = pipe_data[0];
	close(pipe_data[1]);

	bfree(proc_path);

	return pid;
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

void *capdev_thread_main(void *data)
{
	os_set_thread_name("h8819");
	struct capdev_s *dev = data;

	int fd_req = -1, fd_data = -1;
	dev->pid = thread_start_proc(dev->name, &fd_req, &fd_data);
	if (dev->pid < 0) {
		return NULL;
	}

	struct capdev_proc_request_s req = {0};

	while (dev->refcnt > -1) {
		if (dev->channel_mask != req.channel_mask) {
			req.channel_mask = dev->channel_mask;
			blog(LOG_INFO, "requesting channel_mask=%" PRIx64, req.channel_mask);
			ssize_t ret = write(fd_req, &req, sizeof(req));
			if (ret != sizeof(req)) {
				blog(LOG_ERROR, "write returns %d.", (int)ret);
				break;
			}
		}

		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(fd_data, &readfds);
		struct timeval timeout = {.tv_sec = 0, .tv_usec = 50 * 1000};
		int ret_select = select(fd_data + 1, &readfds, NULL, NULL, &timeout);

		if (ret_select <= 0)
			continue;

		struct capdev_proc_header_s header_data;
		ssize_t ret = read(fd_data, &header_data, sizeof(header_data));
		if (ret != sizeof(header_data)) {
			blog(LOG_ERROR, "capdev capdev_thread_main: read returns %d.", (int)ret);
			break;
		}

		uint8_t buf[1500];
		float fltp_buf[500];
		if (header_data.n_data_bytes > (int)sizeof(buf)) {
			blog(LOG_ERROR, "header_data.n_data_bytes = %d is too large.", header_data.n_data_bytes);
			break;
		}
		ret = read(fd_data, buf, header_data.n_data_bytes);
		if (ret != header_data.n_data_bytes) {
			blog(LOG_ERROR, "capdev capdev_thread_main: read returns %d expected %d.", (int)ret,
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
				capdev_send_blank_audio_to_all_unlocked(dev, header_data.n_skipped_packets * n_samples,
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

	blog(LOG_INFO, "exiting h8819 thread");

	if (fd_req >= 0) {
		req.flags |= CAPDEV_REQ_FLAG_EXIT;
		ssize_t ret = write(fd_req, &req, sizeof(req));
		if (ret != sizeof(req)) {
			blog(LOG_ERROR, "write returns %d.", (int)ret);
		}
	}

	close(fd_req);
	close(fd_data);

	int retval;
	waitpid(dev->pid, &retval, 0);
	blog(retval ? LOG_ERROR : LOG_INFO, "exit h8819 proc %d", retval);
	blog(dev->packets_missed ? LOG_ERROR : LOG_INFO, "h8819[%s]: %d packets received, %d packets dropped",
	     dev->name, dev->packets_received, dev->packets_missed);

	return NULL;
}

void capdev_enum_devices(void (*cb)(const char *name, const char *description, void *param), void *param)
{
	int fd_data;
	pid_t pid = thread_start_proc(NULL, NULL, &fd_data);
	if (pid < 0)
		return;

	DARRAY(char) da;
	da_init(da);

	while (true) {
		darray_ensure_capacity(1, &da.da, da.num + 512);
		ssize_t n_read = read(fd_data, da.array + da.num, da.capacity - da.num);
		if (n_read <= 0)
			break;
		da.num += n_read;
	}

	int retval;
	waitpid(pid, &retval, 0);
	if (WIFEXITED(retval))
		blog(WEXITSTATUS(retval) ? LOG_ERROR : LOG_INFO, "exit h8819 proc %d", (int)WEXITSTATUS(retval));
	else
		blog(LOG_ERROR, "waitpid error %d", retval);

	close(fd_data);

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
		const char *name = da.array + offset;
		const char *description = da.array + d1 + 1;

		cb(name, description, param);

		offset = d2 + 1;
	}

	da_free(da);
}
