#include <unistd.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <obs-module.h>
#include <util/platform.h>
#include <util/threading.h>
#include "plugin-macros.generated.h"
#include "source.h"
#include "capdev.h"
#include "capdev-internal.h"
#include "capdev-proc.h"

#define PROC_4219 "obs-h8819-proc"

#define K_OFFSET_DECAY (256 * 16)

static bool thread_start_proc(struct capdev_s *dev, int *fd_req, int *fd_data)
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

	char *proc_path = obs_module_file(PROC_4219);

	// TODO: consider using vfork
	pid_t pid = fork();
	if (pid < 0) {
		blog(LOG_ERROR, "failed to fork");
		close(pipe_req[0]);
		close(pipe_req[1]);
		close(pipe_data[0]);
		close(pipe_data[1]);
		bfree(proc_path);
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
		if (execlp(proc_path, PROC_4219, dev->name, NULL) < 0) {
			fprintf(stderr, "Error: failed to exec \"%s\"\n", proc_path);
			close(0);
			close(1);
			exit(1);
		}
	}

	*fd_req = pipe_req[1];
	close(pipe_req[0]);
	*fd_data = pipe_data[0];
	close(pipe_data[1]);
	dev->pid = pid;

	bfree(proc_path);

	return true;
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
	if (!thread_start_proc(dev, &fd_req, &fd_data)) {
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
