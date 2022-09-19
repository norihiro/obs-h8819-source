#pragma once

#define N_CHANNELS 40
#define N_IGNORE_FIRST_PACKET 1024

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

#ifndef OS_WINDOWS
	pid_t pid;
#else // OS_WINDOWS
	uint16_t counter_last;
	bool got_packet;
#endif
};

static inline int64_t sample_time(int n_samples)
{
	return n_samples * 62500 / 3; // * 1000000000 / 48000
}

void *capdev_thread_main(void *);
void capdev_send_blank_audio_to_all_unlocked(struct capdev_s *dev, int n, uint64_t timestamp);
