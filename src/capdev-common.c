#include <obs-module.h>
#include <util/platform.h>
#include <util/threading.h>
#include <util/darray.h>
#include "plugin-macros.generated.h"
#include "source.h"
#include "capdev.h"
#include "capdev-internal.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static capdev_t *devices = NULL;

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

static capdev_t *capdev_create_unlocked(const char *device_name)
{
	capdev_t *dev = bzalloc(sizeof(struct capdev_s));
	if (!dev)
		return NULL;
	dev->name = bstrdup(device_name);
	dev->next = devices;
	dev->prev_next = &devices;
	if (dev->next)
		dev->next->prev_next = &dev->next;
	devices = dev;

	pthread_mutex_init(&dev->mutex, NULL);
	pthread_create(&dev->thread, NULL, capdev_thread_main, dev);

	return dev;
}

static void capdev_destroy(capdev_t *dev)
{
	pthread_mutex_lock(&mutex);
	capdev_remove_from_devices_unlocked(dev);
	pthread_mutex_unlock(&mutex);

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

void capdev_send_blank_audio_to_all_unlocked(struct capdev_s *dev, int n, uint64_t timestamp)
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
