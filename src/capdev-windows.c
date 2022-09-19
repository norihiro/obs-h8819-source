#include <inttypes.h>
#include <pcap.h>
#include <obs-module.h>
#include <util/platform.h>
#include <util/threading.h>
#include "plugin-macros.generated.h"
#include "source.h"
#include "capdev.h"
#include "capdev-internal.h"

#define K_OFFSET_DECAY (256 * 16)

static int64_t estimate_timestamp(struct capdev_s *dev, int64_t ts_pcap, int n_samples)
{
	int64_t ts_obs = (int64_t)os_gettime_ns() - sample_time(n_samples);
	if (dev->packets_received == 0 || ts_pcap + dev->ts_offset >= ts_obs ||
	    ts_pcap + dev->ts_offset + 70000000 < ts_obs) {
		dev->ts_offset = ts_obs - (int64_t)ts_pcap;
	}
	else {
		int64_t e = ts_obs - ts_pcap - dev->ts_offset;
		dev->ts_offset += e / K_OFFSET_DECAY;
	}

	int64_t ts = ts_pcap + dev->ts_offset;

#if 0
	blog(LOG_INFO, "timestamp: obs: %0.6f pcap: %0.6f ts_offset: %0.6f timestamp: %0.6f", ts_obs * 1e-9,
			ts_pcap * 1e-9, dev->ts_offset * 1e-9, ts * 1e-9);
#endif

	return ts;
}

static pcap_t *initialize_pcap(struct capdev_s *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p = pcap_create(dev->name, errbuf);
	if (!p) {
		blog(LOG_ERROR, "pcap_create: %s", errbuf);
		return NULL;
	}

	pcap_set_timeout(p, 44 /*[ms]*/);
	pcap_set_buffer_size(p, 4 * 256 * 1024);

	int ret = pcap_activate(p);
	struct bpf_program fp = {0};
	ret = pcap_compile(p, &fp, "ether proto 0x8819", 1, PCAP_NETMASK_UNKNOWN);
	if (ret) {
		blog(LOG_WARNING, "pcap_compile: %s", pcap_geterr(p));
	}
	else {
		ret = pcap_setfilter(p, &fp);
		if (ret)
			blog(LOG_ERROR, "pcap_setfilter: %s", pcap_geterr(p));
	}

	return p;
}

#define ETHER_HEADER_LEN (6 * 2 + 2)
#define L2_HEADER_LEN (ETHER_HEADER_LEN + 2 + 2 + 32)

struct packet_header_s
{
	uint8_t dhost[6];
	uint8_t shost[6];
	uint8_t type[2];

	uint16_t l2_counter; // assume LE
	uint16_t l2_type;
	uint8_t l2_unkown[32];
};

static int64_t ts_pcap_to_obs(const struct pcap_pkthdr *pktheader)
{
	return pktheader->ts.tv_sec * 1000000000LL + pktheader->ts.tv_usec * 1000LL;
}

static inline void convert_to_fltp(float *fltp_all[N_CHANNELS], float *dptr, const uint8_t *sptr, uint64_t channel_mask)
{
	float *fltp0 = dptr;
	for (int is = 0; is < 12; is++)
		*dptr++ = 0.0f;

	for (int ch = 0; ch < 40; ch++) {
		if (!(channel_mask & (1LL << ch))) {
			fltp_all[ch] = fltp0;
			continue;
		}

		const uint8_t *sptr1 = sptr + (ch & ~1) * 3;
		fltp_all[ch] = dptr;
		for (int is = 0; is < 12; is++) {
			uint32_t u;
			if ((ch & 1) == 0)
				u = sptr1[3] | sptr1[0] << 8 | sptr1[1] << 16;
			else
				u = sptr1[4] | sptr1[5] << 8 | sptr1[2] << 16;
			int s = u & 0x800000 ? u - 0x1000000 : u;
			*dptr++ = (float)s / 8388608.0f;
			sptr1 += 40 * 3;
		}
	}
}

static void got_msg(const uint8_t *data_packet, const struct pcap_pkthdr *pktheader, struct capdev_s *dev)
{
	if (pktheader->caplen < sizeof(struct packet_header_s) + 2)
		return;
	const struct packet_header_s *packet_header = (const void *)data_packet;

	if (packet_header->type[0] != 0x88 || packet_header->type[1] != 0x19) {
		return;
	}

	// TODO: Check destination is broadcast address.

	if (data_packet[pktheader->caplen - 2] != 0xC2 || data_packet[pktheader->caplen - 1] != 0xEA) {
		blog(LOG_ERROR, "Ending word failed: %02X %02X\n", (int)data_packet[pktheader->caplen - 2],
		     (int)data_packet[pktheader->caplen - 1]);
		return;
	}

	uint64_t channel_mask = dev->channel_mask;
	int n_channels = countones_uint64(channel_mask);
	if (n_channels < 0 || 40 < n_channels)
		return;
	int64_t ts_pcap = ts_pcap_to_obs(pktheader);
	int n_data_bytes = 12 * 3 * n_channels;
	int n_skipped_packets = 0;

	if (dev->got_packet) {
		uint16_t counter_exp = dev->counter_last + 1;
		if (counter_exp != packet_header->l2_counter) {
			uint16_t skipped = packet_header->l2_counter - counter_exp;
			n_skipped_packets = (int)skipped;
			blog(LOG_ERROR, "missing packets: counter is %d expected %d\n", (int)packet_header->l2_counter,
			     (int)counter_exp);
		}
	}

	dev->counter_last = packet_header->l2_counter;
	dev->got_packet = true;

	float fltp_buf[12 * (N_CHANNELS + 1)];
	float *fltp_all[N_CHANNELS];
	convert_to_fltp(fltp_all, fltp_buf, data_packet + L2_HEADER_LEN, channel_mask);

	const int n_samples = 12;

	int64_t timestamp = estimate_timestamp(dev, ts_pcap, n_samples);

	if (dev->packets_received >= N_IGNORE_FIRST_PACKET) {
		pthread_mutex_lock(&dev->mutex);
		if (n_skipped_packets)
			capdev_send_blank_audio_to_all_unlocked(dev, n_skipped_packets * n_samples, timestamp);

		for (struct source_list_s *item = dev->sources; item; item = item->next) {
			float *fltp[N_CHANNELS];
			for (int i = 0; i < N_CHANNELS && item->channels[i] >= 0; i++)
				fltp[i] = fltp_all[item->channels[i]];

			source_add_audio(item->src, fltp, n_samples, timestamp);
		}
		pthread_mutex_unlock(&dev->mutex);
	}

	dev->packets_received++;
	dev->packets_missed += n_skipped_packets;
	if (dev->packets_received % 262144 == 0)
		blog(LOG_INFO, "h8819[%s] current status: %d packets received, %d packets dropped", dev->name,
		     dev->packets_received, dev->packets_missed);
}

void *capdev_thread_main(void *data)
{
	os_set_thread_name("h8819");
	struct capdev_s *dev = data;

	pcap_t *p = initialize_pcap(dev);

	HANDLE hPCap = pcap_getevent(p);

	while (dev->refcnt > -1) {

		DWORD retWait = WaitForSingleObject(hPCap, 70 /* ms */);

		if (retWait == WAIT_OBJECT_0) {
			struct pcap_pkthdr *header;
			const uint8_t *payload;
			if (pcap_next_ex(p, &header, &payload) == 1)
				got_msg(payload, header, dev);
		}
	}

	blog(LOG_INFO, "exiting h8819 thread");

	pcap_close(p);

	blog(dev->packets_missed ? LOG_ERROR : LOG_INFO, "h8819[%s]: %d packets received, %d packets dropped",
	     dev->name, dev->packets_received, dev->packets_missed);

	return NULL;
}

void capdev_enum_devices(void (*cb)(const char *name, const char *description, void *param), void *param)
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		blog(LOG_ERROR, "pcap_findalldevs failed: %s", errbuf);
		return;
	}

	for (pcap_if_t *d = alldevs; d; d = d->next) {
		if (d->flags & PCAP_IF_WIRELESS)
			continue;
		const char *name = d->name;
		const char *description;
		if (d->description)
			description = d->description;
		else
			description = d->name;

		cb(name, description, param);
	}

	pcap_freealldevs(alldevs);
}
