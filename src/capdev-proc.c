#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <pcap.h>
#include "capdev-proc.h"

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

struct context_s
{
	struct capdev_proc_request_s req;
	uint32_t received_packets;
	uint16_t counter_last;
	bool cont;
};

static inline int countones_uint64(uint64_t n)
{
	n = (n & 0xAAAAAAAAAAAAAAAAULL >> 1) + n & 0x5555555555555555ULL;
	n = (n & 0xCCCCCCCCCCCCCCCCULL >> 2) + n & 0x3333333333333333ULL;
	n = (n & 0xF0F0F0F0F0F0F0F0ULL >> 4) + n & 0x0F0F0F0F0F0F0F0FULL;
	n = (n & 0xFF00FF00FF00FF00ULL >> 8) + n & 0x00FF00FF00FF00FFULL;
	n = (n & 0xFFFF0000FFFF0000ULL >> 16) + n & 0x0000FFFF0000FFFFULL;
	n = (n & 0xFFFFFFFF00000000ULL >> 32) + n & 0x00000000FFFFFFFFULL;
	return (int)n;
}

static inline void convert_to_pcm24lep(uint8_t *dptr, const uint8_t *sptr, uint64_t channel_mask)
{
	for (int ch = 0; ch < 40; ch++) {
		if (!(channel_mask & (1LL << ch)))
			continue;

		const uint8_t *sptr1 = sptr + (ch >> 1) * 6;
		for (int is = 0; is < 12; is++) {
			if ((ch & 1) == 0) {
				*dptr++ = sptr1[3];
				*dptr++ = sptr1[0];
				*dptr++ = sptr1[1];
			}
			else {
				*dptr++ = sptr1[4];
				*dptr++ = sptr1[5];
				*dptr++ = sptr1[2];
			}
			sptr1 += 40 * 3;
		}
	}
}

static void got_msg(const char *data_packet, size_t bytes, struct context_s *ctx)
{
	if (bytes < sizeof(struct packet_header_s) + 2)
		return;
	const struct packet_header_s *packet_header = (const void *)data_packet;

	if (packet_header->type[0] != 0x88 || packet_header->type[1] != 0x19) {
		return;
	}

	// TODO: Check destination is broadcast address.

	if (data_packet[bytes - 2] != 0xC2 || data_packet[bytes - 1] != 0xEA) {
		fprintf(stderr, "Error: ending word failed: %02X %02X\n", (int)data_packet[bytes - 2],
			(int)data_packet[bytes - 1]);
		return;
	}

	uint8_t buf[12 * 40 * 3 + sizeof(struct capdev_proc_header_s)];
	struct capdev_proc_header_s *header = (void *)buf;
	int n_channel = countones_uint64(ctx->req.channel_mask);
	if (n_channel < 0 || 40 < n_channel)
		return;
	header->channel_mask = ctx->req.channel_mask;
	header->n_data_bytes = 12 * 3 * n_channel;
	uint8_t *pcm24lep = buf + sizeof(struct capdev_proc_header_s);

	// TODO: Just send number of skipped samples and pad them later.
	if (ctx->received_packets) {
		uint16_t counter_exp = ctx->counter_last + 1;
		if (counter_exp != packet_header->l2_counter) {
			fprintf(stderr, "Error: padding %d packet(s)\n",
				(int)(packet_header->l2_counter - counter_exp));
		}
		while (counter_exp != packet_header->l2_counter) {
			memset(pcm24lep, 0, header->n_data_bytes);
			ssize_t written = write(1, buf, sizeof(struct capdev_proc_header_s) + header->n_data_bytes);
			if (written != sizeof(struct capdev_proc_header_s) + header->n_data_bytes) {
				fprintf(stderr, "Failed to write\n");
				ctx->cont = false;
				return;
			}
			counter_exp++;
		}
	}

	convert_to_pcm24lep(pcm24lep, data_packet + L2_HEADER_LEN, header->channel_mask);

	ssize_t written = write(1, buf, sizeof(struct capdev_proc_header_s) + header->n_data_bytes);
	if (written != sizeof(struct capdev_proc_header_s) + header->n_data_bytes) {
		fprintf(stderr, "Failed to write\n");
		ctx->cont = false;
		return;
	}
	ctx->counter_last = packet_header->l2_counter;

	ctx->received_packets++;
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *if_name = argc > 1 ? argv[1] : NULL;

	pcap_t *p = pcap_create(if_name, errbuf);

	if (!p) {
		fputs(errbuf, stderr);
		return 1;
	}

	pcap_set_buffer_size(p, 524288 * 4);

	pcap_activate(p);
	int fd_pcap = pcap_get_selectable_fd(p);

	struct context_s ctx = {0};

	for (ctx.cont = true; ctx.cont;) {
		int nfds = 1;
		if (fd_pcap + 1 > nfds)
			nfds = fd_pcap + 1;
		fd_set readfds;
		fd_set exceptfds;
		FD_ZERO(&readfds);
		FD_SET(0, &readfds);
		FD_SET(0, &exceptfds);
		if (fd_pcap >= 0)
			FD_SET(fd_pcap, &readfds);

		struct timeval timeout = {.tv_sec = 0, .tv_usec = fd_pcap >= 0 ? 50000 : 500};
		int ret = select(nfds, &readfds, NULL, &exceptfds, &timeout);

		if (FD_ISSET(0, &readfds)) {
			size_t bytes = read(0, &ctx.req, sizeof(ctx.req));
			if (bytes != sizeof(ctx.req)) {
				fprintf(stderr, "Error: read %d bytes, expected %d bytes.\n", bytes, sizeof(ctx.req));
				ctx.cont = false;
				break;
			}
		}

		if (FD_ISSET(0, &exceptfds)) {
			fputs("0 appears on exceptfds. Exiting...\n", stderr);
			ctx.cont = false;
		}

		if (fd_pcap < 0 || FD_ISSET(fd_pcap, &readfds)) {
			struct pcap_pkthdr header;
			const uint8_t *payload = pcap_next(p, &header);
			got_msg(payload, header.caplen, &ctx);
		}
	}

	return 0;
}
