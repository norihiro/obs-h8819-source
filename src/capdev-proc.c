#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pcap.h>
#include "capdev-proc.h"
#include "common.h"

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
	uint16_t counter_last;
	bool got_packet;
	bool cont;
};

static inline void convert_to_pcm24lep(uint8_t *dptr, const uint8_t *sptr, uint64_t channel_mask)
{
	for (int ch = 0; ch < 40; ch++) {
		if (!(channel_mask & (1LL << ch)))
			continue;

		const uint8_t *sptr1 = sptr + (ch & ~1) * 3;
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

static int64_t ts_pcap_to_obs(const struct pcap_pkthdr *pktheader)
{
	return pktheader->ts.tv_sec * 1000000000LL + pktheader->ts.tv_usec * 1000LL;
}

static void got_msg(const uint8_t *data_packet, const struct pcap_pkthdr *pktheader, struct context_s *ctx)
{
	if (pktheader->caplen < sizeof(struct packet_header_s) + 2)
		return;
	const struct packet_header_s *packet_header = (const void *)data_packet;

	if (packet_header->type[0] != 0x88 || packet_header->type[1] != 0x19) {
		return;
	}

	// TODO: Check destination is broadcast address.

	if (data_packet[pktheader->caplen - 2] != 0xC2 || data_packet[pktheader->caplen - 1] != 0xEA) {
		fprintf(stderr, "Error: ending word failed: %02X %02X\n", (int)data_packet[pktheader->caplen - 2],
			(int)data_packet[pktheader->caplen - 1]);
		return;
	}

	uint8_t buf[12 * 40 * 3 + sizeof(struct capdev_proc_header_s)];
	struct capdev_proc_header_s *header = (void *)buf;
	int n_channel = countones_uint64(ctx->req.channel_mask);
	if (n_channel < 0 || 40 < n_channel)
		return;
	header->channel_mask = ctx->req.channel_mask;
	header->timestamp = ts_pcap_to_obs(pktheader);
	header->n_data_bytes = 12 * 3 * n_channel;
	header->n_skipped_packets = 0;
	uint8_t *pcm24lep = buf + sizeof(struct capdev_proc_header_s);

	if (ctx->got_packet) {
		uint16_t counter_exp = ctx->counter_last + 1;
		if (counter_exp != packet_header->l2_counter) {
			uint16_t skipped = packet_header->l2_counter - counter_exp;
			header->n_skipped_packets = (int)skipped;
			fprintf(stderr, "Error: missing packets: counter is %d expected %d\n",
				(int)packet_header->l2_counter, (int)counter_exp);
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

	ctx->got_packet = true;
}

static int list_devices()
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		fprintf(stderr, "Error: pcap_findalldevs failed: %s\n", errbuf);
		return 1;
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

		if (strchr(name, '\n') || strchr(description, '\n'))
			continue;

		puts(name);
		puts(description);
	}

	pcap_freealldevs(alldevs);
	return 0;
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *if_name = argc > 1 ? argv[1] : NULL;

	if (!if_name)
		return list_devices();

	pcap_t *p = pcap_create(if_name, errbuf);

	if (!p) {
		fprintf(stderr, "%s\n", errbuf);
		return 1;
	}

	// Immediate mode caused packet losses.
	// Trying timeout less than the smoothing threshold in libobs (70 ms).
	pcap_set_timeout(p, 44 /*[ms]*/);

	// 44 ms x 48 kHz x 40 ch x 3 byte/ch = 254 kbytes
	// Allocate twice for the slave device, another twice for more safety.
	pcap_set_buffer_size(p, 4 * 256 * 1024);

	int ret = pcap_activate(p);
	if (ret) {
		fprintf(stderr, "Error: pcap_activate failed %s\n", pcap_geterr(p));
		return 1;
	}

	struct bpf_program fp = {0};
	ret = pcap_compile(p, &fp, "ether proto 0x8819", 1, PCAP_NETMASK_UNKNOWN);
	if (ret) {
		fprintf(stderr, "Warning: pcap_compile: %s\n", pcap_geterr(p));
	}
	else {
		ret = pcap_setfilter(p, &fp);
		if (ret)
			fprintf(stderr, "Error: pcap_setfilter: %s\n", pcap_geterr(p));
	}

	int fd_pcap = pcap_get_selectable_fd(p);

	struct context_s ctx = {0};
	pcap_dumper_t *pd = NULL;

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
		if (ret < 0) {
			perror("select");
			ctx.cont = false;
		}

		if (FD_ISSET(0, &readfds)) {
			size_t bytes = read(0, &ctx.req, sizeof(ctx.req));
			if (bytes == 0 || (ctx.req.flags & CAPDEV_REQ_FLAG_EXIT)) {
				fprintf(stderr, "Info normal exit '%s' bytes=%d flags=%d\n",
					if_name ? if_name : "(null)", (int)bytes, (int)ctx.req.flags);
				ctx.cont = false;
				break;
			}
			else if (bytes != sizeof(ctx.req)) {
				fprintf(stderr, "Error: read %d bytes, expected %d bytes.\n", (int)bytes,
					(int)sizeof(ctx.req));
				ctx.cont = false;
				break;
			}

			if (ctx.req.flags & CAPDEV_REQ_FLAG_SAVE_FILENAME) {
				size_t len = ctx.req.unused;
				char *name = malloc(len + 1);
				name[len] = 0;
				read(0, name, len);
				if (pd)
					pcap_dump_close(pd);
				fprintf(stderr, "Info: opening file '%s'\n", name);
				pd = pcap_dump_open(p, name);
				free(name);
			}

			if (pd && !(ctx.req.flags & CAPDEV_REQ_FLAG_SAVE)) {
				fprintf(stderr, "Info: closing the dump file\n");
				pcap_dump_close(pd);
				pd = NULL;
			}
		}

		if (FD_ISSET(0, &exceptfds)) {
			fputs("0 appears on exceptfds. Exiting...\n", stderr);
			ctx.cont = false;
		}

		if (fd_pcap < 0 || FD_ISSET(fd_pcap, &readfds)) {
			struct pcap_pkthdr *header;
			const uint8_t *payload;
			if (pcap_next_ex(p, &header, &payload) == 1) {
				got_msg(payload, header, &ctx);
				if (pd)
					pcap_dump((u_char *)pd, header, payload);
			}
		}
	}

	if (pd)
		pcap_dump_close(pd);

	pcap_close(p);

	return 0;
}
