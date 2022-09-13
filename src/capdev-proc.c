#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "plugin-macros.generated.h"
#include <pcap.h>
#ifndef OS_WINDOWS
#include <unistd.h>
#else
#include <windows.h>
#endif
#include "capdev-proc.h"
#include "common.h"

#ifndef OS_WINDOWS
struct cp_fds_s
{
	int fd_pcap;
	fd_set readfds;
	fd_set exceptfds;
};

static void cp_fds_init(struct cp_fds_s *ctx, pcap_t *p)
{
	ctx->fd_pcap = pcap_get_selectable_fd(p);
	FD_ZERO(&ctx->readfds);
	FD_ZERO(&ctx->exceptfds);
}

static bool cp_fds_select(struct cp_fds_s *ctx)
{
	int nfds = 1;
	if (ctx->fd_pcap + 1 > nfds)
		nfds = ctx->fd_pcap + 1;

	FD_SET(0, &ctx->readfds);
	FD_SET(0, &ctx->exceptfds);
	if (ctx->fd_pcap >= 0)
		FD_SET(ctx->fd_pcap, &ctx->readfds);

	struct timeval timeout = {.tv_sec = 0, .tv_usec = ctx->fd_pcap >= 0 ? 50000 : 500};
	int ret = select(nfds, &ctx->readfds, NULL, &ctx->exceptfds, &timeout);
	if (ret < 0) {
		perror("select");
		return false;
	}

	if (FD_ISSET(0, &ctx->exceptfds)) {
		fputs("0 appears on exceptfds. Exiting...\n", stderr);
		return false;
	}

	return true;
}

static inline bool cp_fds_control_available(struct cp_fds_s *ctx)
{
	return FD_ISSET(0, &ctx->readfds);
}

static inline bool cp_fds_pcap_available(struct cp_fds_s *ctx)
{
	if (ctx->fd_pcap < 0)
		return true;
	return FD_ISSET(ctx->fd_pcap, &ctx->readfds);
}

static int cp_fds_read_control(struct cp_fds_s *ctx, void *data, size_t size)
{
	return (int)read(0, data, size);
}

static int cp_fds_write_data(struct cp_fds_s *ctx, const void *data, size_t size)
{
	return (int)write(1, data, size);
}

#else // OS_WINDOWS

struct cp_fds_s
{
	HANDLE handles[2];
	HANDLE hStdOut;
	DWORD retWait;
};

static void cp_fds_init(struct cp_fds_s *ctx, pcap_t *p)
{
	ctx->handles[0] = GetStdHandle(STD_INPUT_HANDLE);
	ctx->handles[1] = pcap_getevent(p);
	ctx->hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
}

static bool cp_fds_select(struct cp_fds_s *ctx)
{
	ctx->retWait = WaitForMultipleObjects(2, ctx->handles, FALSE, 70);
	switch (ctx->retWait) {
	case WAIT_OBJECT_0:
	case WAIT_OBJECT_0 + 1:
		return true;
	case WAIT_TIMEOUT:
		return true;
	default:
		return false;
	}
}

static inline bool cp_fds_control_available(struct cp_fds_s *ctx)
{
	return ctx->retWait == 0;
}

static inline bool cp_fds_pcap_available(struct cp_fds_s *ctx)
{
	return ctx->retWait == 1;
}

static int cp_fds_read_control(struct cp_fds_s *ctx, void *data, size_t size)
{
	DWORD bytes_read = 0;
	bool success = !!ReadFile(ctx->handles[0], data, (DWORD)size, &bytes_read, NULL);
	if (success && bytes_read)
		return (int)bytes_read;
	return -1;
}

static int cp_fds_write_data(struct cp_fds_s *ctx, const void *data, size_t size)
{
	DWORD bytes_written = 0;
	bool success = !!WriteFile(ctx->hStdOut, data, (DWORD)size, &bytes_written, NULL);
	if (success && bytes_written)
		return (int)bytes_written;
	return -1;
}
#endif

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
	struct cp_fds_s cp_fds;
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

	int written = cp_fds_write_data(&ctx->cp_fds, buf, sizeof(struct capdev_proc_header_s) + header->n_data_bytes);
	if (written != sizeof(struct capdev_proc_header_s) + header->n_data_bytes) {
		fprintf(stderr, "Failed to write\n");
		ctx->cont = false;
		return;
	}
	ctx->counter_last = packet_header->l2_counter;

	ctx->got_packet = true;
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *if_name = argc > 1 ? argv[1] : NULL;

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

	struct context_s ctx = {0};

	cp_fds_init(&ctx.cp_fds, p);

	for (ctx.cont = true; ctx.cont;) {
		if (!cp_fds_select(&ctx.cp_fds))
			ctx.cont = false;

		if (cp_fds_control_available(&ctx.cp_fds)) {
			int bytes = cp_fds_read_control(&ctx.cp_fds, &ctx.req, sizeof(ctx.req));
			if (bytes == 0 || ctx.req.flags & CAPDEV_REQ_FLAG_EXIT) {
				fprintf(stderr, "Info normal exit '%s'\n", if_name ? if_name : "(null)");
				ctx.cont = false;
				break;
			}
			else if (bytes != sizeof(ctx.req)) {
				fprintf(stderr, "Error: read %d bytes, expected %d bytes.\n", (int)bytes,
					(int)sizeof(ctx.req));
				ctx.cont = false;
				break;
			}
		}

		if (cp_fds_pcap_available(&ctx.cp_fds)) {
			struct pcap_pkthdr *header;
			const uint8_t *payload;
			if (pcap_next_ex(p, &header, &payload) == 1)
				got_msg(payload, header, &ctx);
		}
	}

	pcap_close(p);

	return 0;
}
