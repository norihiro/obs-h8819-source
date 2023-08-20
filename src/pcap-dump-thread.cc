#include <stdio.h>
#include <string>
#include <cstring>
#include <list>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <pcap.h>
#include "pcap-dump-thread.h"

#define PAYLOAD_SIZE 1500

struct packet
{
	struct pcap_pkthdr header;
	uint8_t payload[PAYLOAD_SIZE];

	packet() {}
	packet(const struct pcap_pkthdr *h, const uint8_t *p) : header(*h)
	{
		memcpy(payload, p, std::min((size_t)h->caplen, sizeof(payload)));
	}
};

struct pcap_dump_thread
{
	// configurations set at creation
	std::string filename;
	pcap_t *p;

	// data to pass between threads
	std::list<packet> packets;
	std::mutex mutex;
	std::condition_variable cond;
	volatile bool stop = false;
	std::thread thread;
};

static void pcap_dump_thread_thread(pcap_dump_thread_t *);

pcap_dump_thread_t *pcap_dump_thread_create(pcap_t *p, const char *filename)
{
	auto *ctx = new pcap_dump_thread;
	ctx->filename = filename;
	ctx->p = p;

	ctx->thread = std::thread([ctx]() { pcap_dump_thread_thread(ctx); });

	return ctx;
}

void pcap_dump_thread_stop(pcap_dump_thread_t *ctx)
{
	std::unique_lock<std::mutex> lock(ctx->mutex);
	ctx->stop = true;

	lock.unlock();
	ctx->cond.notify_one();
}

void pcap_dump_thread_release(pcap_dump_thread_t *ctx)
{
	if (!ctx)
		return;

	pcap_dump_thread_stop(ctx);

	ctx->thread.join();
	fprintf(stderr, "Info: cleaned up to dump file '%s'\n", ctx->filename.c_str());
	delete ctx;
}

void pcap_dump_thread_dump(pcap_dump_thread_t *ctx, const struct pcap_pkthdr *header, const uint8_t *payload)
{
	std::unique_lock<std::mutex> lock(ctx->mutex);

	ctx->packets.emplace_back(header, payload);

	lock.unlock();
	ctx->cond.notify_one();
}

void pcap_dump_thread_thread(pcap_dump_thread_t *ctx)
{
	fprintf(stderr, "Info: opening a dump file '%s'\n", ctx->filename.c_str());
	pcap_dumper_t *pd = pcap_dump_open(ctx->p, ctx->filename.c_str());

	packet pkt;

	while (!ctx->stop) {
		{
			std::unique_lock<std::mutex> lock(ctx->mutex);
			ctx->cond.wait(lock, [ctx] { return ctx->stop || ctx->packets.size(); });

			if (!ctx->packets.size())
				continue;

			pkt = *ctx->packets.begin();
			ctx->packets.pop_front();
		}

		if (pd) {
			pcap_dump((u_char *)pd, &pkt.header, pkt.payload);
		}
	}

	fprintf(stderr, "Info: closing the dump file '%s'\n", ctx->filename.c_str());
	pcap_dump_close(pd);
}
