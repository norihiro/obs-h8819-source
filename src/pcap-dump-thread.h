#pragma once

#include <stdint.h>

typedef struct pcap_dump_thread pcap_dump_thread_t;

#ifdef __cplusplus
extern "C" {
#endif

pcap_dump_thread_t *pcap_dump_thread_create(pcap_t *p, const char *filename);
void pcap_dump_thread_stop(pcap_dump_thread_t *);
void pcap_dump_thread_release(pcap_dump_thread_t *);
void pcap_dump_thread_dump(pcap_dump_thread_t *, const struct pcap_pkthdr *header, const uint8_t *payload);

#ifdef __cplusplus
} // extern "C"
#endif
