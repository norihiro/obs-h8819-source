#pragma once

#define CAPDEV_REQ_FLAG_EXIT 1

struct capdev_proc_request_s
{
	uint64_t channel_mask;
	uint32_t flags;
	uint32_t unused;
};

struct capdev_proc_header_s
{
	uint64_t channel_mask;
	int64_t timestamp;
	uint32_t n_data_bytes;
	uint32_t n_skipped_packets;
};
