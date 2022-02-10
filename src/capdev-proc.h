#pragma once

struct capdev_proc_request_s
{
	uint64_t channel_mask;
};

struct capdev_proc_header_s
{
	uint64_t channel_mask;
	int n_data_bytes;
};
