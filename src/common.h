#pragma once

typedef struct capdev_s capdev_t;
typedef struct source_s source_t;

static inline int countones_uint64(uint64_t n)
{
	n = (n >> 1 & 0x5555555555555555ULL) + (n & 0x5555555555555555ULL);
	n = (n >> 2 & 0x3333333333333333ULL) + (n & 0x3333333333333333ULL);
	n = (n >> 4 & 0x0F0F0F0F0F0F0F0FULL) + (n & 0x0F0F0F0F0F0F0F0FULL);
	n = (n >> 8 & 0x00FF00FF00FF00FFULL) + (n & 0x00FF00FF00FF00FFULL);
	n = (n >> 16 & 0x000FFFF0000FFFFULL) + (n & 0x0000FFFF0000FFFFULL);
	n = (n >> 32 & 0x0000000FFFFFFFFULL) + (n & 0x00000000FFFFFFFFULL);
	return (int)n;
}
