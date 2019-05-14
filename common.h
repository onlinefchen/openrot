#ifndef __COMMON_H_
#define __COMMON_H_
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ATTR_PACKED     __attribute__((packed))
#define UNUSED_RET      __attribute__((warn_unused_result))

static inline uint32_t avb_be32toh(uint32_t in)
{
	uint8_t* d = (uint8_t*)&in;
	uint32_t ret;
	ret = ((uint32_t)d[0]) << 24;
	ret |= ((uint32_t)d[1]) << 16;
	ret |= ((uint32_t)d[2]) << 8;
	ret |= ((uint32_t)d[3]);
	return ret;
}

static inline uint64_t avb_be64toh(uint64_t in)
{
	uint8_t* d = (uint8_t*)&in;
	uint64_t ret;
	ret = ((uint64_t)d[0]) << 56;
	ret |= ((uint64_t)d[1]) << 48;
	ret |= ((uint64_t)d[2]) << 40;
	ret |= ((uint64_t)d[3]) << 32;
	ret |= ((uint64_t)d[4]) << 24;
	ret |= ((uint64_t)d[5]) << 16;
	ret |= ((uint64_t)d[6]) << 8;
	ret |= ((uint64_t)d[7]);
	return ret;
}

/* Converts a 32-bit unsigned integer from host to big-endian byte order. */
static inline uint32_t avb_htobe32(uint32_t in)
{
	union {
		uint32_t word;
		uint8_t bytes[4];
	} ret;
	ret.bytes[0] = (in >> 24) & 0xff;
	ret.bytes[1] = (in >> 16) & 0xff;
	ret.bytes[2] = (in >> 8) & 0xff;
	ret.bytes[3] = in & 0xff;
	return ret.word;
}

/* Converts a 64-bit unsigned integer from host to big-endian byte order. */
static inline uint64_t avb_htobe64(uint64_t in)
{
	union {
		uint64_t word;
		uint8_t bytes[8];
	} ret;
	ret.bytes[0] = (in >> 56) & 0xff;
	ret.bytes[1] = (in >> 48) & 0xff;
	ret.bytes[2] = (in >> 40) & 0xff;
	ret.bytes[3] = (in >> 32) & 0xff;
	ret.bytes[4] = (in >> 24) & 0xff;
	ret.bytes[5] = (in >> 16) & 0xff;
	ret.bytes[6] = (in >> 8) & 0xff;
	ret.bytes[7] = in & 0xff;
	return ret.word;
}
#endif
