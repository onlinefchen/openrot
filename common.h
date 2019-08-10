#ifndef __COMMON_H_
#define __COMMON_H_
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ATTR_PACKED     __attribute__((packed))
#define UNUSED_RET      __attribute__((warn_unused_result))

static inline uint32_t be32toh(uint32_t in)
{
	uint8_t* d = (uint8_t*)&in;
	uint32_t ret;
	ret = ((uint32_t)d[0]) << 24;
	ret |= ((uint32_t)d[1]) << 16;
	ret |= ((uint32_t)d[2]) << 8;
	ret |= ((uint32_t)d[3]);
	return ret;
}

static inline uint64_t be64toh(uint64_t in)
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
static inline uint32_t htobe32(uint32_t in)
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
static inline uint64_t htobe64(uint64_t in)
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

static const char hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]


static inline char *hex_byte_pack(char *buf, uint8_t byte)
{
        *buf++ = hex_asc_hi(byte);
        *buf++ = hex_asc_lo(byte);
        return buf;
}

static char *bin2hex(char *dst, const void *src, size_t count)
{
        const unsigned char *_src = src;

        while (count--)
                dst = hex_byte_pack(dst, *_src++);
        return dst;
}

static int hex_to_bin(char ch)
{
        if ((ch >= '0') && (ch <= '9'))
                return ch - '0';
        ch = tolower(ch);
        if ((ch >= 'a') && (ch <= 'f'))
                return ch - 'a' + 10;
        return -1;
}

static int hex2bin(uint8_t *dst, const char *src, size_t count)
{
        while (count--) {
                int hi = hex_to_bin(*src++);
                int lo = hex_to_bin(*src++);

                if ((hi < 0) || (lo < 0))
                        return -1;

                *dst++ = (hi << 4) | lo;
        }
        return 0;
}
#endif
