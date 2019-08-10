#ifndef __SHA_H__
#define __SHA_H__

#include "crypto.h"
#include "common.h"

/* Block size in bytes of a sha-256 digest. */
#define SHA256_BLOCK_SIZE 64


/* Block size in bytes of a sha-512 digest. */
#define SHA512_BLOCK_SIZE 128

/* Data structure used for sha-256. */
typedef struct {
	uint32_t h[8];
	uint32_t tot_len;
	uint32_t len;
	uint8_t block[2 * SHA256_BLOCK_SIZE];
	uint8_t buf[SHA256_DIGEST_SIZE]; /* Used for storing the final digest. */
} sha256ctx;

/* Data structure used for sha-512. */
typedef struct {
	uint64_t h[8];
	uint32_t tot_len;
	uint32_t len;
	uint8_t block[2 * SHA512_BLOCK_SIZE];
	uint8_t buf[SHA512_DIGEST_SIZE]; /* Used for storing the final digest. */
} sha512ctx;

/* Initializes the sha-256 context. */
void sha256_init(sha256ctx* ctx);

/* Updates the sha-256 context with |len| bytes from |data|. */
void sha256_update(sha256ctx* ctx, const uint8_t* data, uint32_t len);

/* Returns the sha-256 digest. */
uint8_t* sha256_final(sha256ctx* ctx) __attribute__((warn_unused_result));

/* Initializes the sha-512 context. */
void sha512_init(sha512ctx* ctx);

/* Updates the sha-512 context with |len| bytes from |data|. */
void sha512_update(sha512ctx* ctx, const uint8_t* data, uint32_t len);

/* Returns the sha-512 digest. */
uint8_t* sha512_final(sha512ctx* ctx) UNUSED_RET;

#endif /* _sha_H_ */
