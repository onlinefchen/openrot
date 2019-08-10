#include <stdio.h>
#include <rsa.h>
#include <sha.h>
#include <string.h>

static sha256ctx ctx;
uint8_t *digest_sha256(const uint8_t *data, uint32_t len)
{

	sha256_init(&ctx);
	sha256_update(&ctx, data, len);

	return sha256_final(&ctx);
}

static sha512ctx s2ctx;
uint8_t *digest_sha512(const uint8_t *data, uint32_t len)
{

	sha512_init(&s2ctx);
	sha512_update(&s2ctx, data, len);

	return sha512_final(&s2ctx);
}

/*
 * echo -n "world hello" |openssl dgst -sha256
 * f39eba18947e82884b0fb35c498d71a6c18e0e570184faed370637383407ccca
 */
int main()
{
	char *to_hash = "world hello";
	uint8_t sha256_ret[SHA256_DIGEST_SIZE] = {0};
	char sha256_str[SHA256_DIGEST_SIZE * 2 + 1] = {0};
	uint8_t sha512_ret[SHA512_DIGEST_SIZE] = {0};
	char sha512_str[SHA512_DIGEST_SIZE * 2 + 1] = {0};

	memcpy(sha256_ret, digest_sha256(to_hash, strlen(to_hash)), SHA256_DIGEST_SIZE);
	memcpy(sha512_ret, digest_sha512(to_hash, strlen(to_hash)), SHA512_DIGEST_SIZE);


	bin2hex(sha256_str, sha256_ret, SHA256_DIGEST_SIZE);
	bin2hex(sha512_str, sha512_ret, SHA512_DIGEST_SIZE);

	printf("sha256 %s -> %s\n", to_hash, sha256_str);
	printf("sha512 %s -> %s\n", to_hash, sha512_str);
	return 0;
}
