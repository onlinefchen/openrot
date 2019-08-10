#ifndef RSA_H_
#define RSA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "crypto.h"

/* Using the key given by |key|, verify a RSA signature |sig| of
	 * length |sig_num_bytes| against an expected |hash| of length
	 * |hash_num_bytes|. The padding to expect must be passed in using
	 * |padding| of length |padding_num_bytes|.
	 *
	 * The data in |key| must match the format defined in
	 * |rsa_pubkey_header|, including the two large numbers
	 * following. The |key_num_bytes| must be the size of the entire
	 * serialized key.
	 *
	 * Returns false if verification fails, true otherwise.
	 */
bool rsa_verify(const uint8_t *key, size_t key_num_bytes, const uint8_t *sig,
		size_t sig_num_bytes, const uint8_t *hash,
		size_t hash_num_bytes, const uint8_t *padding,
		size_t padding_num_bytes) UNUSED_RET;

#ifdef __cplusplus
}
#endif

#endif /* RSA_H_ */
