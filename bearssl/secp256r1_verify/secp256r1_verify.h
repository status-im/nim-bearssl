#ifndef __secp256r1_verify_header__
#define __secp256r1_verify_header__

#include <bearssl_ec.h>

uint32_t
secp256r1_i31_vrfy_raw(
	const void *hash, size_t hash_len,
	const br_ec_public_key *pk,
	const void *sig, size_t sig_len);

#endif
