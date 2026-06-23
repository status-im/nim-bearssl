#include <stddef.h>
#include "bearssl_x509.h"

/*
 * Source-compatibility shim for `br_x509_decoder_init`'s `append_dn` callback.
 *
 * nim-bearssl keeps the public callback's middle arg a plain `void *` (not
 * `const void *`) so non-const downstream callbacks keep compiling and the C
 * typedef shared with PEM `setdest`/hash `update` stays non-const; see
 * `x509DecoderInit` in bearssl_x509.nim. The const conversion the real callback
 * type needs is done with an explicit cast here (accepted by GCC 14+), mirroring
 * `pem_compat.c`. Nim generates this function's prototype from its `importc`
 * proc, so no companion header is needed.
 */
void
nimbearssl_x509_decoder_init(br_x509_decoder_context *ctx,
	void (*append_dn)(void *append_dn_ctx, void *buf, size_t len),
	void *append_dn_ctx)
{
	br_x509_decoder_init(ctx,
		(void (*)(void *, const void *, size_t))append_dn, append_dn_ctx);
}
