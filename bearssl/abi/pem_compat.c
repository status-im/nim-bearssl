#include <stddef.h>
#include "bearssl_pem.h"

/*
 * Source-compatibility shim for `br_pem_decoder_context.dest`.
 *
 * The field is `void (*)(void *, const void *, size_t)`, but nim-bearssl keeps
 * the public `setdest` callback's `src` a plain `void *` so existing callers
 * (e.g. nim-chronos, whose callback uses a plain pointer) keep compiling. The
 * const conversion is performed here with an explicit C cast - which GCC 14+
 * accepts - instead of in Nim `{.emit.}`. This mirrors bearssl's own
 * `br_pem_decoder_setdest` inline setter, with the cast added.
 *
 * No companion header is needed: Nim generates the prototype for this function
 * from the `importc` proc signature in `bearssl_pem.nim`.
 */
void
nimbearssl_pem_decoder_setdest(br_pem_decoder_context *ctx,
	void (*dest)(void *dest_ctx, void *src, size_t len), void *dest_ctx)
{
	ctx->dest = (void (*)(void *, const void *, size_t))dest;
	ctx->dest_ctx = dest_ctx;
}
