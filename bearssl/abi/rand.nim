import
  "."/[csources, hash, hmac]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_rand.h".}
{.used.}

const
  bearRandPath = bearSrcPath / "rand"

{.compile: bearRandPath / "hmac_drbg.c".}
{.compile: bearRandPath / "sysrng.c".}

type
  PrngClass* {.importc: "br_prng_class", header: "bearssl_rand.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: csize_t
    init* {.importc: "init".}: proc (ctx: ptr ptr PrngClass; params: pointer;
                                 seed: pointer; seedLen: csize_t) {.importcFunc.}
    generate* {.importc: "generate".}: proc (ctx: ptr ptr PrngClass; `out`: pointer;
        len: csize_t) {.importcFunc.}
    update* {.importc: "update".}: proc (ctx: ptr ptr PrngClass; seed: pointer;
                                     seedLen: csize_t) {.importcFunc.}

  HmacDrbgContext* {.importc: "br_hmac_drbg_context", header: "bearssl_rand.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr PrngClass
    k* {.importc: "K".}: array[64, cuchar]
    v* {.importc: "V".}: array[64, cuchar]
    digestClass* {.importc: "digest_class".}: ptr HashClass


var hmacDrbgVtable* {.importc: "br_hmac_drbg_vtable", header: "bearssl_rand.h".}: PrngClass

proc hmacDrbgInit*(ctx: ptr HmacDrbgContext; digestClass: ptr HashClass; seed: pointer;
                  seedLen: int) {.importc: "br_hmac_drbg_init",
                                  headerFunc.}

proc hmacDrbgGenerate*(ctx: ptr HmacDrbgContext; `out`: pointer; len: csize_t) {.
    importc: "br_hmac_drbg_generate", headerFunc.}

proc hmacDrbgUpdate*(ctx: ptr HmacDrbgContext; seed: pointer; seedLen: csize_t) {.
    importc: "br_hmac_drbg_update", headerFunc.}

proc hmacDrbgGetHash*(ctx: ptr HmacDrbgContext): ptr HashClass {.inline.} =
  return ctx.digestClass

type
  PrngSeeder* {.importc: "br_prng_seeder", header: "bearssl_rand.h".} =
    proc (ctx: ptr ptr PrngClass): cint {.importcFunc.}

proc prngSeederSystem*(name: cstringArray): PrngSeeder {.
     importc: "br_prng_seeder_system", headerFunc.}
