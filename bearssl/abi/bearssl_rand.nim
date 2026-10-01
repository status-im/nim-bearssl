import ./[bearssl_hash, bearssl_hmac, consttypes, csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearRandPath = bearSrcPath & "rand/"

# {.compile: bearRandPath & "aesctr_drbg.c".}
{.compile: bearRandPath & "hmac_drbg.c".}
{.compile: bearRandPath & "sysrng.c".}

type
  PrngClassPointerConst* {.importc: "const br_prng_class**", header: "bearssl_rand.h", bycopy.} = pointer
  constCstringArray* {.importc: "const char **", header: "bearssl_rand.h", bycopy.} = pointer

type
  PrngClass* {.importc: "br_prng_class", header: "bearssl_rand.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: csize_t
    init* {.importc: "init".}: proc (ctx: PrngClassPointerConst; params: ConstPointer;
                                 seed: ConstPointer; seedlen: csize_t) {.importcFunc.}
    generate* {.importc: "generate".}: proc (ctx: PrngClassPointerConst;
        `out`: pointer; len: csize_t) {.importcFunc.}
    update* {.importc: "update".}: proc (ctx: PrngClassPointerConst; seed: ConstPointer;
                                     seedlen: csize_t) {.importcFunc.}


type
  HmacDrbgContext* {.importc: "br_hmac_drbg_context", header: "bearssl_rand.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr PrngClass
    k* {.importc: "K".}: array[64, byte]
    v* {.importc: "V".}: array[64, byte]
    digestClass* {.importc: "digest_class".}: ptr HashClass



var hmacDrbgVtable* {.importc: "br_hmac_drbg_vtable", header: "bearssl_rand.h".}: PrngClass


proc hmacDrbgInit*(ctx: var HmacDrbgContext; digestClass: ptr HashClass; seed: ConstPointer;
                  seedlen: csize_t) {.importcFunc, importc: "br_hmac_drbg_init",
                                    header: "bearssl_rand.h".}

proc hmacDrbgGenerate*(ctx: var HmacDrbgContext; `out`: pointer; len: csize_t) {.importcFunc,
    importc: "br_hmac_drbg_generate", header: "bearssl_rand.h".}

proc hmacDrbgUpdate*(ctx: var HmacDrbgContext; seed: ConstPointer; seedlen: csize_t) {.importcFunc,
    importc: "br_hmac_drbg_update", header: "bearssl_rand.h".}

proc hmacDrbgGetHash*(ctx: var HmacDrbgContext): ptr HashClass {.inline.} =
  return ctx.digestClass


type
  PrngSeeder* {.importc: "br_prng_seeder".} = proc (ctx: PrngClassPointerConst): cint {.importcFunc.}


proc prngSeederSystem*(name: constCstringArray): PrngSeeder {.importcFunc,
    importc: "br_prng_seeder_system", header: "bearssl_rand.h".}

# type
#   AesctrDrbgContext* {.importc: "br_aesctr_drbg_context", header: "bearssl_rand.h",
#                       bycopy.} = object
#     vtable* {.importc: "vtable".}: ptr PrngClass
#     sk* {.importc: "sk".}: AesGenCtrKeys
#     cc* {.importc: "cc".}: uint32



# var aesctrDrbgVtable* {.importc: "br_aesctr_drbg_vtable", header: "bearssl_rand.h".}: PrngClass


# proc aesctrDrbgInit*(ctx: var AesctrDrbgContext; aesctr: ptr BlockCtrClass;
#                     seed: pointer; seedlen: csize_t) {.importcFunc,
#     importc: "br_aesctr_drbg_init", header: "bearssl_rand.h".}

# proc aesctrDrbgGenerate*(ctx: var AesctrDrbgContext; `out`: pointer; len: csize_t) {.
#     importcFunc, importc: "br_aesctr_drbg_generate", header: "bearssl_rand.h".}

# proc aesctrDrbgUpdate*(ctx: var AesctrDrbgContext; seed: pointer; seedlen: csize_t) {.
#     importcFunc, importc: "br_aesctr_drbg_update", header: "bearssl_rand.h".}
