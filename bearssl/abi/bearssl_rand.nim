import
  "."/[bearssl_hash, bearssl_hmac, csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearRandPath = bearSrcPath & "rand/"

# {.compile: bearRandPath & "aesctr_drbg.c".}
{.compile: bearRandPath & "hmac_drbg.c".}
{.compile: bearRandPath & "sysrng.c".}

type
  PrngClass* {.importc: "br_prng_class", header: "bearssl_rand.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: uint
    init* {.importc: "init".}: proc (ctx: ptr ptr PrngClass; params: pointer;
                                 seed: pointer; seedLen: uint) {.importcFunc.}
    generate* {.importc: "generate".}: proc (ctx: ptr ptr PrngClass; `out`: pointer;
        len: uint) {.importcFunc.}
    update* {.importc: "update".}: proc (ctx: ptr ptr PrngClass; seed: pointer;
                                     seedLen: uint) {.importcFunc.}



type
  HmacDrbgContext* {.importc: "br_hmac_drbg_context", header: "bearssl_rand.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr PrngClass
    k* {.importc: "K".}: array[64, byte]
    v* {.importc: "V".}: array[64, byte]
    digestClass* {.importc: "digest_class".}: ptr HashClass



var hmacDrbgVtable* {.importc: "br_hmac_drbg_vtable", header: "bearssl_rand.h".}: PrngClass


proc hmacDrbgInit*(ctx: var HmacDrbgContext; digestClass: ptr HashClass; seed: pointer;
                  seedLen: uint) {.importcFunc, importc: "br_hmac_drbg_init",
                                    header: "bearssl_rand.h".}

proc hmacDrbgGenerate*(ctx: var HmacDrbgContext; `out`: pointer; len: uint) {.importcFunc,
    importc: "br_hmac_drbg_generate", header: "bearssl_rand.h".}

proc hmacDrbgUpdate*(ctx: var HmacDrbgContext; seed: pointer; seedLen: uint) {.importcFunc,
    importc: "br_hmac_drbg_update", header: "bearssl_rand.h".}

proc hmacDrbgGetHash*(ctx: var HmacDrbgContext): ptr HashClass {.inline.} =
  return ctx.digestClass


type
  PrngSeeder* {.importc: "br_prng_seeder".} = proc (ctx: ptr ptr PrngClass): cint {.importcFunc.}


proc prngSeederSystem*(name: cstringArray): PrngSeeder {.importcFunc,
    importc: "br_prng_seeder_system", header: "bearssl_rand.h".}

# type
#   AesctrDrbgContext* {.importc: "br_aesctr_drbg_context", header: "bearssl_rand.h",
#                       bycopy.} = object
#     vtable* {.importc: "vtable".}: ptr PrngClass
#     sk* {.importc: "sk".}: AesGenCtrKeys
#     cc* {.importc: "cc".}: uint32



# var aesctrDrbgVtable* {.importc: "br_aesctr_drbg_vtable", header: "bearssl_rand.h".}: PrngClass


# proc aesctrDrbgInit*(ctx: var AesctrDrbgContext; aesctr: ptr BlockCtrClass;
#                     seed: pointer; seedLen: uint) {.importcFunc,
#     importc: "br_aesctr_drbg_init", header: "bearssl_rand.h".}

# proc aesctrDrbgGenerate*(ctx: var AesctrDrbgContext; `out`: pointer; len: uint) {.
#     importcFunc, importc: "br_aesctr_drbg_generate", header: "bearssl_rand.h".}

# proc aesctrDrbgUpdate*(ctx: var AesctrDrbgContext; seed: pointer; seedLen: uint) {.
#     importcFunc, importc: "br_aesctr_drbg_update", header: "bearssl_rand.h".}
