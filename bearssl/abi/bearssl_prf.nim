import
  "."/[csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearSslPath = bearSrcPath & "ssl/"

{.compile: bearSslPath & "prf.c".}
{.compile: bearSslPath & "prf_md5sha1.c".}
{.compile: bearSslPath & "prf_sha256.c".}
{.compile: bearSslPath & "prf_sha384.c".}

type
  TlsPrfSeedChunk* {.importc: "br_tls_prf_seed_chunk", header: "bearssl_prf.h",
                    bycopy.} = object
    data* {.importc: "data".}: pointer
    len* {.importc: "len".}: uint



proc tls10Prf*(dst: pointer; len: uint; secret: pointer; secretLen: uint;
              label: cstring; seedNum: uint; seed: ptr TlsPrfSeedChunk) {.importcFunc,
    importc: "br_tls10_prf", header: "bearssl_prf.h".}

proc tls12Sha256Prf*(dst: pointer; len: uint; secret: pointer; secretLen: uint;
                    label: cstring; seedNum: uint; seed: ptr TlsPrfSeedChunk) {.
    importcFunc, importc: "br_tls12_sha256_prf", header: "bearssl_prf.h".}

proc tls12Sha384Prf*(dst: pointer; len: uint; secret: pointer; secretLen: uint;
                    label: cstring; seedNum: uint; seed: ptr TlsPrfSeedChunk) {.
    importcFunc, importc: "br_tls12_sha384_prf", header: "bearssl_prf.h".}

type
  TlsPrfImpl* {.importc: "br_tls_prf_impl".} = proc (dst: pointer; len: uint; secret: pointer; secretLen: uint;
                   label: cstring; seedNum: uint; seed: ptr TlsPrfSeedChunk) {.importcFunc.}
