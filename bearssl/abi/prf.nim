import
  "."/[csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_prf.h".}
{.used.}

const
  bearSslPath = bearSrcPath / "ssl"

{.compile: bearSslPath / "prf.c".}
{.compile: bearSslPath / "prf_md5sha1.c".}
{.compile: bearSslPath / "prf_sha256.c".}
{.compile: bearSslPath / "prf_sha384.c".}

type
  TlsPrfSeedChunk* {.importc: "br_tls_prf_seed_chunk", header: "bearssl_prf.h",
                    bycopy.} = object
    data* {.importc: "data".}: pointer
    len* {.importc: "len".}: int

proc tls10Prf*(dst: pointer; len: int; secret: pointer; secretLen: int;
              label: cstring; seedNum: int; seed: ptr TlsPrfSeedChunk) {.
    importc: "br_tls10_prf", headerFunc.}

proc tls12Sha256Prf*(dst: pointer; len: int; secret: pointer; secretLen: int;
                    label: cstring; seedNum: int; seed: ptr TlsPrfSeedChunk) {.
    importc: "br_tls12_sha256_prf", headerFunc.}

proc tls12Sha384Prf*(dst: pointer; len: int; secret: pointer; secretLen: int;
                    label: cstring; seedNum: int; seed: ptr TlsPrfSeedChunk) {.
    importc: "br_tls12_sha384_prf", headerFunc.}

type
  TlsPrfImpl* {.importc: "br_tls_prf_impl".} = proc (dst: pointer; len: int; secret: pointer; secretLen: int;
                   label: cstring; seedNum: int; seed: ptr TlsPrfSeedChunk) {.importcFunc.}
