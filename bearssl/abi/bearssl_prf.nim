import ./[consttypes, csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

{.compile: bearSrcPath & "ssl/prf.c".}
{.compile: bearSrcPath & "ssl/prf_md5sha1.c".}
{.compile: bearSrcPath & "ssl/prf_sha256.c".}
{.compile: bearSrcPath & "ssl/prf_sha384.c".}

type
  ConstPtrTlsPrfSeedChunk* {.importc: "const br_tls_prf_seed_chunk *", header: "bearssl_prf.h", bycopy.} = pointer

type
  TlsPrfSeedChunk* {.importc: "br_tls_prf_seed_chunk", header: "bearssl_prf.h",
                    bycopy.} = object
    data* {.importc: "data".}: ConstPointer
    len* {.importc: "len".}: csize_t



proc tls10Prf*(dst: pointer; len: csize_t; secret: ConstPointer; secretLen: csize_t;
              label: ConstCstring; seedNum: csize_t; seed: ConstPtrTlsPrfSeedChunk) {.
    importcFunc, importc: "br_tls10_prf", header: "bearssl_prf.h".}

proc tls12Sha256Prf*(dst: pointer; len: csize_t; secret: ConstPointer;
                    secretLen: csize_t; label: ConstCstring; seedNum: csize_t;
                    seed: ConstPtrTlsPrfSeedChunk) {.importcFunc,
    importc: "br_tls12_sha256_prf", header: "bearssl_prf.h".}

proc tls12Sha384Prf*(dst: pointer; len: csize_t; secret: ConstPointer;
                    secretLen: csize_t; label: ConstCstring; seedNum: csize_t;
                    seed: ConstPtrTlsPrfSeedChunk) {.importcFunc,
    importc: "br_tls12_sha384_prf", header: "bearssl_prf.h".}

type
  TlsPrfImpl* {.importc: "br_tls_prf_impl", header: "bearssl_prf.h".} = proc (dst: pointer; len: csize_t; secret: ConstPointer;
                   secretLen: csize_t; label: ConstCstring; seedNum: csize_t;
                   seed: ConstPtrTlsPrfSeedChunk) {.importcFunc.}
