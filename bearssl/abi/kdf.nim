import
  "."/[csources, hash, hmac]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_kdf.h".}
{.used.}

const
  bearKdfPath = bearSrcPath / "kdf"

{.compile: bearKdfPath / "hkdf.c".}
{.compile: bearKdfPath / "shake.c".}

type
  HkdfContextU* {.union.} = object
    hmacCtx* {.importc: "hmac_ctx"}: HmacContext
    prkCtx* {.importc: "prk_ctx"}: HmacKeyContext

  HkdfContext* {.importc: "br_hkdf_context", header: "bearssl_kdf.h", bycopy.} = object

    buf* {.importc: "buf".}: array[64, cuchar]
    `ptr`* {.importc: "ptr".}: csize_t
    digLen* {.importc: "dig_len".}: int
    chunkNum* {.importc: "chunk_num".}: cuint

proc hkdfInit*(hc: ptr HkdfContext; digestVtable: ptr HashClass; salt: pointer;
              saltLen: csize_t) {.importc: "br_hkdf_init", headerFunc.}


var hkdfNoSalt* {.importc: "br_hkdf_no_salt", header: "bearssl_kdf.h".}: cuchar

proc hkdfInject*(hc: ptr HkdfContext; ikm: pointer; ikmLen: csize_t) {.
    importc: "br_hkdf_inject", headerFunc.}

proc hkdfFlip*(hc: ptr HkdfContext) {.importc: "br_hkdf_flip", headerFunc.}

proc hkdfProduce*(hc: ptr HkdfContext; info: pointer; infoLen: csize_t; `out`: pointer;
                 outLen: csize_t): csize_t {.importc: "br_hkdf_produce",
    headerFunc.}

type
  ShakeContext* {.importc: "br_shake_context", header: "bearssl_kdf.h", bycopy.} = object
    dbuf* {.importc: "dbuf".}: array[200, cuchar]
    dptr* {.importc: "dptr".}: csize_t
    rate* {.importc: "rate".}: csize_t
    A* {.importc: "A".}: array[25, uint64]

proc shakeInit*(sc: ptr ShakeContext; securityLevel: cint) {.importc: "br_shake_init",
    headerFunc.}

proc shakeInject*(sc: ptr ShakeContext; data: pointer; len: int) {.
    importc: "br_shake_inject", headerFunc.}

proc shakeFlip*(hc: ptr ShakeContext) {.importc: "br_shake_flip",
                                    headerFunc.}

proc shakeProduce*(sc: ptr ShakeContext; `out`: pointer; len: int) {.
    importc: "br_shake_produce", headerFunc.}