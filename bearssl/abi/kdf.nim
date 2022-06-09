import
  "."/[csources, hash, hmac]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearKdfPath = bearSrcPath / "kdf"

{.compile: bearKdfPath / "hkdf.c".}
{.compile: bearKdfPath / "shake.c".}

type
  INNER_C_UNION_bearssl_kdf_1* {.importc: "br_hkdf_context::no_name",
                                header: "bearssl_kdf.h", bycopy, union.} = object
    hmacCtx* {.importc: "hmac_ctx".}: HmacContext
    prkCtx* {.importc: "prk_ctx".}: HmacKeyContext

  HkdfContext* {.importc: "br_hkdf_context", header: "bearssl_kdf.h", bycopy.} = object
    u* {.importc: "u".}: INNER_C_UNION_bearssl_kdf_1
    buf* {.importc: "buf".}: array[64, cuchar]
    `ptr`* {.importc: "ptr".}: int
    digLen* {.importc: "dig_len".}: int
    chunkNum* {.importc: "chunk_num".}: cuint



proc hkdfInit*(hc: ptr HkdfContext; digestVtable: ptr HashClass; salt: pointer;
              saltLen: int) {.importcFunc, importc: "br_hkdf_init",
                                header: "bearssl_kdf.h".}


var hkdfNoSalt* {.importc: "br_hkdf_no_salt", header: "bearssl_kdf.h".}: cuchar

proc hkdfInject*(hc: ptr HkdfContext; ikm: pointer; ikmLen: int) {.importcFunc,
    importc: "br_hkdf_inject", header: "bearssl_kdf.h".}

proc hkdfFlip*(hc: ptr HkdfContext) {.importcFunc, importc: "br_hkdf_flip",
                                  header: "bearssl_kdf.h".}

proc hkdfProduce*(hc: ptr HkdfContext; info: pointer; infoLen: int; `out`: pointer;
                 outLen: int): int {.importcFunc, importc: "br_hkdf_produce",
    header: "bearssl_kdf.h".}

type
  ShakeContext* {.importc: "br_shake_context", header: "bearssl_kdf.h", bycopy.} = object
    dbuf* {.importc: "dbuf".}: array[200, cuchar]
    dptr* {.importc: "dptr".}: int
    rate* {.importc: "rate".}: int
    a* {.importc: "A".}: array[25, uint64]



proc shakeInit*(sc: ptr ShakeContext; securityLevel: cint) {.importcFunc,
    importc: "br_shake_init", header: "bearssl_kdf.h".}

proc shakeInject*(sc: ptr ShakeContext; data: pointer; len: int) {.importcFunc,
    importc: "br_shake_inject", header: "bearssl_kdf.h".}

proc shakeFlip*(hc: ptr ShakeContext) {.importcFunc, importc: "br_shake_flip",
                                    header: "bearssl_kdf.h".}

proc shakeProduce*(sc: ptr ShakeContext; `out`: pointer; len: int) {.importcFunc,
    importc: "br_shake_produce", header: "bearssl_kdf.h".}