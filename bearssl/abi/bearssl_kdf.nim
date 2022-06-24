import
  "."/[bearssl_hash, bearssl_hmac, csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearKdfPath = bearSrcPath & "kdf/"

{.compile: bearKdfPath & "hkdf.c".}
{.compile: bearKdfPath & "shake.c".}

type
  INNER_C_UNION_bearssl_kdf_1* {.importc: "br_hkdf_context::no_name",
                                header: "bearssl_kdf.h", bycopy, union.} = object
    hmacCtx* {.importc: "hmac_ctx".}: HmacContext
    prkCtx* {.importc: "prk_ctx".}: HmacKeyContext

  HkdfContext* {.importc: "br_hkdf_context", header: "bearssl_kdf.h", bycopy.} = object
    u* {.importc: "u".}: INNER_C_UNION_bearssl_kdf_1
    buf* {.importc: "buf".}: array[64, byte]
    `ptr`* {.importc: "ptr".}: uint
    digLen* {.importc: "dig_len".}: uint
    chunkNum* {.importc: "chunk_num".}: cuint



proc hkdfInit*(hc: var HkdfContext; digestVtable: ptr HashClass; salt: pointer;
              saltLen: uint) {.importcFunc, importc: "br_hkdf_init",
                                header: "bearssl_kdf.h".}


var hkdfNoSalt* {.importc: "br_hkdf_no_salt", header: "bearssl_kdf.h".}: byte


proc hkdfInject*(hc: var HkdfContext; ikm: pointer; ikmLen: uint) {.importcFunc,
    importc: "br_hkdf_inject", header: "bearssl_kdf.h".}

proc hkdfFlip*(hc: var HkdfContext) {.importcFunc, importc: "br_hkdf_flip",
                                  header: "bearssl_kdf.h".}

proc hkdfProduce*(hc: var HkdfContext; info: pointer; infoLen: uint; `out`: pointer;
                 outLen: uint): uint {.importcFunc, importc: "br_hkdf_produce",
    header: "bearssl_kdf.h".}

type
  ShakeContext* {.importc: "br_shake_context", header: "bearssl_kdf.h", bycopy.} = object
    dbuf* {.importc: "dbuf".}: array[200, byte]
    dptr* {.importc: "dptr".}: uint
    rate* {.importc: "rate".}: uint
    a* {.importc: "A".}: array[25, uint64]



proc shakeInit*(sc: var ShakeContext; securityLevel: cint) {.importcFunc,
    importc: "br_shake_init", header: "bearssl_kdf.h".}

proc shakeInject*(sc: var ShakeContext; data: pointer; len: uint) {.importcFunc,
    importc: "br_shake_inject", header: "bearssl_kdf.h".}

proc shakeFlip*(hc: var ShakeContext) {.importcFunc, importc: "br_shake_flip",
                                    header: "bearssl_kdf.h".}

proc shakeProduce*(sc: var ShakeContext; `out`: pointer; len: uint) {.importcFunc,
    importc: "br_shake_produce", header: "bearssl_kdf.h".}
