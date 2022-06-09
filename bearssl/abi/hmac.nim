import
  "."/[csources, inner, hash]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearMacPath = bearSrcPath / "mac"

{.compile: bearMacPath / "hmac.c".}
{.compile: bearMacPath / "hmac_ct.c".}

type
  HmacKeyContext* {.importc: "br_hmac_key_context", header: "bearssl_hmac.h", bycopy.} = object
    digVtable* {.importc: "dig_vtable".}: ptr HashClass
    ksi* {.importc: "ksi".}: array[64, byte]
    kso* {.importc: "kso".}: array[64, byte]



proc hmacKeyInit*(kc: ptr HmacKeyContext; digestVtable: ptr HashClass; key: pointer;
                 keyLen: uint) {.importcFunc, importc: "br_hmac_key_init",
                                  header: "bearssl_hmac.h".}

proc hmacKeyGetDigest*(kc: ptr HmacKeyContext): ptr HashClass {.inline.} =
  return kc.digVtable


type
  HmacContext* {.importc: "br_hmac_context", header: "bearssl_hmac.h", bycopy.} = object
    dig* {.importc: "dig".}: HashCompatContext
    kso* {.importc: "kso".}: array[64, byte]
    outLen* {.importc: "out_len".}: uint



proc hmacInit*(ctx: ptr HmacContext; kc: ptr HmacKeyContext; outLen: uint) {.importcFunc,
    importc: "br_hmac_init", header: "bearssl_hmac.h".}

proc hmacSize*(ctx: ptr HmacContext): uint {.inline, importcFunc, importc: "br_hmac_size".} =
  return ctx.outLen


proc hmacGetDigest*(hc: ptr HmacContext): ptr HashClass {.inline.} =
  return hc.dig.vtable


proc hmacUpdate*(ctx: ptr HmacContext; data: pointer; len: uint) {.importcFunc,
    importc: "br_hmac_update", header: "bearssl_hmac.h".}

proc hmacOut*(ctx: ptr HmacContext; `out`: pointer): uint {.importcFunc,
    importc: "br_hmac_out", header: "bearssl_hmac.h".}

proc hmacOutCT*(ctx: ptr HmacContext; data: pointer; len: uint; minLen: uint;
               maxLen: uint; `out`: pointer): uint {.importcFunc,
    importc: "br_hmac_outCT", header: "bearssl_hmac.h".}
