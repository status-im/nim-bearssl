import
  "."/[csources, inner, hash]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_rand.h".}
{.used.}

const
  bearMacPath = bearSrcPath / "mac"

{.compile: bearMacPath / "hmac.c".}
{.compile: bearMacPath / "hmac_ct.c".}

type
  HmacKeyContext* {.importc: "br_hmac_key_context", header: "bearssl_hmac.h", bycopy.} = object
    digVtable* {.importc: "dig_vtable".}: ptr HashClass
    ksi* {.importc: "ksi".}: array[64, cuchar]
    kso* {.importc: "kso".}: array[64, cuchar]


proc hmacKeyInit*(kc: ptr HmacKeyContext; digestVtable: ptr HashClass; key: pointer;
                 keyLen: int) {.importcFunc, importc: "br_hmac_key_init",
                                header: "bearssl_hmac.h".}

type
  HmacContext* {.importc: "br_hmac_context", header: "bearssl_hmac.h", bycopy.} = object
    dig* {.importc: "dig".}: HashCompatContext
    kso* {.importc: "kso".}: array[64, cuchar]
    outLen* {.importc: "out_len".}: int


proc hmacInit*(ctx: ptr HmacContext; kc: ptr HmacKeyContext; outLen: int) {.
    importc: "br_hmac_init", headerFunc.}

proc hmacSize*(ctx: ptr HmacContext): int {.inline.} =
  return ctx.outLen

proc hmacUpdate*(ctx: ptr HmacContext; data: pointer; len: int) {.
    importc: "br_hmac_update", headerFunc.}

proc hmacOut*(ctx: ptr HmacContext; `out`: pointer): int {.
    importc: "br_hmac_out", headerFunc.}

proc hmacOutCT*(ctx: ptr HmacContext; data: pointer; len: int; minLen: int;
               maxLen: int; `out`: pointer): int {.
    importc: "br_hmac_outCT", headerFunc.}

