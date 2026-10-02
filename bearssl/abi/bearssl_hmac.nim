import ./[bearssl_hash, consttypes, csources, inner]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearMacPath = bearSrcPath & "mac/"

{.compile: bearMacPath & "hmac.c".}
{.compile: bearMacPath & "hmac_ct.c".}

type
  HmacKeyContext* {.importc: "br_hmac_key_context", header: "bearssl_hmac.h", bycopy.} = object
    digVtable* {.importc: "dig_vtable".}: ptr HashClass
    ksi* {.importc: "ksi".}: array[64, byte]
    kso* {.importc: "kso".}: array[64, byte]



proc hmacKeyInit*(kc: var HmacKeyContext; digestVtable: ptr HashClass; key: ConstPointer;
                 keylen: csize_t) {.importcFunc, importc: "br_hmac_key_init",
                                  header: "bearssl_hmac.h".}

proc hmacKeyGetDigest*(kc: var HmacKeyContext): ptr HashClass {.inline.} =
  return kc.digVtable


type
  HmacContext* {.importc: "br_hmac_context", header: "bearssl_hmac.h", bycopy.} = object
    dig* {.importc: "dig".}: HashCompatContext
    kso* {.importc: "kso".}: array[64, byte]
    outLen* {.importc: "out_len".}: csize_t



proc hmacInit*(ctx: var HmacContext; kc: var HmacKeyContext; outlen: csize_t) {.importcFunc,
    importc: "br_hmac_init", header: "bearssl_hmac.h".}

proc hmacSize*(ctx: var HmacContext): csize_t {.inline.} =
  return ctx.outLen


proc hmacGetDigest*(hc: var HmacContext): ptr HashClass {.inline.} =
  return hc.dig.vtable


proc hmacUpdate*(ctx: var HmacContext; data: ConstPointer; len: csize_t) {.importcFunc,
    importc: "br_hmac_update", header: "bearssl_hmac.h".}

proc hmacOut*(ctx: var HmacContext; `out`: pointer): csize_t {.importcFunc,
    importc: "br_hmac_out", header: "bearssl_hmac.h".}

proc hmacOutCT*(ctx: var HmacContext; data: ConstPointer; len: csize_t; minlen: csize_t;
               maxlen: csize_t; `out`: pointer): csize_t {.importcFunc,
    importc: "br_hmac_outCT", header: "bearssl_hmac.h".}
