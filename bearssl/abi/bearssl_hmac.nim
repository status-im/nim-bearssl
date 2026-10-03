import ./[bearssl_hash, consttypes, csources, inner]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

{.compile: bearSrcPath & "mac/hmac.c".}
{.compile: bearSrcPath & "mac/hmac_ct.c".}

type
  HmacKeyContext* {.importc: "br_hmac_key_context", header: "bearssl_hmac.h", bycopy.} = object
    digVtable* {.importc: "dig_vtable".}: ptr HashClass
    ksi* {.importc: "ksi".}: array[64, byte]
    kso* {.importc: "kso".}: array[64, byte]



proc hmacKeyInit*(kc: var HmacKeyContext; digestVtable: ptr HashClass;
                 key: ConstPointer; keyLen: csize_t) {.importcFunc,
    importc: "br_hmac_key_init", header: "bearssl_hmac.h".}

proc hmacKeyGetDigest*(kc: var HmacKeyContext): ptr HashClass {.importcFunc,
    importc: "br_hmac_key_get_digest", header: "bearssl_hmac.h".}

type
  HmacContext* {.importc: "br_hmac_context", header: "bearssl_hmac.h", bycopy.} = object
    dig* {.importc: "dig".}: HashCompatContext
    kso* {.importc: "kso".}: array[64, byte]
    outLen* {.importc: "out_len".}: csize_t



proc hmacInit*(ctx: var HmacContext; kc: var HmacKeyContext; outLen: csize_t) {.importcFunc,
    importc: "br_hmac_init", header: "bearssl_hmac.h".}

proc hmacSize*(ctx: var HmacContext): csize_t {.importcFunc, importc: "br_hmac_size",
    header: "bearssl_hmac.h".}

proc hmacGetDigest*(hc: var HmacContext): ptr HashClass {.importcFunc,
    importc: "br_hmac_get_digest", header: "bearssl_hmac.h".}

proc hmacUpdate*(ctx: var HmacContext; data: ConstPointer; len: csize_t) {.importcFunc,
    importc: "br_hmac_update", header: "bearssl_hmac.h".}

proc hmacOut*(ctx: var HmacContext; `out`: pointer): csize_t {.importcFunc,
    importc: "br_hmac_out", header: "bearssl_hmac.h".}

proc hmacOutCT*(ctx: var HmacContext; data: ConstPointer; len: csize_t; minLen: csize_t;
               maxLen: csize_t; `out`: pointer): csize_t {.importcFunc,
    importc: "br_hmac_outCT", header: "bearssl_hmac.h".}
