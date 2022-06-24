import
  "."/[bearssl_block, bearssl_hash, csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearAeadPath = bearSrcPath & "aead/"

{.compile: bearAeadPath & "ccm.c".}
{.compile: bearAeadPath & "eax.c".}
{.compile: bearAeadPath & "gcm.c".}

type
  AeadClass* {.importc: "br_aead_class", header: "bearssl_aead.h", bycopy.} = object
    tagSize* {.importc: "tag_size".}: uint
    reset* {.importc: "reset".}: proc (cc: ptr ptr AeadClass; iv: pointer; len: uint) {.
        importcFunc.}
    aadInject* {.importc: "aad_inject".}: proc (cc: ptr ptr AeadClass; data: pointer;
        len: uint) {.importcFunc.}
    flip* {.importc: "flip".}: proc (cc: ptr ptr AeadClass) {.importcFunc.}
    run* {.importc: "run".}: proc (cc: ptr ptr AeadClass; encrypt: cint; data: pointer;
                               len: uint) {.importcFunc.}
    getTag* {.importc: "get_tag".}: proc (cc: ptr ptr AeadClass; tag: pointer) {.importcFunc.}
    checkTag* {.importc: "check_tag".}: proc (cc: ptr ptr AeadClass; tag: pointer): uint32 {.
        importcFunc.}
    getTagTrunc* {.importc: "get_tag_trunc".}: proc (cc: ptr ptr AeadClass;
        tag: pointer; len: uint) {.importcFunc.}
    checkTagTrunc* {.importc: "check_tag_trunc".}: proc (cc: ptr ptr AeadClass;
        tag: pointer; len: uint): uint32 {.importcFunc.}



type
  GcmContext* {.importc: "br_gcm_context", header: "bearssl_aead.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr AeadClass
    bctx* {.importc: "bctx".}: ptr ptr BlockCtrClass
    gh* {.importc: "gh".}: Ghash
    h* {.importc: "h".}: array[16, byte]
    j01* {.importc: "j0_1".}: array[12, byte]
    buf* {.importc: "buf".}: array[16, byte]
    y* {.importc: "y".}: array[16, byte]
    j02* {.importc: "j0_2".}: uint32
    jc* {.importc: "jc".}: uint32
    countAad* {.importc: "count_aad".}: uint64
    countCtr* {.importc: "count_ctr".}: uint64



proc gcmInit*(ctx: var GcmContext; bctx: ptr ptr BlockCtrClass; gh: Ghash) {.importcFunc,
    importc: "br_gcm_init", header: "bearssl_aead.h".}

proc gcmReset*(ctx: var GcmContext; iv: pointer; len: uint) {.importcFunc,
    importc: "br_gcm_reset", header: "bearssl_aead.h".}

proc gcmAadInject*(ctx: var GcmContext; data: pointer; len: uint) {.importcFunc,
    importc: "br_gcm_aad_inject", header: "bearssl_aead.h".}

proc gcmFlip*(ctx: var GcmContext) {.importcFunc, importc: "br_gcm_flip",
                                 header: "bearssl_aead.h".}

proc gcmRun*(ctx: var GcmContext; encrypt: cint; data: pointer; len: uint) {.importcFunc,
    importc: "br_gcm_run", header: "bearssl_aead.h".}

proc gcmGetTag*(ctx: var GcmContext; tag: pointer) {.importcFunc, importc: "br_gcm_get_tag",
    header: "bearssl_aead.h".}

proc gcmCheckTag*(ctx: var GcmContext; tag: pointer): uint32 {.importcFunc,
    importc: "br_gcm_check_tag", header: "bearssl_aead.h".}

proc gcmGetTagTrunc*(ctx: var GcmContext; tag: pointer; len: uint) {.importcFunc,
    importc: "br_gcm_get_tag_trunc", header: "bearssl_aead.h".}

proc gcmCheckTagTrunc*(ctx: var GcmContext; tag: pointer; len: uint): uint32 {.importcFunc,
    importc: "br_gcm_check_tag_trunc", header: "bearssl_aead.h".}

var gcmVtable* {.importc: "br_gcm_vtable", header: "bearssl_aead.h".}: AeadClass


type
  EaxContext* {.importc: "br_eax_context", header: "bearssl_aead.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr AeadClass
    bctx* {.importc: "bctx".}: ptr ptr BlockCtrcbcClass
    l2* {.importc: "L2".}: array[16, byte]
    l4* {.importc: "L4".}: array[16, byte]
    nonce* {.importc: "nonce".}: array[16, byte]
    head* {.importc: "head".}: array[16, byte]
    ctr* {.importc: "ctr".}: array[16, byte]
    cbcmac* {.importc: "cbcmac".}: array[16, byte]
    buf* {.importc: "buf".}: array[16, byte]
    `ptr`* {.importc: "ptr".}: uint



type
  EaxState* {.importc: "br_eax_state", header: "bearssl_aead.h", bycopy.} = object
    st* {.importc: "st".}: array[3, array[16, byte]]



proc eaxInit*(ctx: var EaxContext; bctx: ptr ptr BlockCtrcbcClass) {.importcFunc,
    importc: "br_eax_init", header: "bearssl_aead.h".}

proc eaxCapture*(ctx: var EaxContext; st: ptr EaxState) {.importcFunc,
    importc: "br_eax_capture", header: "bearssl_aead.h".}

proc eaxReset*(ctx: var EaxContext; nonce: pointer; len: uint) {.importcFunc,
    importc: "br_eax_reset", header: "bearssl_aead.h".}

proc eaxResetPreAad*(ctx: var EaxContext; st: ptr EaxState; nonce: pointer; len: uint) {.
    importcFunc, importc: "br_eax_reset_pre_aad", header: "bearssl_aead.h".}

proc eaxResetPostAad*(ctx: var EaxContext; st: ptr EaxState; nonce: pointer; len: uint) {.
    importcFunc, importc: "br_eax_reset_post_aad", header: "bearssl_aead.h".}

proc eaxAadInject*(ctx: var EaxContext; data: pointer; len: uint) {.importcFunc,
    importc: "br_eax_aad_inject", header: "bearssl_aead.h".}

proc eaxFlip*(ctx: var EaxContext) {.importcFunc, importc: "br_eax_flip",
                                 header: "bearssl_aead.h".}

proc eaxGetAadMac*(ctx: var EaxContext; st: ptr EaxState) {.inline.} =
  copyMem(unsafeAddr st.st[1], unsafeAddr ctx.head, sizeof(ctx.head))


proc eaxRun*(ctx: var EaxContext; encrypt: cint; data: pointer; len: uint) {.importcFunc,
    importc: "br_eax_run", header: "bearssl_aead.h".}

proc eaxGetTag*(ctx: var EaxContext; tag: pointer) {.importcFunc, importc: "br_eax_get_tag",
    header: "bearssl_aead.h".}

proc eaxCheckTag*(ctx: var EaxContext; tag: pointer): uint32 {.importcFunc,
    importc: "br_eax_check_tag", header: "bearssl_aead.h".}

proc eaxGetTagTrunc*(ctx: var EaxContext; tag: pointer; len: uint) {.importcFunc,
    importc: "br_eax_get_tag_trunc", header: "bearssl_aead.h".}

proc eaxCheckTagTrunc*(ctx: var EaxContext; tag: pointer; len: uint): uint32 {.importcFunc,
    importc: "br_eax_check_tag_trunc", header: "bearssl_aead.h".}

var eaxVtable* {.importc: "br_eax_vtable", header: "bearssl_aead.h".}: AeadClass


type
  CcmContext* {.importc: "br_ccm_context", header: "bearssl_aead.h", bycopy.} = object
    bctx* {.importc: "bctx".}: ptr ptr BlockCtrcbcClass
    ctr* {.importc: "ctr".}: array[16, byte]
    cbcmac* {.importc: "cbcmac".}: array[16, byte]
    tagmask* {.importc: "tagmask".}: array[16, byte]
    buf* {.importc: "buf".}: array[16, byte]
    `ptr`* {.importc: "ptr".}: uint
    tagLen* {.importc: "tag_len".}: uint



proc ccmInit*(ctx: var CcmContext; bctx: ptr ptr BlockCtrcbcClass) {.importcFunc,
    importc: "br_ccm_init", header: "bearssl_aead.h".}

proc ccmReset*(ctx: var CcmContext; nonce: pointer; nonceLen: uint; aadLen: uint64;
              dataLen: uint64; tagLen: uint): cint {.importcFunc,
    importc: "br_ccm_reset", header: "bearssl_aead.h".}

proc ccmAadInject*(ctx: var CcmContext; data: pointer; len: uint) {.importcFunc,
    importc: "br_ccm_aad_inject", header: "bearssl_aead.h".}

proc ccmFlip*(ctx: var CcmContext) {.importcFunc, importc: "br_ccm_flip",
                                 header: "bearssl_aead.h".}

proc ccmRun*(ctx: var CcmContext; encrypt: cint; data: pointer; len: uint) {.importcFunc,
    importc: "br_ccm_run", header: "bearssl_aead.h".}

proc ccmGetTag*(ctx: var CcmContext; tag: pointer): uint {.importcFunc,
    importc: "br_ccm_get_tag", header: "bearssl_aead.h".}

proc ccmCheckTag*(ctx: var CcmContext; tag: pointer): uint32 {.importcFunc,
    importc: "br_ccm_check_tag", header: "bearssl_aead.h".}
