import ./[consttypes, csources]
export consttypes

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

{.compile: bearSrcPath & "codec/pemdec.c".}
{.compile: bearSrcPath & "codec/pemenc.c".}

type
  INNER_C_STRUCT_bearssl_pem_1* {.importc: "br_pem_decoder_context::no_name",
                                   header: "bearssl_pem.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ConstPtrByte

  RawPemDecoderContext* {.importc: "br_pem_decoder_context", header: "bearssl_pem.h",
                      bycopy.} = object
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_bearssl_pem_1
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    hbuf* {.importc: "hbuf".}: ConstPtrByte
    hlen* {.importc: "hlen".}: csize_t
    dest* {.importc: "dest".}: proc (destCtx: pointer; src: ConstPointer; len: csize_t) {.
        importcFunc.}
    destCtx* {.importc: "dest_ctx".}: pointer
    event* {.importc: "event".}: byte
    name* {.importc: "name".}: array[128, char]
    buf* {.importc: "buf".}: array[255, byte]
    `ptr`* {.importc: "ptr".}: csize_t



proc pemDecoderInit*(ctx: var RawPemDecoderContext) {.importcFunc,
    importc: "br_pem_decoder_init", header: "bearssl_pem.h".}

proc pemDecoderPush*(ctx: var RawPemDecoderContext; data: ConstPointer; len: csize_t): csize_t {.
    importcFunc, importc: "br_pem_decoder_push", header: "bearssl_pem.h".}

proc pemDecoderEvent*(ctx: var RawPemDecoderContext): cint {.importcFunc,
    importc: "br_pem_decoder_event", header: "bearssl_pem.h".}

const
  PEM_BEGIN_OBJ* = 1


const
  PEM_END_OBJ* = 2


const
  PEM_ERROR* = 3


proc pemDecoderName*(ctx: var RawPemDecoderContext): ConstCstring {.importcFunc,
    importc: "br_pem_decoder_name", header: "bearssl_pem.h".}

proc pemEncode*(dest: pointer; data: ConstPointer; len: csize_t; banner: ConstCstring;
               flags: cuint): csize_t {.importcFunc, importc: "br_pem_encode",
                                     header: "bearssl_pem.h".}

const
  PEM_LINE64* = 0x0001


const
  PEM_CRLF* = 0x0002
