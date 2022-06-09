import
  "."/[csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearCodecPath = bearSrcPath & "/" & "codec" & "/"

{.compile: bearCodecPath / "pemdec.c".}
{.compile: bearCodecPath / "pemenc.c".}

type
  INNER_C_STRUCT_bearssl_pem_1* {.importc: "br_pem_decoder_context::no_name",
                                 header: "bearssl_pem.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr cuchar

  PemDecoderContext* {.importc: "br_pem_decoder_context", header: "bearssl_pem.h",
                      bycopy.} = object
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_bearssl_pem_1
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    hbuf* {.importc: "hbuf".}: ptr cuchar
    hlen* {.importc: "hlen".}: int
    dest* {.importc: "dest".}: proc (destCtx: pointer; src: pointer; len: int) {.importcFunc.}
    destCtx* {.importc: "dest_ctx".}: pointer
    event* {.importc: "event".}: cuchar
    name* {.importc: "name".}: array[128, char]
    buf* {.importc: "buf".}: array[255, cuchar]
    `ptr`* {.importc: "ptr".}: int



proc pemDecoderInit*(ctx: ptr PemDecoderContext) {.importcFunc,
    importc: "br_pem_decoder_init", header: "bearssl_pem.h".}

proc pemDecoderPush*(ctx: ptr PemDecoderContext; data: pointer; len: int): int {.
    importcFunc, importc: "br_pem_decoder_push", header: "bearssl_pem.h".}

proc pemDecoderSetdest*(ctx: ptr PemDecoderContext; dest: proc (destCtx: pointer;
    src: pointer; len: int) {.importcFunc.}; destCtx: pointer) {.inline, importcFunc,
    importc: "br_pem_decoder_setdest".} =
  ctx.dest = dest
  ctx.destCtx = destCtx


proc pemDecoderEvent*(ctx: ptr PemDecoderContext): cint {.importcFunc,
    importc: "br_pem_decoder_event", header: "bearssl_pem.h".}


const
  PEM_BEGIN_OBJ* = 1


const
  PEM_END_OBJ* = 2


const
  PEM_ERROR* = 3

proc pemDecoderName*(ctx: ptr PemDecoderContext): cstring {.inline.} =
  return addr ctx.name

proc pemEncode*(dest: pointer; data: pointer; len: int; banner: cstring; flags: cuint): int {.
    importcFunc, importc: "br_pem_encode", header: "bearssl_pem.h".}

const
  PEM_LINE64* = 0x0001


const
  PEM_CRLF* = 0x0002
