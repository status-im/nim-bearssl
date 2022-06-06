## Nim-BearSSL
## Copyright (c) 2018-2022 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

import
  "."/[csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_pem.h".}
{.used.}

const
  bearCodecPath = bearSrcPath & "/" & "codec" & "/"

{.compile: bearCodecPath / "pemdec.c".}
{.compile: bearCodecPath / "pemenc.c".}

type
  INNER_C_STRUCT_1475532182* {.importc: "no_name", header: "bearssl_pem.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr cuchar

  PemDecoderContext* {.importc: "br_pem_decoder_context", header: "bearssl_pem.h",
                      bycopy.} = object
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_1475532182
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


proc pemDecoderInit*(ctx: ptr PemDecoderContext) {.
    importc: "br_pem_decoder_init", headerFunc.}

proc pemDecoderPush*(ctx: ptr PemDecoderContext; data: pointer; len: int): int {.
    importc: "br_pem_decoder_push", headerFunc.}

proc pemDecoderSetdest*(ctx: ptr PemDecoderContext; dest: proc (destCtx: pointer;
    src: pointer; len: int) {.importcFunc.}; destCtx: pointer) {.inline.} =
  ctx.dest = dest
  ctx.destCtx = destCtx

proc pemDecoderEvent*(ctx: ptr PemDecoderContext): cint {.
    importc: "br_pem_decoder_event", headerFunc.}

proc pemDecoderName*(ctx: ptr PemDecoderContext): cstring {.inline.} =
  return addr ctx.name

const
  PEM_BEGIN_OBJ* = 1

const
  PEM_END_OBJ* = 2

const
  PEM_ERROR* = 3

