import
  typetraits,
  ./abi/bearssl_pem

export bearssl_pem

type
  PemDestProc* = proc (
      destCtx: pointer; src: pointer; len: csize_t
    ) {.cdecl, gcsafe, noSideEffect, raises: [].}

  PemDecoderContext* = ref object
    raw: RawPemDecoderContext
    dest: PemDestProc
    destCtx: pointer

func init*(v: var PemDecoderContext) =
  # Careful, (Raw|)PemDecoderContext items are not copyable!
  # TODO prevent copying
  if v == nil:
    v.new()
  pemDecoderInit(v.raw)

func push*(ctx: var PemDecoderContext, data: openArray[byte|char]): int =
  doAssert ctx != nil, "PemDecoderContext not initialized"
  if data.len > 0:
    let consumed = pemDecoderPush(
      ctx[].raw, unsafeAddr data[0], uint data.len)
    int(consumed)
  else:
    0

func destWrapper(destCtx: pointer, src: ConstPointer, len: csize_t) {.cdecl.} =
  let ctx = cast[PemDecoderContext](destCtx)
  ctx.dest(ctx.destCtx, cast[pointer](src), len)

when (NimMajor, NimMinor, NimPatch) >= (2, 2, 12):
  func setdest*(ctx: var PemDecoderContext; dest: PemDestProc; destCtx: pointer) =
    doAssert ctx != nil, "PemDecoderContext not initialized"
    ctx[].dest = dest
    ctx[].destCtx = destCtx
    ctx[].raw.dest = if dest != nil: destWrapper else: nil
    ctx[].raw.destCtx = cast[pointer](ctx)
else:
  # https://github.com/nim-lang/Nim/issues/25931
  # `dest` is passed on as `pointer`, not `PemDestProc`: structurally identical
  # callbacks (e.g. the X509 decoder `appendDn` and hash `update`) share one C
  # `typedef`, and a `ConstPointer` alias renders that typedef `const` in some
  # translation units (compilation-order dependent), breaking non-const
  # downstream callbacks (e.g. nim-chronos's PEM `itemAppend`) under
  # `-Werror=incompatible[-function]-pointer-types`.
  func setdestImpl(ctx: var PemDecoderContext; dest, destCtx: pointer) =
    doAssert ctx != nil, "PemDecoderContext not initialized"
    ctx[].dest = cast[PemDestProc](dest)
    ctx[].destCtx = destCtx
    ctx[].raw.dest = if dest != nil: destWrapper else: nil
    ctx[].raw.destCtx = cast[pointer](ctx)

  template setdest*(ctx: var PemDecoderContext; dest: PemDestProc; destCtx: pointer) =
    setdestImpl(ctx, cast[pointer](dest), destCtx)

func lastEvent*(ctx: var PemDecoderContext): cint =
  doAssert ctx != nil, "PemDecoderContext not initialized"
  pemDecoderEvent(ctx.raw)

func banner*(ctx: PemDecoderContext): string =
  ## Return the `name` field as a string
  doAssert ctx != nil, "PemDecoderContext not initialized"
  if ctx[].raw.name[ctx[].raw.name.high] == char(0):
    $(cast[cstring](unsafeAddr ctx[].raw.name))
  else:
    var res = newString(ctx[].raw.name.len)
    for i, c in ctx[].raw.name: res[i] = ctx[].raw.name[i]
    res

func pemEncode*(
    data: openArray[byte|char], banner: cstring, flags: cuint = 0): string =
  let bytes = pemEncode(nil, nil, uint data.len, banner, flags)
  result.setLen(int bytes + 1)
  discard pemEncode(
    addr result[0], unsafeAddr data[0], uint data.len, banner, flags)
  result.setLen(int bytes)
