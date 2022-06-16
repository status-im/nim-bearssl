import
  typetraits,
  ./abi/bearssl_pem

export bearssl_pem

func init*(v: var PemDecoderContext) =
  # Careful, PemDecoderContext items are not copyable!
  # TODO prevent copying
  pemDecoderInit(v)

func push*(ctx: var PemDecoderContext, data: openArray[byte|char]): int =
  if data.len > 0:
    let consumed = pemDecoderPush(
      ctx, unsafeAddr data[0], uint data.len)
    int(consumed)
  else:
    0

func setdest*(
    ctx: var PemDecoderContext;
    dest: proc (destCtx: pointer;
      src: pointer; len: uint) {.cdecl, gcsafe, noSideEffect, raises: [].};
    destCtx: pointer) =
  pemDecoderSetdest(ctx, dest, destCtx)

func lastEvent*(ctx: var PemDecoderContext): cint =
  pemDecoderEvent(ctx)

func banner*(ctx: PemDecoderContext): string =
  ## Return the `name` field as a string
  if ctx.name[ctx.name.high] == char(0):
    $(unsafeAddr ctx.name)
  else:
    var res = newString(ctx.name.len)
    for i, c in ctx.name: res[i] = ctx.name[i]
    res

func pemEncode*(
    data: openArray[byte|char], banner: cstring, flags: cuint = 0): string =
  let bytes = pemEncode(nil, nil, uint data.len, banner, flags)
  result.setLen(int bytes + 1)
  discard pemEncode(
    addr result[0], unsafeAddr data[0], uint data.len, banner, flags)
  result.setLen(int bytes)
