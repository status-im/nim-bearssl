import
  typetraits,
  ./abi/bearssl_pem

export bearssl_pem

func init*(v: var PemDecoderContext) =
  # Careful, PemDecoderContext items are not copyable!
  # TODO prevent copying
  pemDecoderInit(v)

func push*[S](ctx: var PemDecoderContext, data: openArray[S]): int =
  static: doAssert supportsCopyMem(S)
  if data.len > 0:
    let consumed = pemDecoderPush(
      ctx, unsafeAddr data[0], uint data.len * sizeof(S))
    int(consumed) div sizeof(S)
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

func name*(ctx: PemDecoderContext): cstring =
  unsafeAddr ctx.name

func pemEncode*(
    data: openArray[byte], banner: cstring, flags: cuint = 0): seq[byte] =
  let bytes = pemEncode(nil, nil, uint data.len, banner, flags)
  result.setLen(int bytes + 1)
  discard pemEncode(
    addr result[0], unsafeAddr data[0], uint data.len, banner, flags)
  result.setLen(int bytes)
