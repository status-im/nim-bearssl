import
  ./abi/bearssl_rand

export bearssl_rand

func hmacDrbgGenerate*(ctx: var HmacDrbgContext, output: var openArray[byte]) =
  if output.len > 0:
    hmacDrbgGenerate(ctx, addr output[0], uint output.len)
