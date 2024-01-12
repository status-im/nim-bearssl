import std/os
import bearssl/hash

let inp = paramStr(1)
var
  ctx = Md5Context()
  res: array[md5SIZE, uint8]

md5Init(ctx)
md5Update(ctx, inp.cstring, uint inp.len)
md5Out(ctx, addr res[0])
echo $res
