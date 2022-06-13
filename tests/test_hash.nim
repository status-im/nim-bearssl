import std/[strutils, sequtils],
  unittest2,
  ../bearssl/hash

{.used.}

suite "Hashing":
  test "MD5":
    let
      input = ["",
              "a",
              "abc",
              "message digest",
              "abcdefghijklmnopqrstuvwxyz",
              "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
              "12345678901234567890123456789012345678901234567890123456789012345678901234567890"]
      output = ["d41d8cd98f00b204e9800998ecf8427e",
                "0cc175b9c0f1b6a831c399e269772661",
                "900150983cd24fb0d6963f7d28e17f72",
                "f96b697d7cb7938d525a2f31aaf161d0",
                "c3fcd3d76192e4007dfb496cca67e13b",
                "d174ab98d277d9f5a5611c2c9f419d9f",
                "57edf4a22be3c955ac49da2e2107b67a"]

    for i in 0 ..< input.len:
      var
        ctx = Md5Context()
        res: array[md5SIZE, uint8]

      md5Init(ctx)
      md5Update(ctx, input[i].cstring, uint input[i].len)
      md5Out(ctx, addr res[0])
      check res.foldl(a & b.toHex(), "").toLower() == output[i]
