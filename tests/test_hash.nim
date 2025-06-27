import std/[strutils, sequtils],
  unittest2,
  ../bearssl/hash

{.used.}

suite "Hashing":
  const
    input = [
      "",
      "a",
      "abc",
      "message digest",
      "abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    ]
  test "MD5":
    const
      output = [
        "d41d8cd98f00b204e9800998ecf8427e",
        "0cc175b9c0f1b6a831c399e269772661",
        "900150983cd24fb0d6963f7d28e17f72",
        "f96b697d7cb7938d525a2f31aaf161d0",
        "c3fcd3d76192e4007dfb496cca67e13b",
        "d174ab98d277d9f5a5611c2c9f419d9f",
        "57edf4a22be3c955ac49da2e2107b67a"
      ]

    for i in 0 ..< input.len:
      var
        ctx = Md5Context()
        res: array[md5SIZE, uint8]

      md5Init(ctx)
      md5Update(ctx, input[i].cstring, uint input[i].len)
      md5Out(ctx, addr res[0])
      check res.foldl(a & b.toHex(), "").toLower() == output[i]
  test "SHA256":
    const
      output = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
        "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
        "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
        "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
      ]

    for i in 0 ..< input.len:
      var
        ctx = Sha256Context()
        res: array[sha256SIZE, uint8]

      sha256Init(ctx)
      sha256Update(ctx, input[i].cstring, uint input[i].len)
      sha256Out(ctx, addr res[0])
      check res.foldl(a & b.toHex(), "").toLower() == output[i]
