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
  test "SHA512":
    const
      output = [
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
        "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
        "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
        "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843"
      ]

    for i in 0 ..< input.len:
      var
        ctx = Sha512Context()
        res: array[sha512SIZE, uint8]

      sha512Init(ctx)
      sha512Update(ctx, input[i].cstring, uint input[i].len)
      sha512Out(ctx, addr res[0])
      check res.foldl(a & b.toHex(), "").toLower() == output[i]
