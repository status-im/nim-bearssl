import
  unittest2,
  ../bearssl/pem

suite "PEM":
  test "roundtrip":
    let
      data = [byte 0, 1, 2, 3]
      pem = pemEncode(data, "")

    var
      ctx: PemDecoderContext
      called = false

    ctx.init()

    proc test(dctx: pointer, data: pointer, len: uint) {.cdecl.} =
      cast[ptr bool](dctx)[] = true

    ctx.setdest(test, addr called)

    var read = 0
    while read < pem.len:
      let
        consumed = ctx.push(pem.toOpenArray(read, pem.high))
      read += consumed
      if read < pem.len:
        check: ctx.lastEvent > 0

    check:
      pem.len > data.len
      called
