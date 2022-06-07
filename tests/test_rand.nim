import
  unittest2,
  ../bearssl/rand

{.used.}

suite "random":
  test "simple random ops":
    let rng = HmacDrbgContext.new()

    var v: array[1024, byte]
    fill(rng[], v)

    let v2 = fill(rng[], array[1024, byte])
    check:
      v != default(array[1024, byte]) # possible, but not likely
      v2 != default(array[1024, byte]) # possible, but not likely

    for i in 0..<1000:
      doAssert cast[int](rng[].fill(bool)) in [0, 1]

  test "seed":
    var
      rng = HmacDrbgContext.init([byte 0])
      rng2 = HmacDrbgContext.init([byte 0])

    check:
      rng.fill(uint64) == rng2.fill(uint64)
