import
  unittest2,
  ../bearssl/random

{.used.}

suite "random":
  test "simple random ops":
    let rng = HmacDrbgContext.new()

    check:
      rng[].rand(1) <= 1

    var v: array[1024, byte]
    fill(rng[], v)

    let v2 = fill(rng[], array[1024, byte])
    check:
      v != default(array[1024, byte]) # possible, but not likely
      v2 != default(array[1024, byte]) # possible, but not likely

  test "seed":
    let
      rng = HmacDrbgContext.new([byte 0])
      rng2 = HmacDrbgContext.new([byte 0])

    check:
      rng[].fill(uint64) == rng2[].fill(uint64)
