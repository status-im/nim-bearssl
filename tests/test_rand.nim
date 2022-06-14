import
  unittest2,
  ../bearssl/rand

{.used.}

suite "random":
  test "simple random ops":
    # Some of these tests may end up triggering false fails, but given their
    # probability, should be fine

    let rng = HmacDrbgContext.new()

    var v: array[1024, byte]
    generate(rng[], v)

    let v2 = generate(rng[], array[1024, byte])
    check:
      v != default(array[1024, byte]) # probable
      v2 != default(array[1024, byte]) # probable

    for i in 0..<1000:
      doAssert cast[int](rng[].generate(bool)) in [0, 1]

    var bools: array[64 * 1024, bool]
    rng[].generate(bools)

    check:
      true in bools # probable

    var
      xxx = newSeq[int](1024)
      yyy = xxx
    rng[].generate(xxx)
    check:
      xxx != yyy # probable

  test "seed":
    var
      rng = HmacDrbgContext.init([byte 0])
      rng2 = HmacDrbgContext.init([byte 0])

    check:
      rng.generate(uint64) == rng2.generate(uint64)
