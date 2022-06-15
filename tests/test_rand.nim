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
    rng[].generate(v)

    let v2 = rng[].generate(array[1024, byte])
    check:
      v != default(array[1024, byte]) # probable
      v2 != default(array[1024, byte]) # probable

    for i in 0..<1000:
      doAssert cast[int](rng[].generate(bool)) in [0, 1]

    var bools: array[64 * 1024, bool]
    rng[].generate(bools)

    check:
      true in bools # probable
      false in bools # probable

    var
      xxx = newSeq[int](1024)
      yyy = xxx
    rng[].generate(xxx)
    check:
      xxx != yyy # probable

  test "seed":
    for seed in [@[byte 0], @[byte 1], @[byte 1, 1], @[byte 42, 13, 37]]:
      var
        rng = HmacDrbgContext.init(seed)
        rng2 = HmacDrbgContext.init(seed)

      check:
        rng.generate(uint64) == rng2.generate(uint64)

    for seed in [@[0], @[1], @[1, 1], @[42, 1337, -5]]:
      var
        rng = HmacDrbgContext.init(seed)
        rng2 = HmacDrbgContext.init(seed)

      check:
        rng.generate(uint64) == rng2.generate(uint64)

  test "antiseed":
    var
      rng = HmacDrbgContext.init([0])
      rng2 = HmacDrbgContext.init([1])

    check:
      rng.generate(array[1024, byte]) != rng2.generate(array[1024, byte])
