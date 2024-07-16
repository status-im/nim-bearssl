import
  unittest2,
  ../bearssl/[rand, ec]

{.used.}

type
  EcPrivateKey* = ref object
    buffer*: array[EC_KBUF_PRIV_MAX_SIZE, byte]
    key*: ec.EcPrivateKey

suite "ec":
  test "test ecKeygen interface":
    let rng = HmacDrbgContext.new()

    var ecimp = ecGetDefault()
    var res = new EcPrivateKey
    check ecKeygen(
      addr rng.vtable, ecimp, addr res.key, addr res.buffer[0], cint(EC_secp256r1)
    ) != 0
