import
  unittest2,
  ../bearssl/[rand, rsa]

{.used.}

const
  DefaultKeySize* = 3072 ## Default RSA key size in bits.
  DefaultPublicExponent* = 65537'u32

type
  RsaPrivateKey* = ref object
    buffer*: seq[byte]
    seck*: rsa.RsaPrivateKey
    pubk*: rsa.RsaPublicKey
    pexp*: ptr byte
    pexplen*: uint

suite "rsa":
  test "rsaKeygenGetDefault":
    let rng = HmacDrbgContext.new()

    let
      sko = 0
      pko = rsaKbufPrivSize(DefaultKeySize)
      eko = pko + rsaKbufPubSize(DefaultKeySize)
      length = eko + ((DefaultKeySize + 7) shr 3)

    let res = new RsaPrivateKey
    res.buffer = newSeq[byte](length)

    var keygen = rsaKeygenGetDefault()
    check keygen(
      addr rng.vtable,
      addr res.seck,
      addr res.buffer[sko],
      addr res.pubk,
      addr res.buffer[pko],
      cuint(DefaultKeySize),
      DefaultPublicExponent,
    ) != 0