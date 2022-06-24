import
  "."/[bearssl_hash, bearssl_rand, csources, intx]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearEcPath = bearSrcPath & "ec/"

{.compile: bearEcPath & "ecdsa_atr.c".}
{.compile: bearEcPath & "ecdsa_default_sign_asn1.c".}
{.compile: bearEcPath & "ecdsa_default_sign_raw.c".}
{.compile: bearEcPath & "ecdsa_default_vrfy_asn1.c".}
{.compile: bearEcPath & "ecdsa_default_vrfy_raw.c".}
{.compile: bearEcPath & "ecdsa_i15_bits.c".}
{.compile: bearEcPath & "ecdsa_i15_sign_asn1.c".}
{.compile: bearEcPath & "ecdsa_i15_sign_raw.c".}
{.compile: bearEcPath & "ecdsa_i15_vrfy_asn1.c".}
{.compile: bearEcPath & "ecdsa_i15_vrfy_raw.c".}
{.compile: bearEcPath & "ecdsa_i31_bits.c".}
{.compile: bearEcPath & "ecdsa_i31_sign_asn1.c".}
{.compile: bearEcPath & "ecdsa_i31_sign_raw.c".}
{.compile: bearEcPath & "ecdsa_i31_vrfy_asn1.c".}
{.compile: bearEcPath & "ecdsa_i31_vrfy_raw.c".}
{.compile: bearEcPath & "ecdsa_rta.c".}
{.compile: bearEcPath & "ec_all_m15.c".}
{.compile: bearEcPath & "ec_all_m31.c".}
{.compile: bearEcPath & "ec_c25519_i15.c".}
{.compile: bearEcPath & "ec_c25519_i31.c".}
{.compile: bearEcPath & "ec_c25519_m15.c".}
{.compile: bearEcPath & "ec_c25519_m31.c".}
{.compile: bearEcPath & "ec_c25519_m62.c".}
{.compile: bearEcPath & "ec_c25519_m64.c".}
{.compile: bearEcPath & "ec_curve25519.c".}
{.compile: bearEcPath & "ec_default.c".}
{.compile: bearEcPath & "ec_keygen.c".}
{.compile: bearEcPath & "ec_p256_m15.c".}
{.compile: bearEcPath & "ec_p256_m31.c".}
{.compile: bearEcPath & "ec_p256_m62.c".}
{.compile: bearEcPath & "ec_p256_m64.c".}
{.compile: bearEcPath & "ec_prime_i15.c".}
{.compile: bearEcPath & "ec_prime_i31.c".}
{.compile: bearEcPath & "ec_pubkey.c".}
{.compile: bearEcPath & "ec_secp256r1.c".}
{.compile: bearEcPath & "ec_secp384r1.c".}
{.compile: bearEcPath & "ec_secp521r1.c".}


const
  EC_sect163k1* = 1


const
  EC_sect163r1* = 2


const
  EC_sect163r2* = 3


const
  EC_sect193r1* = 4


const
  EC_sect193r2* = 5


const
  EC_sect233k1* = 6


const
  EC_sect233r1* = 7


const
  EC_sect239k1* = 8


const
  EC_sect283k1* = 9


const
  EC_sect283r1* = 10


const
  EC_sect409k1* = 11


const
  EC_sect409r1* = 12


const
  EC_sect571k1* = 13


const
  EC_sect571r1* = 14


const
  EC_secp160k1* = 15


const
  EC_secp160r1* = 16


const
  EC_secp160r2* = 17


const
  EC_secp192k1* = 18


const
  EC_secp192r1* = 19


const
  EC_secp224k1* = 20


const
  EC_secp224r1* = 21


const
  EC_secp256k1* = 22


const
  EC_secp256r1* = 23


const
  EC_secp384r1* = 24


const
  EC_secp521r1* = 25


const
  EC_brainpoolP256r1* = 26


const
  EC_brainpoolP384r1* = 27


const
  EC_brainpoolP512r1* = 28


const
  EC_curve25519* = 29


const
  EC_curve448* = 30


type
  EcPublicKey* {.importc: "br_ec_public_key", header: "bearssl_ec.h", bycopy.} = object
    curve* {.importc: "curve".}: cint
    q* {.importc: "q".}: ptr byte
    qlen* {.importc: "qlen".}: uint



type
  EcPrivateKey* {.importc: "br_ec_private_key", header: "bearssl_ec.h", bycopy.} = object
    curve* {.importc: "curve".}: cint
    x* {.importc: "x".}: ptr byte
    xlen* {.importc: "xlen".}: uint



type
  EcImpl* {.importc: "br_ec_impl", header: "bearssl_ec.h", bycopy.} = object
    supportedCurves* {.importc: "supported_curves".}: uint32
    generator* {.importc: "generator".}: proc (curve: cint; len: var uint): ptr byte {.
        importcFunc.}
    order* {.importc: "order".}: proc (curve: cint; len: var uint): ptr byte {.importcFunc.}
    xoff* {.importc: "xoff".}: proc (curve: cint; len: var uint): uint {.importcFunc.}
    mul* {.importc: "mul".}: proc (g: ptr byte; glen: uint; x: ptr byte;
                               xlen: uint; curve: cint): uint32 {.importcFunc.}
    mulgen* {.importc: "mulgen".}: proc (r: ptr byte; x: ptr byte; xlen: uint;
                                     curve: cint): uint {.importcFunc.}
    muladd* {.importc: "muladd".}: proc (a: ptr byte; b: ptr byte; len: uint;
                                     x: ptr byte; xlen: uint; y: ptr byte;
                                     ylen: uint; curve: cint): uint32 {.importcFunc.}


var ecPrimeI31* {.importc: "br_ec_prime_i31", header: "bearssl_ec.h".}: EcImpl


var ecPrimeI15* {.importc: "br_ec_prime_i15", header: "bearssl_ec.h".}: EcImpl


var ecP256M15* {.importc: "br_ec_p256_m15", header: "bearssl_ec.h".}: EcImpl


var ecP256M31* {.importc: "br_ec_p256_m31", header: "bearssl_ec.h".}: EcImpl


var ecP256M62* {.importc: "br_ec_p256_m62", header: "bearssl_ec.h".}: EcImpl


proc ecP256M62Get*(): ptr EcImpl {.importcFunc, importc: "br_ec_p256_m62_get",
                               header: "bearssl_ec.h".}

var ecP256M64* {.importc: "br_ec_p256_m64", header: "bearssl_ec.h".}: EcImpl


proc ecP256M64Get*(): ptr EcImpl {.importcFunc, importc: "br_ec_p256_m64_get",
                               header: "bearssl_ec.h".}


var ecC25519I15* {.importc: "br_ec_c25519_i15", header: "bearssl_ec.h".}: EcImpl


var ecC25519I31* {.importc: "br_ec_c25519_i31", header: "bearssl_ec.h".}: EcImpl


var ecC25519M15* {.importc: "br_ec_c25519_m15", header: "bearssl_ec.h".}: EcImpl


var ecC25519M31* {.importc: "br_ec_c25519_m31", header: "bearssl_ec.h".}: EcImpl


var ecC25519M62* {.importc: "br_ec_c25519_m62", header: "bearssl_ec.h".}: EcImpl


proc ecC25519M62Get*(): ptr EcImpl {.importcFunc, importc: "br_ec_c25519_m62_get",
                                 header: "bearssl_ec.h".}

var ecC25519M64* {.importc: "br_ec_c25519_m64", header: "bearssl_ec.h".}: EcImpl


proc ecC25519M64Get*(): ptr EcImpl {.importcFunc, importc: "br_ec_c25519_m64_get",
                                 header: "bearssl_ec.h".}


var ecAllM15* {.importc: "br_ec_all_m15", header: "bearssl_ec.h".}: EcImpl


var ecAllM31* {.importc: "br_ec_all_m31", header: "bearssl_ec.h".}: EcImpl


proc ecGetDefault*(): ptr EcImpl {.importcFunc, importc: "br_ec_get_default",
                               header: "bearssl_ec.h".}

proc ecdsaRawToAsn1*(sig: pointer; sigLen: uint): uint {.importcFunc,
    importc: "br_ecdsa_raw_to_asn1", header: "bearssl_ec.h".}

proc ecdsaAsn1ToRaw*(sig: pointer; sigLen: uint): uint {.importcFunc,
    importc: "br_ecdsa_asn1_to_raw", header: "bearssl_ec.h".}

type
  EcdsaSign* {.importc: "br_ecdsa_sign".} = proc (impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                  sk: ptr EcPrivateKey; sig: pointer): uint {.importcFunc.}


type
  EcdsaVrfy* {.importc: "br_ecdsa_vrfy".} = proc (impl: ptr EcImpl; hash: pointer; hashLen: uint;
                  pk: ptr EcPublicKey; sig: pointer; sigLen: uint): uint32 {.importcFunc.}


proc ecdsaI31SignAsn1*(impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                      sk: ptr EcPrivateKey; sig: pointer): uint {.importcFunc,
    importc: "br_ecdsa_i31_sign_asn1", header: "bearssl_ec.h".}

proc ecdsaI31SignRaw*(impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                     sk: ptr EcPrivateKey; sig: pointer): uint {.importcFunc,
    importc: "br_ecdsa_i31_sign_raw", header: "bearssl_ec.h".}

proc ecdsaI31VrfyAsn1*(impl: ptr EcImpl; hash: pointer; hashLen: uint;
                      pk: ptr EcPublicKey; sig: pointer; sigLen: uint): uint32 {.
    importcFunc, importc: "br_ecdsa_i31_vrfy_asn1", header: "bearssl_ec.h".}

proc ecdsaI31VrfyRaw*(impl: ptr EcImpl; hash: pointer; hashLen: uint;
                     pk: ptr EcPublicKey; sig: pointer; sigLen: uint): uint32 {.
    importcFunc, importc: "br_ecdsa_i31_vrfy_raw", header: "bearssl_ec.h".}

proc ecdsaI15SignAsn1*(impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                      sk: ptr EcPrivateKey; sig: pointer): uint {.importcFunc,
    importc: "br_ecdsa_i15_sign_asn1", header: "bearssl_ec.h".}

proc ecdsaI15SignRaw*(impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                     sk: ptr EcPrivateKey; sig: pointer): uint {.importcFunc,
    importc: "br_ecdsa_i15_sign_raw", header: "bearssl_ec.h".}

proc ecdsaI15VrfyAsn1*(impl: ptr EcImpl; hash: pointer; hashLen: uint;
                      pk: ptr EcPublicKey; sig: pointer; sigLen: uint): uint32 {.
    importcFunc, importc: "br_ecdsa_i15_vrfy_asn1", header: "bearssl_ec.h".}

proc ecdsaI15VrfyRaw*(impl: ptr EcImpl; hash: pointer; hashLen: uint;
                     pk: ptr EcPublicKey; sig: pointer; sigLen: uint): uint32 {.
    importcFunc, importc: "br_ecdsa_i15_vrfy_raw", header: "bearssl_ec.h".}

proc ecdsaSignAsn1GetDefault*(): EcdsaSign {.importcFunc,
    importc: "br_ecdsa_sign_asn1_get_default", header: "bearssl_ec.h".}

proc ecdsaSignRawGetDefault*(): EcdsaSign {.importcFunc,
    importc: "br_ecdsa_sign_raw_get_default", header: "bearssl_ec.h".}

proc ecdsaVrfyAsn1GetDefault*(): EcdsaVrfy {.importcFunc,
    importc: "br_ecdsa_vrfy_asn1_get_default", header: "bearssl_ec.h".}

proc ecdsaVrfyRawGetDefault*(): EcdsaVrfy {.importcFunc,
    importc: "br_ecdsa_vrfy_raw_get_default", header: "bearssl_ec.h".}

const
  EC_KBUF_PRIV_MAX_SIZE* = 72


const
  EC_KBUF_PUB_MAX_SIZE* = 145


proc ecKeygen*(rngCtx: ptr ptr PrngClass; impl: ptr EcImpl; sk: ptr EcPrivateKey;
              kbuf: pointer; curve: cint): uint {.importcFunc, importc: "br_ec_keygen",
    header: "bearssl_ec.h".}

proc ecComputePub*(impl: ptr EcImpl; pk: ptr EcPublicKey; kbuf: pointer;
                  sk: ptr EcPrivateKey): uint {.importcFunc,
    importc: "br_ec_compute_pub", header: "bearssl_ec.h".}
