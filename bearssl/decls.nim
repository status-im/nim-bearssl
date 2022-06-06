## Nim-BearSSL
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.
## This module implements interface with BearSSL library sources.

from os import quoteShell, DirSep, AltSep

import
  ./abi/[
    aead, blockx, brssl, csources, ec, hash, hmac, intx, kdf, pem, prf, rand,
    rsa, ssl, x509]

export
  aead, blockx, brssl, csources, ec, hash, hmac, intx, kdf, pem, prf, rand,
  rsa, ssl, x509

const
  bearRootPath = bearSrcPath & "/"

{.compile: bearRootPath & "settings.c".}

# This modules must be reimplemented using Nim, because it can be changed
# freely.

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}

const
  TLS_NULL_WITH_NULL_NULL* = 0x00000000
  TLS_RSA_WITH_NULL_MD5* = 0x00000001
  TLS_RSA_WITH_NULL_SHA* = 0x00000002
  TLS_RSA_WITH_NULL_SHA256* = 0x0000003B
  TLS_RSA_WITH_RC4_128_MD5* = 0x00000004
  TLS_RSA_WITH_RC4_128_SHA* = 0x00000005
  TLS_RSA_WITH_3DES_EDE_CBC_SHA* = 0x0000000A
  TLS_RSA_WITH_AES_128_CBC_SHA* = 0x0000002F
  TLS_RSA_WITH_AES_256_CBC_SHA* = 0x00000035
  TLS_RSA_WITH_AES_128_CBC_SHA256* = 0x0000003C
  TLS_RSA_WITH_AES_256_CBC_SHA256* = 0x0000003D
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA* = 0x0000000D
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA* = 0x00000010
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA* = 0x00000013
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA* = 0x00000016
  TLS_DH_DSS_WITH_AES_128_CBC_SHA* = 0x00000030
  TLS_DH_RSA_WITH_AES_128_CBC_SHA* = 0x00000031
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA* = 0x00000032
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA* = 0x00000033
  TLS_DH_DSS_WITH_AES_256_CBC_SHA* = 0x00000036
  TLS_DH_RSA_WITH_AES_256_CBC_SHA* = 0x00000037
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA* = 0x00000038
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA* = 0x00000039
  TLS_DH_DSS_WITH_AES_128_CBC_SHA256* = 0x0000003E
  TLS_DH_RSA_WITH_AES_128_CBC_SHA256* = 0x0000003F
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256* = 0x00000040
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256* = 0x00000067
  TLS_DH_DSS_WITH_AES_256_CBC_SHA256* = 0x00000068
  TLS_DH_RSA_WITH_AES_256_CBC_SHA256* = 0x00000069
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256* = 0x0000006A
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256* = 0x0000006B
  TLS_DH_anonWITH_RC4128MD5* = 0x00000018
  TLS_DH_anonWITH_3DES_EDE_CBC_SHA* = 0x0000001B
  TLS_DH_anonWITH_AES_128CBC_SHA* = 0x00000034
  TLS_DH_anonWITH_AES_256CBC_SHA* = 0x0000003A
  TLS_DH_anonWITH_AES_128CBC_SHA256* = 0x0000006C
  TLS_DH_anonWITH_AES_256CBC_SHA256* = 0x0000006D

const
  TLS_ECDH_ECDSA_WITH_NULL_SHA* = 0x0000C001
  TLS_ECDH_ECDSA_WITH_RC4_128_SHA* = 0x0000C002
  TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA* = 0x0000C003
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA* = 0x0000C004
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA* = 0x0000C005
  TLS_ECDHE_ECDSA_WITH_NULL_SHA* = 0x0000C006
  TLS_ECDHE_ECDSA_WITH_RC4_128_SHA* = 0x0000C007
  TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA* = 0x0000C008
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA* = 0x0000C009
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA* = 0x0000C00A
  TLS_ECDH_RSA_WITH_NULL_SHA* = 0x0000C00B
  TLS_ECDH_RSA_WITH_RC4_128_SHA* = 0x0000C00C
  TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA* = 0x0000C00D
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA* = 0x0000C00E
  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA* = 0x0000C00F
  TLS_ECDHE_RSA_WITH_NULL_SHA* = 0x0000C010
  TLS_ECDHE_RSA_WITH_RC4_128_SHA* = 0x0000C011
  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA* = 0x0000C012
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA* = 0x0000C013
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA* = 0x0000C014
  TLS_ECDH_anonWITH_NULL_SHA* = 0x0000C015
  TLS_ECDH_anonWITH_RC4128SHA* = 0x0000C016
  TLS_ECDH_anonWITH_3DES_EDE_CBC_SHA* = 0x0000C017
  TLS_ECDH_anonWITH_AES_128CBC_SHA* = 0x0000C018
  TLS_ECDH_anonWITH_AES_256CBC_SHA* = 0x0000C019

const
  TLS_RSA_WITH_AES_128_GCM_SHA256* = 0x0000009C
  TLS_RSA_WITH_AES_256_GCM_SHA384* = 0x0000009D
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256* = 0x0000009E
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384* = 0x0000009F
  TLS_DH_RSA_WITH_AES_128_GCM_SHA256* = 0x000000A0
  TLS_DH_RSA_WITH_AES_256_GCM_SHA384* = 0x000000A1
  TLS_DHE_DSS_WITH_AES_128_GCM_SHA256* = 0x000000A2
  TLS_DHE_DSS_WITH_AES_256_GCM_SHA384* = 0x000000A3
  TLS_DH_DSS_WITH_AES_128_GCM_SHA256* = 0x000000A4
  TLS_DH_DSS_WITH_AES_256_GCM_SHA384* = 0x000000A5
  TLS_DH_anonWITH_AES_128GCM_SHA256* = 0x000000A6
  TLS_DH_anonWITH_AES_256GCM_SHA384* = 0x000000A7

const
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256* = 0x0000C023
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384* = 0x0000C024
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256* = 0x0000C025
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384* = 0x0000C026
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256* = 0x0000C027
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384* = 0x0000C028
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256* = 0x0000C029
  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384* = 0x0000C02A
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256* = 0x0000C02B
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384* = 0x0000C02C
  TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256* = 0x0000C02D
  TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384* = 0x0000C02E
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256* = 0x0000C02F
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384* = 0x0000C030
  TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256* = 0x0000C031
  TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384* = 0x0000C032

const
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCA8
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCA9
  TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAA
  TLS_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAB
  TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAC
  TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAD
  TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0x0000CCAE

const
  TLS_FALLBACK_SCSV* = 0x00005600

const
  ALERT_CLOSE_NOTIFY* = 0
  ALERT_UNEXPECTED_MESSAGE* = 10
  ALERT_BAD_RECORD_MAC* = 20
  ALERT_RECORD_OVERFLOW* = 22
  ALERT_DECOMPRESSION_FAILURE* = 30
  ALERT_HANDSHAKE_FAILURE* = 40
  ALERT_BAD_CERTIFICATE* = 42
  ALERT_UNSUPPORTED_CERTIFICATE* = 43
  ALERT_CERTIFICATE_REVOKED* = 44
  ALERT_CERTIFICATE_EXPIRED* = 45
  ALERT_CERTIFICATE_UNKNOWN* = 46
  ALERT_ILLEGAL_PARAMETER* = 47
  ALERT_UNKNOWN_CA* = 48
  ALERT_ACCESS_DENIED* = 49
  ALERT_DECODE_ERROR* = 50
  ALERT_DECRYPT_ERROR* = 51
  ALERT_PROTOCOL_VERSION* = 70
  ALERT_INSUFFICIENT_SECURITY* = 71
  ALERT_INTERNAL_ERROR* = 80
  ALERT_USER_CANCELED* = 90
  ALERT_NO_RENEGOTIATION* = 100
  ALERT_UNSUPPORTED_EXTENSION* = 110
  ALERT_NO_APPLICATION_PROTOCOL* = 120

type
  ConfigOption* {.importc: "br_config_option", header: "bearssl.h", bycopy.} = object
    name* {.importc: "name".}: cstring
    value* {.importc: "value".}: clong


proc getConfig*(): ptr ConfigOption {.importcFunc, importc: "br_get_config",
  header: "bearssl.h".}

const
  BR_EC_SECP256R1* {.deprecated.} = 23
  BR_EC_SECP384R1* {.deprecated.} = 24
  BR_EC_SECP521R1* {.deprecated.} = 25

  BR_EC_KBUF_PRIV_MAX_SIZE* {.deprecated.} = 72
  BR_EC_KBUF_PUB_MAX_SIZE* {.deprecated.} = 145

# Following declarations are used inside `nim-libp2p`.

type
  BrHashClass* {.deprecated.} = HashClass
  BrMd5Context* {.deprecated.} = Md5Context
  BrMd5sha1Context* {.deprecated.} = Md5sha1Context
  BrSha512Context* {.deprecated.} = Sha384Context
  BrSha384Context* {.deprecated.} = Sha384Context
  BrSha256Context* {.deprecated.} = Sha224Context
  BrSha224Context* {.deprecated.} = Sha224Context
  BrHashCompatContext* {.deprecated.} = HashCompatContext
  BrPrngClass* {.deprecated.} = PrngClass
  BrHmacDrbgContext* {.deprecated.} = HmacDrbgContext
  BrRsaPublicKey* {.deprecated.} = RsaPublicKey
  BrRsaPrivateKey* {.deprecated.} = RsaPrivateKey
  BrEcPublicKey* {.deprecated.} = EcPublicKey
  BrEcPrivateKey* {.deprecated.} = EcPrivateKey
  BrEcImplementation* {.deprecated.} = EcImpl
  BrPrngSeeder* {.deprecated.} = PrngSeeder
  BrRsaKeygen* {.deprecated.} = proc (ctx: ptr ptr BrPrngClass,
                       sk: ptr BrRsaPrivateKey, bufsec: ptr byte,
                       pk: ptr BrRsaPublicKey, bufpub: ptr byte,
                       size: cuint, pubexp: uint32): uint32 {.importcFunc.}
  BrRsaComputeModulus* {.deprecated.} = proc (n: pointer,
                               sk: ptr BrRsaPrivateKey): int {.importcFunc.}
  BrRsaComputePubexp* {.deprecated.} = proc (sk: ptr BrRsaPrivateKey): uint32 {.importcFunc.}
  BrRsaComputePrivexp* {.deprecated.} = proc (d: pointer,
                               sk: ptr BrRsaPrivateKey,
                               pubexp: uint32): int {.importcFunc.}
  BrRsaPkcs1Verify* {.deprecated.} = proc (x: ptr cuchar, xlen: int,
                            hash_oid: ptr cuchar, hash_len: int,
                            pk: ptr BrRsaPublicKey,
                            hash_out: ptr cuchar): uint32 {.importcFunc.}
  BrPemDecoderProc* {.deprecated.} = proc (destctx: pointer, src: pointer,
                            length: int) {.importcFunc.}
  BrRsaPkcs1Sign* {.deprecated.} = RsaPkcs1Sign

proc brPrngSeederSystem*(name: cstringArray): BrPrngSeeder {.importcFunc,
     importc: "br_prng_seeder_system", header: "bearssl_rand.h", deprecated.}

proc brHmacDrbgInit*(ctx: ptr BrHmacDrbgContext, digestClass: ptr BrHashClass,
                     seed: pointer, seedLen: int) {.
     importcFunc, importc: "br_hmac_drbg_init", header: "bearssl_rand.h", deprecated.}

proc brHmacDrbgGenerate*(ctx: ptr BrHmacDrbgContext, outs: pointer, len: csize_t) {.
     importcFunc, importc: "br_hmac_drbg_generate", header: "bearssl_rand.h", deprecated.}

proc brHmacDrbgGenerate*(ctx: var BrHmacDrbgContext, outp: var openArray[byte]) {.deprecated.} =
  brHmacDrbgGenerate(addr ctx, addr outp, csize_t(outp.len))

proc brRsaKeygenGetDefault*(): BrRsaKeygen {.
     importcFunc, importc: "br_rsa_keygen_get_default", header: "bearssl_rsa.h", deprecated.}

proc BrRsaPkcs1SignGetDefault*(): BrRsaPkcs1Sign {.
     importcFunc, importc: "br_rsa_pkcs1_sign_get_default", header: "bearssl_rsa.h", deprecated.}

proc BrRsaPkcs1VrfyGetDefault*(): BrRsaPkcs1Verify {.
     importcFunc, importc: "br_rsa_pkcs1_vrfy_get_default", header: "bearssl_rsa.h", deprecated.}

proc brRsaComputeModulusGetDefault*(): BrRsaComputeModulus {.
     importcFunc, importc: "br_rsa_compute_modulus_get_default",
     header: "bearssl_rsa.h", deprecated.}

proc brRsaComputePubexpGetDefault*(): BrRsaComputePubexp {.
     importcFunc, importc: "br_rsa_compute_pubexp_get_default",
     header: "bearssl_rsa.h", deprecated.}

proc brRsaComputePrivexpGetDefault*(): BrRsaComputePrivexp {.
     importcFunc, importc: "br_rsa_compute_privexp_get_default",
     header: "bearssl_rsa.h", deprecated.}

proc brEcGetDefault*(): ptr BrEcImplementation {.
     importcFunc, importc: "br_ec_get_default", header: "bearssl_ec.h", deprecated.}

proc brEcKeygen*(ctx: ptr ptr BrPrngClass, impl: ptr BrEcImplementation,
                 sk: ptr BrEcPrivateKey, keybuf: ptr byte,
                 curve: cint): int {.importcFunc,
     importc: "br_ec_keygen", header: "bearssl_ec.h", deprecated.}

proc brEcComputePublicKey*(impl: ptr BrEcImplementation, pk: ptr BrEcPublicKey,
                           kbuf: ptr byte, sk: ptr BrEcPrivateKey): int {.
     importcFunc, importc: "br_ec_compute_pub", header: "bearssl_ec.h", deprecated.}

proc brEcdsaSignRaw*(impl: ptr BrEcImplementation, hf: ptr BrHashClass,
                     value: pointer, sk: ptr BrEcPrivateKey,
                     sig: pointer): int {.
     importcFunc, importc: "br_ecdsa_i31_sign_raw", header: "bearssl_ec.h", deprecated.}

proc brEcdsaVerifyRaw*(impl: ptr BrEcImplementation, hash: pointer,
                       hashlen: int, pk: ptr BrEcPublicKey, sig: pointer,
                       siglen: int): uint32 {.
     importcFunc, importc: "br_ecdsa_i31_vrfy_raw", header: "bearssl_ec.h", deprecated.}

proc brEcdsaSignAsn1*(impl: ptr BrEcImplementation, hf: ptr BrHashClass,
                     value: pointer, sk: ptr BrEcPrivateKey,
                     sig: pointer): int {.
     importcFunc, importc: "br_ecdsa_i31_sign_asn1", header: "bearssl_ec.h", deprecated.}

proc brEcdsaVerifyAsn1*(impl: ptr BrEcImplementation, hash: pointer,
                        hashlen: int, pk: ptr BrEcPublicKey, sig: pointer,
                        siglen: int): uint32 {.
     importcFunc, importc: "br_ecdsa_i31_vrfy_asn1", header: "bearssl_ec.h", deprecated.}

template brRsaPrivateKeyBufferSize*(size: int): int {.deprecated.} =
  # BR_RSA_KBUF_PRIV_SIZE(size)
  (5 * ((size + 15) shr 4))

template brRsaPublicKeyBufferSize*(size: int): int {.deprecated.} =
  # BR_RSA_KBUF_PUB_SIZE(size)
  (4 + ((size + 7) shr 3))
