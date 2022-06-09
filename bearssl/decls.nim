## Nim-BearSSL
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.
##
## This module reexports the whole raw beassl C api, as found in the api/
## directory as well as some legacy helpers. It should not be used in new
## projects (either import `bearssl` or individual abi modules)

import
  ./abi/[
    aead, blockx, brssl, config, ec, hash, hmac, intx, kdf, pem, prf,
    rand, rsa, ssl, x509]

export
  aead, blockx, brssl, config, ec, hash, hmac, intx, kdf, pem, prf,
  rand, rsa, ssl, x509

# This modules must be reimplemented using Nim, because it can be changed
# freely.

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}

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
