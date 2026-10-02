import ./[bearssl_hash, bearssl_rand, consttypes, csources, intx]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

# TODO Compile only the relevant backends for each platform
{.compile: currentSourceDir() & "/bearssl_rsa.c".} # includes i62
{.compile: currentSourceDir() & "/bearssl_rsa_i15.c".}
{.compile: currentSourceDir() & "/bearssl_rsa_i31.c".}
{.compile: currentSourceDir() & "/bearssl_rsa_i32.c".}

type
  ConstPtrRsaPrivateKey* {.importc: "const br_rsa_private_key *", header: "bearssl_rsa.h", bycopy.} = pointer
  ConstPtrRsaPublicKey* {.importc: "const br_rsa_public_key *", header: "bearssl_rsa.h", bycopy.} = pointer

type
  RsaPublicKey* {.importc: "br_rsa_public_key", header: "bearssl_rsa.h", bycopy.} = object
    n* {.importc: "n".}: ptr byte
    nlen* {.importc: "nlen".}: csize_t
    e* {.importc: "e".}: ptr byte
    elen* {.importc: "elen".}: csize_t



type
  RsaPrivateKey* {.importc: "br_rsa_private_key", header: "bearssl_rsa.h", bycopy.} = object
    nBitlen* {.importc: "n_bitlen".}: uint32
    p* {.importc: "p".}: ptr byte
    plen* {.importc: "plen".}: csize_t
    q* {.importc: "q".}: ptr byte
    qlen* {.importc: "qlen".}: csize_t
    dp* {.importc: "dp".}: ptr byte
    dplen* {.importc: "dplen".}: csize_t
    dq* {.importc: "dq".}: ptr byte
    dqlen* {.importc: "dqlen".}: csize_t
    iq* {.importc: "iq".}: ptr byte
    iqlen* {.importc: "iqlen".}: csize_t



type
  RsaPublic* {.importc: "br_rsa_public".} = proc (x: ptr byte; xlen: csize_t; pk: ConstPtrRsaPublicKey): uint32 {.importcFunc.}


type
  RsaPkcs1Vrfy* {.importc: "br_rsa_pkcs1_vrfy".} = proc (x: ConstPtrByte; xlen: csize_t; hashOid: ConstPtrByte;
                     hashlen: csize_t; pk: ConstPtrRsaPublicKey; hashOut: ptr byte): uint32 {.
      importcFunc.}


type
  RsaPssVrfy* {.importc: "br_rsa_pss_vrfy".} = proc (x: ConstPtrByte; xlen: csize_t; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hash: ConstPointer; saltlen: csize_t;
                   pk: ConstPtrRsaPublicKey): uint32 {.importcFunc.}


type
  RsaOaepEncrypt* {.importc: "br_rsa_oaep_encrypt".} = proc (rnd: PrngClassPointerConst; dig: ConstPtrHashClass; label: ConstPointer;
                       labellen: csize_t; pk: ConstPtrRsaPublicKey; dst: pointer;
                       dstMaxlen: csize_t; src: ConstPointer; srclen: csize_t): csize_t {.
      importcFunc.}


type
  RsaPrivate* {.importc: "br_rsa_private".} = proc (x: ptr byte; sk: ConstPtrRsaPrivateKey): uint32 {.importcFunc.}


type
  RsaPkcs1Sign* {.importc: "br_rsa_pkcs1_sign".} = proc (hashOid: ConstPtrByte; hash: ConstPtrByte; hashlen: csize_t;
                     sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc.}


type
  RsaPssSign* {.importc: "br_rsa_pss_sign".} = proc (rng: PrngClassPointerConst; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hashValue: ConstPtrByte; saltlen: csize_t;
                   sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc.}


const
  HASH_OID_SHA1* = (("\x05+\x0E\x03\x02\x1A"))


const
  HASH_OID_SHA224* = (("\t`\x86H\x01e\x03\x04\x02\x04"))


const
  HASH_OID_SHA256* = (("\t`\x86H\x01e\x03\x04\x02\x01"))


const
  HASH_OID_SHA384* = (("\t`\x86H\x01e\x03\x04\x02\x02"))


const
  HASH_OID_SHA512* = (("\t`\x86H\x01e\x03\x04\x02\x03"))


type
  RsaOaepDecrypt* {.importc: "br_rsa_oaep_decrypt".} = proc (dig: ConstPtrHashClass; label: ConstPointer; labellen: csize_t;
                       sk: ConstPtrRsaPrivateKey; data: pointer; len: var csize_t): uint32 {.
      importcFunc.}


proc rsaI32Public*(x: ptr byte; xlen: csize_t; pk: ConstPtrRsaPublicKey): uint32 {.
    importcFunc, importc: "br_rsa_i32_public", header: "bearssl_rsa.h".}

proc rsaI32Pkcs1Vrfy*(x: ConstPtrByte; xlen: csize_t; hashOid: ConstPtrByte;
                     hashlen: csize_t; pk: ConstPtrRsaPublicKey; hashOut: ptr byte): uint32 {.
    importcFunc, importc: "br_rsa_i32_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI32PssVrfy*(x: ConstPtrByte; xlen: csize_t; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hash: ConstPointer; saltlen: csize_t;
                   pk: ConstPtrRsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i32_pss_vrfy", header: "bearssl_rsa.h".}

proc rsaI32Private*(x: ptr byte; sk: ConstPtrRsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i32_private", header: "bearssl_rsa.h".}

proc rsaI32Pkcs1Sign*(hashOid: ConstPtrByte; hash: ConstPtrByte; hashlen: csize_t;
                     sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc,
    importc: "br_rsa_i32_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI32PssSign*(rng: PrngClassPointerConst; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hashValue: ConstPtrByte; saltlen: csize_t;
                   sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc,
    importc: "br_rsa_i32_pss_sign", header: "bearssl_rsa.h".}

proc rsaI31Public*(x: ptr byte; xlen: csize_t; pk: ConstPtrRsaPublicKey): uint32 {.
    importcFunc, importc: "br_rsa_i31_public", header: "bearssl_rsa.h".}

proc rsaI31Pkcs1Vrfy*(x: ConstPtrByte; xlen: csize_t; hashOid: ConstPtrByte;
                     hashlen: csize_t; pk: ConstPtrRsaPublicKey; hashOut: ptr byte): uint32 {.
    importcFunc, importc: "br_rsa_i31_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI31PssVrfy*(x: ConstPtrByte; xlen: csize_t; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hash: ConstPointer; saltlen: csize_t;
                   pk: ConstPtrRsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i31_pss_vrfy", header: "bearssl_rsa.h".}

proc rsaI31Private*(x: ptr byte; sk: ConstPtrRsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i31_private", header: "bearssl_rsa.h".}

proc rsaI31Pkcs1Sign*(hashOid: ConstPtrByte; hash: ConstPtrByte; hashlen: csize_t;
                     sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc,
    importc: "br_rsa_i31_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI31PssSign*(rng: PrngClassPointerConst; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hashValue: ConstPtrByte; saltlen: csize_t;
                   sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc,
    importc: "br_rsa_i31_pss_sign", header: "bearssl_rsa.h".}

proc rsaI62Public*(x: ptr byte; xlen: csize_t; pk: ConstPtrRsaPublicKey): uint32 {.
    importcFunc, importc: "br_rsa_i62_public", header: "bearssl_rsa.h".}

proc rsaI62Pkcs1Vrfy*(x: ConstPtrByte; xlen: csize_t; hashOid: ConstPtrByte;
                     hashlen: csize_t; pk: ConstPtrRsaPublicKey; hashOut: ptr byte): uint32 {.
    importcFunc, importc: "br_rsa_i62_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI62PssVrfy*(x: ConstPtrByte; xlen: csize_t; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hash: ConstPointer; saltlen: csize_t;
                   pk: ConstPtrRsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i62_pss_vrfy", header: "bearssl_rsa.h".}

proc rsaI62Private*(x: ptr byte; sk: ConstPtrRsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i62_private", header: "bearssl_rsa.h".}

proc rsaI62Pkcs1Sign*(hashOid: ConstPtrByte; hash: ConstPtrByte; hashlen: csize_t;
                     sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc,
    importc: "br_rsa_i62_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI62PssSign*(rng: PrngClassPointerConst; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hashValue: ConstPtrByte; saltlen: csize_t;
                   sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc,
    importc: "br_rsa_i62_pss_sign", header: "bearssl_rsa.h".}

proc rsaI62PublicGet*(): RsaPublic {.importcFunc, importc: "br_rsa_i62_public_get",
                                  header: "bearssl_rsa.h".}

proc rsaI62Pkcs1VrfyGet*(): RsaPkcs1Vrfy {.importcFunc,
                                        importc: "br_rsa_i62_pkcs1_vrfy_get",
                                        header: "bearssl_rsa.h".}

proc rsaI62PssVrfyGet*(): RsaPssVrfy {.importcFunc, importc: "br_rsa_i62_pss_vrfy_get",
                                    header: "bearssl_rsa.h".}

proc rsaI62PrivateGet*(): RsaPrivate {.importcFunc, importc: "br_rsa_i62_private_get",
                                    header: "bearssl_rsa.h".}

proc rsaI62Pkcs1SignGet*(): RsaPkcs1Sign {.importcFunc,
                                        importc: "br_rsa_i62_pkcs1_sign_get",
                                        header: "bearssl_rsa.h".}

proc rsaI62PssSignGet*(): RsaPssSign {.importcFunc, importc: "br_rsa_i62_pss_sign_get",
                                    header: "bearssl_rsa.h".}

proc rsaI62OaepEncryptGet*(): RsaOaepEncrypt {.importcFunc,
    importc: "br_rsa_i62_oaep_encrypt_get", header: "bearssl_rsa.h".}

proc rsaI62OaepDecryptGet*(): RsaOaepDecrypt {.importcFunc,
    importc: "br_rsa_i62_oaep_decrypt_get", header: "bearssl_rsa.h".}

proc rsaI15Public*(x: ptr byte; xlen: csize_t; pk: ConstPtrRsaPublicKey): uint32 {.
    importcFunc, importc: "br_rsa_i15_public", header: "bearssl_rsa.h".}

proc rsaI15Pkcs1Vrfy*(x: ConstPtrByte; xlen: csize_t; hashOid: ConstPtrByte;
                     hashlen: csize_t; pk: ConstPtrRsaPublicKey; hashOut: ptr byte): uint32 {.
    importcFunc, importc: "br_rsa_i15_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI15PssVrfy*(x: ConstPtrByte; xlen: csize_t; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hash: ConstPointer; saltlen: csize_t;
                   pk: ConstPtrRsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i15_pss_vrfy", header: "bearssl_rsa.h".}

proc rsaI15Private*(x: ptr byte; sk: ConstPtrRsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i15_private", header: "bearssl_rsa.h".}

proc rsaI15Pkcs1Sign*(hashOid: ConstPtrByte; hash: ConstPtrByte; hashlen: csize_t;
                     sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc,
    importc: "br_rsa_i15_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI15PssSign*(rng: PrngClassPointerConst; hfData: ConstPtrHashClass;
                   hfMgf1: ConstPtrHashClass; hashValue: ConstPtrByte; saltlen: csize_t;
                   sk: ConstPtrRsaPrivateKey; x: ptr byte): uint32 {.importcFunc,
    importc: "br_rsa_i15_pss_sign", header: "bearssl_rsa.h".}

proc rsaPublicGetDefault*(): RsaPublic {.importcFunc,
                                      importc: "br_rsa_public_get_default",
                                      header: "bearssl_rsa.h".}

proc rsaPrivateGetDefault*(): RsaPrivate {.importcFunc,
                                        importc: "br_rsa_private_get_default",
                                        header: "bearssl_rsa.h".}

proc rsaPkcs1VrfyGetDefault*(): RsaPkcs1Vrfy {.importcFunc,
    importc: "br_rsa_pkcs1_vrfy_get_default", header: "bearssl_rsa.h".}

proc rsaPssVrfyGetDefault*(): RsaPssVrfy {.importcFunc,
                                        importc: "br_rsa_pss_vrfy_get_default",
                                        header: "bearssl_rsa.h".}

proc rsaPkcs1SignGetDefault*(): RsaPkcs1Sign {.importcFunc,
    importc: "br_rsa_pkcs1_sign_get_default", header: "bearssl_rsa.h".}

proc rsaPssSignGetDefault*(): RsaPssSign {.importcFunc,
                                        importc: "br_rsa_pss_sign_get_default",
                                        header: "bearssl_rsa.h".}

proc rsaOaepEncryptGetDefault*(): RsaOaepEncrypt {.importcFunc,
    importc: "br_rsa_oaep_encrypt_get_default", header: "bearssl_rsa.h".}

proc rsaOaepDecryptGetDefault*(): RsaOaepDecrypt {.importcFunc,
    importc: "br_rsa_oaep_decrypt_get_default", header: "bearssl_rsa.h".}

proc rsaSslDecrypt*(core: RsaPrivate; sk: ptr RsaPrivateKey; data: ptr byte;
                   len: csize_t): uint32 {.importcFunc, importc: "br_rsa_ssl_decrypt",
    header: "bearssl_rsa.h".}

proc rsaI15OaepEncrypt*(rnd: PrngClassPointerConst; dig: ConstPtrHashClass; label: ConstPointer;
                       labellen: csize_t; pk: ConstPtrRsaPublicKey; dst: pointer;
                       dstMaxlen: csize_t; src: ConstPointer; srclen: csize_t): csize_t {.
    importcFunc, importc: "br_rsa_i15_oaep_encrypt", header: "bearssl_rsa.h".}

proc rsaI15OaepDecrypt*(dig: ConstPtrHashClass; label: ConstPointer; labellen: csize_t;
                       sk: ConstPtrRsaPrivateKey; data: pointer; len: var csize_t): uint32 {.
    importcFunc, importc: "br_rsa_i15_oaep_decrypt", header: "bearssl_rsa.h".}

proc rsaI31OaepEncrypt*(rnd: PrngClassPointerConst; dig: ConstPtrHashClass; label: ConstPointer;
                       labellen: csize_t; pk: ConstPtrRsaPublicKey; dst: pointer;
                       dstMaxlen: csize_t; src: ConstPointer; srclen: csize_t): csize_t {.
    importcFunc, importc: "br_rsa_i31_oaep_encrypt", header: "bearssl_rsa.h".}

proc rsaI31OaepDecrypt*(dig: ConstPtrHashClass; label: ConstPointer; labellen: csize_t;
                       sk: ConstPtrRsaPrivateKey; data: pointer; len: var csize_t): uint32 {.
    importcFunc, importc: "br_rsa_i31_oaep_decrypt", header: "bearssl_rsa.h".}

proc rsaI32OaepEncrypt*(rnd: PrngClassPointerConst; dig: ConstPtrHashClass; label: ConstPointer;
                       labellen: csize_t; pk: ConstPtrRsaPublicKey; dst: pointer;
                       dstMaxlen: csize_t; src: ConstPointer; srclen: csize_t): csize_t {.
    importcFunc, importc: "br_rsa_i32_oaep_encrypt", header: "bearssl_rsa.h".}

proc rsaI32OaepDecrypt*(dig: ConstPtrHashClass; label: ConstPointer; labellen: csize_t;
                       sk: ConstPtrRsaPrivateKey; data: pointer; len: var csize_t): uint32 {.
    importcFunc, importc: "br_rsa_i32_oaep_decrypt", header: "bearssl_rsa.h".}

proc rsaI62OaepEncrypt*(rnd: PrngClassPointerConst; dig: ConstPtrHashClass; label: ConstPointer;
                       labellen: csize_t; pk: ConstPtrRsaPublicKey; dst: pointer;
                       dstMaxlen: csize_t; src: ConstPointer; srclen: csize_t): csize_t {.
    importcFunc, importc: "br_rsa_i62_oaep_encrypt", header: "bearssl_rsa.h".}

proc rsaI62OaepDecrypt*(dig: ConstPtrHashClass; label: ConstPointer; labellen: csize_t;
                       sk: ConstPtrRsaPrivateKey; data: pointer; len: var csize_t): uint32 {.
    importcFunc, importc: "br_rsa_i62_oaep_decrypt", header: "bearssl_rsa.h".}

template rsaKbufPrivSize*(size: untyped): untyped =
  (5 * (((size) + 15) shr 4))


template rsaKbufPubSize*(size: untyped): untyped =
  (4 + (((size) + 7) shr 3))


type
  RsaKeygen* {.importc: "br_rsa_keygen".} = proc (rngCtx: PrngClassPointerConst; sk: ptr RsaPrivateKey; kbufPriv: pointer;
                  pk: ptr RsaPublicKey; kbufPub: pointer; size: cuint; pubexp: uint32): uint32 {.
      importcFunc.}


proc rsaI15Keygen*(rngCtx: PrngClassPointerConst; sk: ptr RsaPrivateKey;
                  kbufPriv: pointer; pk: ptr RsaPublicKey; kbufPub: pointer;
                  size: cuint; pubexp: uint32): uint32 {.importcFunc,
    importc: "br_rsa_i15_keygen", header: "bearssl_rsa.h".}

proc rsaI31Keygen*(rngCtx: PrngClassPointerConst; sk: ptr RsaPrivateKey;
                  kbufPriv: pointer; pk: ptr RsaPublicKey; kbufPub: pointer;
                  size: cuint; pubexp: uint32): uint32 {.importcFunc,
    importc: "br_rsa_i31_keygen", header: "bearssl_rsa.h".}

proc rsaI62Keygen*(rngCtx: PrngClassPointerConst; sk: ptr RsaPrivateKey;
                  kbufPriv: pointer; pk: ptr RsaPublicKey; kbufPub: pointer;
                  size: cuint; pubexp: uint32): uint32 {.importcFunc,
    importc: "br_rsa_i62_keygen", header: "bearssl_rsa.h".}

proc rsaI62KeygenGet*(): RsaKeygen {.importcFunc, importc: "br_rsa_i62_keygen_get",
                                  header: "bearssl_rsa.h".}

proc rsaKeygenGetDefault*(): RsaKeygen {.importcFunc,
                                      importc: "br_rsa_keygen_get_default",
                                      header: "bearssl_rsa.h".}

type
  RsaComputeModulus* {.importc: "br_rsa_compute_modulus".} = proc (n: pointer; sk: ConstPtrRsaPrivateKey): csize_t {.importcFunc.}


proc rsaI15ComputeModulus*(n: pointer; sk: ConstPtrRsaPrivateKey): csize_t {.importcFunc,
    importc: "br_rsa_i15_compute_modulus", header: "bearssl_rsa.h".}

proc rsaI31ComputeModulus*(n: pointer; sk: ConstPtrRsaPrivateKey): csize_t {.importcFunc,
    importc: "br_rsa_i31_compute_modulus", header: "bearssl_rsa.h".}

proc rsaComputeModulusGetDefault*(): RsaComputeModulus {.importcFunc,
    importc: "br_rsa_compute_modulus_get_default", header: "bearssl_rsa.h".}

type
  RsaComputePubexp* {.importc: "br_rsa_compute_pubexp".} = proc (sk: ConstPtrRsaPrivateKey): uint32 {.importcFunc.}


proc rsaI15ComputePubexp*(sk: ConstPtrRsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i15_compute_pubexp", header: "bearssl_rsa.h".}

proc rsaI31ComputePubexp*(sk: ConstPtrRsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i31_compute_pubexp", header: "bearssl_rsa.h".}

proc rsaComputePubexpGetDefault*(): RsaComputePubexp {.importcFunc,
    importc: "br_rsa_compute_pubexp_get_default", header: "bearssl_rsa.h".}

type
  RsaComputePrivexp* {.importc: "br_rsa_compute_privexp".} = proc (d: pointer; sk: ConstPtrRsaPrivateKey; pubexp: uint32): csize_t {.
      importcFunc.}


proc rsaI15ComputePrivexp*(d: pointer; sk: ConstPtrRsaPrivateKey; pubexp: uint32): csize_t {.
    importcFunc, importc: "br_rsa_i15_compute_privexp", header: "bearssl_rsa.h".}

proc rsaI31ComputePrivexp*(d: pointer; sk: ConstPtrRsaPrivateKey; pubexp: uint32): csize_t {.
    importcFunc, importc: "br_rsa_i31_compute_privexp", header: "bearssl_rsa.h".}

proc rsaComputePrivexpGetDefault*(): RsaComputePrivexp {.importcFunc,
    importc: "br_rsa_compute_privexp_get_default", header: "bearssl_rsa.h".}
