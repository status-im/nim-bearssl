import
  "."/[csources, hash, rand]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_rsa.h".}
{.used.}

const
  bearRsaPath = bearSrcPath / "rsa"

{.compile: bearRsaPath / "rsa_default_keygen.c".}
{.compile: bearRsaPath / "rsa_default_modulus.c".}
{.compile: bearRsaPath / "rsa_default_oaep_decrypt.c".}
{.compile: bearRsaPath / "rsa_default_oaep_encrypt.c".}
{.compile: bearRsaPath / "rsa_default_pkcs1_sign.c".}
{.compile: bearRsaPath / "rsa_default_pkcs1_vrfy.c".}
{.compile: bearRsaPath / "rsa_default_priv.c".}
{.compile: bearRsaPath / "rsa_default_privexp.c".}
{.compile: bearRsaPath / "rsa_default_pss_sign.c".}
{.compile: bearRsaPath / "rsa_default_pss_vrfy.c".}
{.compile: bearRsaPath / "rsa_default_pub.c".}
{.compile: bearRsaPath / "rsa_default_pubexp.c".}
{.compile: bearRsaPath / "rsa_i15_keygen.c".}
{.compile: bearRsaPath / "rsa_i15_modulus.c".}
{.compile: bearRsaPath / "rsa_i15_oaep_decrypt.c".}
{.compile: bearRsaPath / "rsa_i15_oaep_encrypt.c".}
{.compile: bearRsaPath / "rsa_i15_pkcs1_sign.c".}
{.compile: bearRsaPath / "rsa_i15_pkcs1_vrfy.c".}
{.compile: bearRsaPath / "rsa_i15_priv.c".}
{.compile: bearRsaPath / "rsa_i15_privexp.c".}
{.compile: bearRsaPath / "rsa_i15_pss_sign.c".}
{.compile: bearRsaPath / "rsa_i15_pss_vrfy.c".}
{.compile: bearRsaPath / "rsa_i15_pub.c".}
{.compile: bearRsaPath / "rsa_i15_pubexp.c".}
{.compile: bearRsaPath / "rsa_i31_keygen.c".}
{.compile: bearRsaPath / "rsa_i31_keygen_inner.c".}
{.compile: bearRsaPath / "rsa_i31_modulus.c".}
{.compile: bearRsaPath / "rsa_i31_oaep_decrypt.c".}
{.compile: bearRsaPath / "rsa_i31_oaep_encrypt.c".}
{.compile: bearRsaPath / "rsa_i31_pkcs1_sign.c".}
{.compile: bearRsaPath / "rsa_i31_pkcs1_vrfy.c".}
{.compile: bearRsaPath / "rsa_i31_priv.c".}
{.compile: bearRsaPath / "rsa_i31_privexp.c".}
{.compile: bearRsaPath / "rsa_i31_pss_sign.c".}
{.compile: bearRsaPath / "rsa_i31_pss_vrfy.c".}
{.compile: bearRsaPath / "rsa_i31_pub.c".}
{.compile: bearRsaPath / "rsa_i31_pubexp.c".}
{.compile: bearRsaPath / "rsa_i32_oaep_decrypt.c".}
{.compile: bearRsaPath / "rsa_i32_oaep_encrypt.c".}
{.compile: bearRsaPath / "rsa_i32_pkcs1_sign.c".}
{.compile: bearRsaPath / "rsa_i32_pkcs1_vrfy.c".}
{.compile: bearRsaPath / "rsa_i32_priv.c".}
{.compile: bearRsaPath / "rsa_i32_pss_sign.c".}
{.compile: bearRsaPath / "rsa_i32_pss_vrfy.c".}
{.compile: bearRsaPath / "rsa_i32_pub.c".}
{.compile: bearRsaPath / "rsa_i62_keygen.c".}
{.compile: bearRsaPath / "rsa_i62_oaep_decrypt.c".}
{.compile: bearRsaPath / "rsa_i62_oaep_encrypt.c".}
{.compile: bearRsaPath / "rsa_i62_pkcs1_sign.c".}
{.compile: bearRsaPath / "rsa_i62_pkcs1_vrfy.c".}
{.compile: bearRsaPath / "rsa_i62_priv.c".}
{.compile: bearRsaPath / "rsa_i62_pss_sign.c".}
{.compile: bearRsaPath / "rsa_i62_pss_vrfy.c".}
{.compile: bearRsaPath / "rsa_i62_pub.c".}
{.compile: bearRsaPath / "rsa_oaep_pad.c".}
{.compile: bearRsaPath / "rsa_oaep_unpad.c".}
{.compile: bearRsaPath / "rsa_pkcs1_sig_pad.c".}
{.compile: bearRsaPath / "rsa_pkcs1_sig_unpad.c".}
{.compile: bearRsaPath / "rsa_pss_sig_pad.c".}
{.compile: bearRsaPath / "rsa_pss_sig_unpad.c".}
{.compile: bearRsaPath / "rsa_ssl_decrypt.c".}

type
  RsaPublicKey* {.importc: "br_rsa_public_key", header: "bearssl_rsa.h", bycopy.} = object
    n* {.importc: "n".}: ptr cuchar
    nlen* {.importc: "nlen".}: int
    e* {.importc: "e".}: ptr cuchar
    elen* {.importc: "elen".}: int


type
  RsaPrivateKey* {.importc: "br_rsa_private_key", header: "bearssl_rsa.h", bycopy.} = object
    nBitlen* {.importc: "n_bitlen".}: uint32
    p* {.importc: "p".}: ptr cuchar
    plen* {.importc: "plen".}: int
    q* {.importc: "q".}: ptr cuchar
    qlen* {.importc: "qlen".}: int
    dp* {.importc: "dp".}: ptr cuchar
    dplen* {.importc: "dplen".}: int
    dq* {.importc: "dq".}: ptr cuchar
    dqlen* {.importc: "dqlen".}: int
    iq* {.importc: "iq".}: ptr cuchar
    iqlen* {.importc: "iqlen".}: int


type
  RsaPublic* {.importc: "br_rsa_public".} = proc (x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.importcFunc.}

type
  RsaPkcs1Vrfy* {.importc: "br_rsa_pkcs1_vrfy".} = proc (x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.importcFunc.}

type
  RsaPrivate* {.importc: "br_rsa_private".} = proc (x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.importcFunc.}

type
  RsaPkcs1Sign* {.importc: "br_rsa_pkcs1_sign".} = proc (hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.importcFunc.}

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

proc rsaI32Public*(x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i32_public", header: "bearssl_rsa.h".}

proc rsaI32Pkcs1Vrfy*(x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i32_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI32Private*(x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i32_private", header: "bearssl_rsa.h".}

proc rsaI32Pkcs1Sign*(hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i32_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI31Public*(x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i31_public", header: "bearssl_rsa.h".}

proc rsaI31Pkcs1Vrfy*(x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i31_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI31Private*(x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i31_private", header: "bearssl_rsa.h".}

proc rsaI31Pkcs1Sign*(hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i31_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI62Public*(x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i62_public", header: "bearssl_rsa.h".}

proc rsaI62Pkcs1Vrfy*(x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i62_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI62Private*(x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i62_private", header: "bearssl_rsa.h".}

proc rsaI62Pkcs1Sign*(hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i62_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI62PublicGet*(): RsaPublic {.importcFunc, importc: "br_rsa_i62_public_get",
                                  header: "bearssl_rsa.h".}

proc rsaI62Pkcs1VrfyGet*(): RsaPkcs1Vrfy {.importcFunc,
                                        importc: "br_rsa_i62_pkcs1_vrfy_get",
                                        header: "bearssl_rsa.h".}

proc rsaI62PrivateGet*(): RsaPrivate {.importcFunc, importc: "br_rsa_i62_private_get",
                                    header: "bearssl_rsa.h".}

proc rsaI62Pkcs1SignGet*(): RsaPkcs1Sign {.importcFunc,
                                        importc: "br_rsa_i62_pkcs1_sign_get",
                                        header: "bearssl_rsa.h".}

proc rsaI15Public*(x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i15_public", header: "bearssl_rsa.h".}

proc rsaI15Pkcs1Vrfy*(x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i15_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI15Private*(x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.importcFunc,
    importc: "br_rsa_i15_private", header: "bearssl_rsa.h".}

proc rsaI15Pkcs1Sign*(hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i15_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaPublicGetDefault*(): RsaPublic {.importcFunc,
                                      importc: "br_rsa_public_get_default",
                                      header: "bearssl_rsa.h".}

proc rsaPrivateGetDefault*(): RsaPrivate {.importcFunc,
                                        importc: "br_rsa_private_get_default",
                                        header: "bearssl_rsa.h".}

proc rsaPkcs1VrfyGetDefault*(): RsaPkcs1Vrfy {.importcFunc,
    importc: "br_rsa_pkcs1_vrfy_get_default", header: "bearssl_rsa.h".}

proc rsaPkcs1SignGetDefault*(): RsaPkcs1Sign {.importcFunc,
    importc: "br_rsa_pkcs1_sign_get_default", header: "bearssl_rsa.h".}

proc rsaSslDecrypt*(core: RsaPrivate; sk: ptr RsaPrivateKey; data: ptr cuchar; len: int): uint32 {.
    importcFunc, importc: "br_rsa_ssl_decrypt", header: "bearssl_rsa.h".}

type
  RsaPssSign* {.importc: "br_rsa_pss_sign".} = proc(rng: ptr ptr PrngClass,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash_value: ptr cuchar, salt_len: int,
                   sk: ptr RsaPrivateKey, x: ptr cuchar): uint32 {.importcFunc.}

  RsaPssVrfy* {.importc: "br_rsa_pss_vrfy".} = proc(x: ptr cuchar, xlen: int,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash: ptr cuchar, salt_len: int,
                   pk: ptr RsaPublicKey): uint32 {.importcFunc.}

proc rsaPssSignGetDefault*(): RsaPssSign {.importcFunc,
    importc: "br_rsa_pss_sign_get_default", header: "bearssl_rsa.h".}

proc rsaPssVrfyGetDefault*(): RsaPssVrfy {.importcFunc,
    importc: "br_rsa_pss_vrfy_get_default", header: "bearssl_rsa.h".}

proc rsaI15PssSign*(rng: ptr ptr PrngClass,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash_value: ptr cuchar, salt_len: int,
                   sk: ptr RsaPrivateKey, x: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i15_pss_sign", header: "bearssl_rsa.h".}

proc rsaI15PssVrfy*(x: ptr cuchar, xlen: int,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash: ptr cuchar, salt_len: int,
                   pk: ptr RsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i15_pss_vrfy", header: "bearssl_rsa.h".}

proc rsaI31PssSign*(rng: ptr ptr PrngClass,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash_value: ptr cuchar, salt_len: int,
                   sk: ptr RsaPrivateKey, x: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i31_pss_sign", header: "bearssl_rsa.h".}

proc rsaI31PssVrfy*(x: ptr cuchar, xlen: int,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash: ptr cuchar, salt_len: int,
                   pk: ptr RsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i31_pss_vrfy", header: "bearssl_rsa.h".}

proc rsaI32PssSign*(rng: ptr ptr PrngClass,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash_value: ptr cuchar, salt_len: int,
                   sk: ptr RsaPrivateKey, x: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i32_pss_sign", header: "bearssl_rsa.h".}

proc rsaI32PssVrfy*(x: ptr cuchar, xlen: int,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash: ptr cuchar, salt_len: int,
                   pk: ptr RsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i32_pss_vrfy", header: "bearssl_rsa.h".}

proc rsaI62PssSign*(rng: ptr ptr PrngClass,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash_value: ptr cuchar, salt_len: int,
                   sk: ptr RsaPrivateKey, x: ptr cuchar): uint32 {.importcFunc,
    importc: "br_rsa_i62_pss_sign", header: "bearssl_rsa.h".}

proc rsaI62PssVrfy*(x: ptr cuchar, xlen: int,
                   hf_data, hf_mgf1: ptr HashClass,
                   hash: ptr cuchar, salt_len: int,
                   pk: ptr RsaPublicKey): uint32 {.importcFunc,
    importc: "br_rsa_i62_pss_vrfy", header: "bearssl_rsa.h".}
