## Nim-BearSSL
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.
## This module implements interface with BearSSL library sources.
import strutils
from os import quoteShell, DirSep, AltSep

const
  bearPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "/" &
             "csources" & "/"

  bearSrcPath = bearPath & "src"
  bearIncPath = bearPath & "inc"
  bearIntPath = bearSrcPath & "/" & "int" & "/"
  bearCodecPath = bearSrcPath & "/" & "codec" & "/"
  bearRandPath = bearSrcPath & "/" & "rand" & "/"
  bearRsaPath = bearSrcPath & "/" & "rsa" & "/"
  bearEcPath = bearSrcPath & "/" & "ec" & "/"
  bearX509Path = bearSrcPath & "/" & "x509" & "/"
  bearSslPath = bearSrcPath & "/" & "ssl" & "/"
  bearMacPath = bearSrcPath & "/" & "mac" & "/"
  bearKdfPath = bearSrcPath & "/" & "kdf" & "/"
  bearHashPath = bearSrcPath & "/" & "hash" & "/"
  bearSymcPath = bearSrcPath & "/" & "symcipher" & "/"
  bearAeadPath = bearSrcPath & "/" & "aead" & "/"
  bearToolsPath = bearPath & "tools" & "/"
  bearRootPath = bearSrcPath & "/"

{.passc: "-I" & quoteShell(bearSrcPath)}
{.passc: "-I" & quoteShell(bearIncPath)}
{.passc: "-I" & quoteShell(bearPath & "tools")}

when defined(windows):
  {.passc: "-DBR_USE_WIN32_TIME=1".}
  {.passc: "-DBR_USE_WIN32_RAND=1".}
else:
  {.passc: "-DBR_USE_UNIX_TIME=1".}
  {.passc: "-DBR_USE_URANDOM=1".}

when defined(i386) or defined(amd64) or defined(arm64):
  {.passc: "-DBR_LE_UNALIGNED=1".}
elif defined(powerpc) or defined(powerpc64):
  {.passc: "-DBR_BE_UNALIGNED=1".}
elif defined(powerpc64el):
  {.passc: "-DBR_LE_UNALIGNED=1".}

when sizeof(int) == 8:
  {.passc: "-DBR_64=1".}
  when hostCPU == "amd64":
    {.passc:" -DBR_amd64=1".}
  when defined(vcc):
    {.passc: "-DBR_UMUL128=1".}
  else:
    {.passc: "-DBR_INT128=1".}

{.compile: bearCodecPath & "ccopy.c".}
{.compile: bearCodecPath & "dec16be.c".}
{.compile: bearCodecPath & "dec16le.c".}
{.compile: bearCodecPath & "dec32be.c".}
{.compile: bearCodecPath & "dec32le.c".}
{.compile: bearCodecPath & "dec64be.c".}
{.compile: bearCodecPath & "dec64le.c".}
{.compile: bearCodecPath & "enc16be.c".}
{.compile: bearCodecPath & "enc16le.c".}
{.compile: bearCodecPath & "enc32be.c".}
{.compile: bearCodecPath & "enc32le.c".}
{.compile: bearCodecPath & "enc64be.c".}
{.compile: bearCodecPath & "enc64le.c".}
{.compile: bearCodecPath & "pemdec.c".}
{.compile: bearCodecPath & "pemenc.c".}

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

{.compile: bearHashPath & "dig_oid.c".}
{.compile: bearHashPath & "dig_size.c".}
{.compile: bearHashPath & "ghash_ctmul.c".}
{.compile: bearHashPath & "ghash_ctmul32.c".}
{.compile: bearHashPath & "ghash_ctmul64.c".}
{.compile: bearHashPath & "ghash_pclmul.c".}
{.compile: bearHashPath & "ghash_pwr8.c".}
{.compile: bearHashPath & "md5.c".}
{.compile: bearHashPath & "md5sha1.c".}
{.compile: bearHashPath & "mgf1.c".}
{.compile: bearHashPath & "multihash.c".}
{.compile: bearHashPath & "sha1.c".}
{.compile: bearHashPath & "sha2big.c".}
{.compile: bearHashPath & "sha2small.c".}

{.compile: bearIntPath & "i15_add.c".}
{.compile: bearIntPath & "i15_bitlen.c".}
{.compile: bearIntPath & "i15_decmod.c".}
{.compile: bearIntPath & "i15_decode.c".}
{.compile: bearIntPath & "i15_decred.c".}
{.compile: bearIntPath & "i15_encode.c".}
{.compile: bearIntPath & "i15_fmont.c".}
{.compile: bearIntPath & "i15_iszero.c".}
{.compile: bearIntPath & "i15_moddiv.c".}
{.compile: bearIntPath & "i15_modpow.c".}
{.compile: bearIntPath & "i15_modpow2.c".}
{.compile: bearIntPath & "i15_montmul.c".}
{.compile: bearIntPath & "i15_mulacc.c".}
{.compile: bearIntPath & "i15_muladd.c".}
{.compile: bearIntPath & "i15_ninv15.c".}
{.compile: bearIntPath & "i15_reduce.c".}
{.compile: bearIntPath & "i15_rshift.c".}
{.compile: bearIntPath & "i15_sub.c".}
{.compile: bearIntPath & "i15_tmont.c".}
{.compile: bearIntPath & "i31_add.c".}
{.compile: bearIntPath & "i31_bitlen.c".}
{.compile: bearIntPath & "i31_decmod.c".}
{.compile: bearIntPath & "i31_decode.c".}
{.compile: bearIntPath & "i31_decred.c".}
{.compile: bearIntPath & "i31_encode.c".}
{.compile: bearIntPath & "i31_fmont.c".}
{.compile: bearIntPath & "i31_iszero.c".}
{.compile: bearIntPath & "i31_moddiv.c".}
{.compile: bearIntPath & "i31_modpow.c".}
{.compile: bearIntPath & "i31_modpow2.c".}
{.compile: bearIntPath & "i31_montmul.c".}
{.compile: bearIntPath & "i31_mulacc.c".}
{.compile: bearIntPath & "i31_muladd.c".}
{.compile: bearIntPath & "i31_ninv31.c".}
{.compile: bearIntPath & "i31_reduce.c".}
{.compile: bearIntPath & "i31_rshift.c".}
{.compile: bearIntPath & "i31_sub.c".}
{.compile: bearIntPath & "i31_tmont.c".}
{.compile: bearIntPath & "i32_add.c".}
{.compile: bearIntPath & "i32_bitlen.c".}
{.compile: bearIntPath & "i32_decmod.c".}
{.compile: bearIntPath & "i32_decode.c".}
{.compile: bearIntPath & "i32_decred.c".}
{.compile: bearIntPath & "i32_div32.c".}
{.compile: bearIntPath & "i32_encode.c".}
{.compile: bearIntPath & "i32_fmont.c".}
{.compile: bearIntPath & "i32_iszero.c".}
{.compile: bearIntPath & "i32_modpow.c".}
{.compile: bearIntPath & "i32_montmul.c".}
{.compile: bearIntPath & "i32_mulacc.c".}
{.compile: bearIntPath & "i32_muladd.c".}
{.compile: bearIntPath & "i32_ninv32.c".}
{.compile: bearIntPath & "i32_reduce.c".}
{.compile: bearIntPath & "i32_sub.c".}
{.compile: bearIntPath & "i32_tmont.c".}
{.compile: bearIntPath & "i62_modpow2.c".}

{.compile: bearKdfPath & "hkdf.c".}
{.compile: bearKdfPath & "shake.c".}

{.compile: bearMacPath & "hmac.c".}
{.compile: bearMacPath & "hmac_ct.c".}

{.compile: bearRandPath & "aesctr_drbg.c".}
{.compile: bearRandPath & "hmac_drbg.c".}
{.compile: bearRandPath & "sysrng.c".}

{.compile: bearRsaPath & "rsa_default_keygen.c".}
{.compile: bearRsaPath & "rsa_default_modulus.c".}
{.compile: bearRsaPath & "rsa_default_oaep_decrypt.c".}
{.compile: bearRsaPath & "rsa_default_oaep_encrypt.c".}
{.compile: bearRsaPath & "rsa_default_pkcs1_sign.c".}
{.compile: bearRsaPath & "rsa_default_pkcs1_vrfy.c".}
{.compile: bearRsaPath & "rsa_default_priv.c".}
{.compile: bearRsaPath & "rsa_default_privexp.c".}
{.compile: bearRsaPath & "rsa_default_pss_sign.c".}
{.compile: bearRsaPath & "rsa_default_pss_vrfy.c".}
{.compile: bearRsaPath & "rsa_default_pub.c".}
{.compile: bearRsaPath & "rsa_default_pubexp.c".}
{.compile: bearRsaPath & "rsa_i15_keygen.c".}
{.compile: bearRsaPath & "rsa_i15_modulus.c".}
{.compile: bearRsaPath & "rsa_i15_oaep_decrypt.c".}
{.compile: bearRsaPath & "rsa_i15_oaep_encrypt.c".}
{.compile: bearRsaPath & "rsa_i15_pkcs1_sign.c".}
{.compile: bearRsaPath & "rsa_i15_pkcs1_vrfy.c".}
{.compile: bearRsaPath & "rsa_i15_priv.c".}
{.compile: bearRsaPath & "rsa_i15_privexp.c".}
{.compile: bearRsaPath & "rsa_i15_pss_sign.c".}
{.compile: bearRsaPath & "rsa_i15_pss_vrfy.c".}
{.compile: bearRsaPath & "rsa_i15_pub.c".}
{.compile: bearRsaPath & "rsa_i15_pubexp.c".}
{.compile: bearRsaPath & "rsa_i31_keygen.c".}
{.compile: bearRsaPath & "rsa_i31_keygen_inner.c".}
{.compile: bearRsaPath & "rsa_i31_modulus.c".}
{.compile: bearRsaPath & "rsa_i31_oaep_decrypt.c".}
{.compile: bearRsaPath & "rsa_i31_oaep_encrypt.c".}
{.compile: bearRsaPath & "rsa_i31_pkcs1_sign.c".}
{.compile: bearRsaPath & "rsa_i31_pkcs1_vrfy.c".}
{.compile: bearRsaPath & "rsa_i31_priv.c".}
{.compile: bearRsaPath & "rsa_i31_privexp.c".}
{.compile: bearRsaPath & "rsa_i31_pss_sign.c".}
{.compile: bearRsaPath & "rsa_i31_pss_vrfy.c".}
{.compile: bearRsaPath & "rsa_i31_pub.c".}
{.compile: bearRsaPath & "rsa_i31_pubexp.c".}
{.compile: bearRsaPath & "rsa_i32_oaep_decrypt.c".}
{.compile: bearRsaPath & "rsa_i32_oaep_encrypt.c".}
{.compile: bearRsaPath & "rsa_i32_pkcs1_sign.c".}
{.compile: bearRsaPath & "rsa_i32_pkcs1_vrfy.c".}
{.compile: bearRsaPath & "rsa_i32_priv.c".}
{.compile: bearRsaPath & "rsa_i32_pss_sign.c".}
{.compile: bearRsaPath & "rsa_i32_pss_vrfy.c".}
{.compile: bearRsaPath & "rsa_i32_pub.c".}
{.compile: bearRsaPath & "rsa_i62_keygen.c".}
{.compile: bearRsaPath & "rsa_i62_oaep_decrypt.c".}
{.compile: bearRsaPath & "rsa_i62_oaep_encrypt.c".}
{.compile: bearRsaPath & "rsa_i62_pkcs1_sign.c".}
{.compile: bearRsaPath & "rsa_i62_pkcs1_vrfy.c".}
{.compile: bearRsaPath & "rsa_i62_priv.c".}
{.compile: bearRsaPath & "rsa_i62_pss_sign.c".}
{.compile: bearRsaPath & "rsa_i62_pss_vrfy.c".}
{.compile: bearRsaPath & "rsa_i62_pub.c".}
{.compile: bearRsaPath & "rsa_oaep_pad.c".}
{.compile: bearRsaPath & "rsa_oaep_unpad.c".}
{.compile: bearRsaPath & "rsa_pkcs1_sig_pad.c".}
{.compile: bearRsaPath & "rsa_pkcs1_sig_unpad.c".}
{.compile: bearRsaPath & "rsa_pss_sig_pad.c".}
{.compile: bearRsaPath & "rsa_pss_sig_unpad.c".}
{.compile: bearRsaPath & "rsa_ssl_decrypt.c".}

{.compile: bearSslPath & "prf.c".}
{.compile: bearSslPath & "prf_md5sha1.c".}
{.compile: bearSslPath & "prf_sha256.c".}
{.compile: bearSslPath & "prf_sha384.c".}
{.compile: bearSslPath & "ssl_ccert_single_ec.c".}
{.compile: bearSslPath & "ssl_ccert_single_rsa.c".}
{.compile: bearSslPath & "ssl_client.c".}
{.compile: bearSslPath & "ssl_client_default_rsapub.c".}
{.compile: bearSslPath & "ssl_client_full.c".}
{.compile: bearSslPath & "ssl_engine.c".}
{.compile: bearSslPath & "ssl_engine_default_aescbc.c".}
{.compile: bearSslPath & "ssl_engine_default_aesccm.c".}
{.compile: bearSslPath & "ssl_engine_default_aesgcm.c".}
{.compile: bearSslPath & "ssl_engine_default_chapol.c".}
{.compile: bearSslPath & "ssl_engine_default_descbc.c".}
{.compile: bearSslPath & "ssl_engine_default_ec.c".}
{.compile: bearSslPath & "ssl_engine_default_ecdsa.c".}
{.compile: bearSslPath & "ssl_engine_default_rsavrfy.c".}
{.compile: bearSslPath & "ssl_hashes.c".}
{.compile: bearSslPath & "ssl_hs_client.c".}
{.compile: bearSslPath & "ssl_hs_server.c".}
{.compile: bearSslPath & "ssl_io.c".}
{.compile: bearSslPath & "ssl_keyexport.c".}
{.compile: bearSslPath & "ssl_lru.c".}
{.compile: bearSslPath & "ssl_rec_cbc.c".}
{.compile: bearSslPath & "ssl_rec_ccm.c".}
{.compile: bearSslPath & "ssl_rec_chapol.c".}
{.compile: bearSslPath & "ssl_rec_gcm.c".}
{.compile: bearSslPath & "ssl_scert_single_ec.c".}
{.compile: bearSslPath & "ssl_scert_single_rsa.c".}
{.compile: bearSslPath & "ssl_server.c".}
{.compile: bearSslPath & "ssl_server_full_ec.c".}
{.compile: bearSslPath & "ssl_server_full_rsa.c".}
{.compile: bearSslPath & "ssl_server_mine2c.c".}
{.compile: bearSslPath & "ssl_server_mine2g.c".}
{.compile: bearSslPath & "ssl_server_minf2c.c".}
{.compile: bearSslPath & "ssl_server_minf2g.c".}
{.compile: bearSslPath & "ssl_server_minr2g.c".}
{.compile: bearSslPath & "ssl_server_minu2g.c".}
{.compile: bearSslPath & "ssl_server_minv2g.c".}

{.compile: bearSymcPath & "aes_big_cbcdec.c".}
{.compile: bearSymcPath & "aes_big_cbcenc.c".}
{.compile: bearSymcPath & "aes_big_ctr.c".}
{.compile: bearSymcPath & "aes_big_ctrcbc.c".}
{.compile: bearSymcPath & "aes_big_dec.c".}
{.compile: bearSymcPath & "aes_big_enc.c".}
{.compile: bearSymcPath & "aes_common.c".}
{.compile: bearSymcPath & "aes_ct.c".}
{.compile: bearSymcPath & "aes_ct64.c".}
{.compile: bearSymcPath & "aes_ct64_cbcdec.c".}
{.compile: bearSymcPath & "aes_ct64_cbcenc.c".}
{.compile: bearSymcPath & "aes_ct64_ctr.c".}
{.compile: bearSymcPath & "aes_ct64_ctrcbc.c".}
{.compile: bearSymcPath & "aes_ct64_dec.c".}
{.compile: bearSymcPath & "aes_ct64_enc.c".}
{.compile: bearSymcPath & "aes_ct_cbcdec.c".}
{.compile: bearSymcPath & "aes_ct_cbcenc.c".}
{.compile: bearSymcPath & "aes_ct_ctr.c".}
{.compile: bearSymcPath & "aes_ct_ctrcbc.c".}
{.compile: bearSymcPath & "aes_ct_dec.c".}
{.compile: bearSymcPath & "aes_ct_enc.c".}
{.compile: bearSymcPath & "aes_pwr8.c".}
{.compile: bearSymcPath & "aes_pwr8_cbcdec.c".}
{.compile: bearSymcPath & "aes_pwr8_cbcenc.c".}
{.compile: bearSymcPath & "aes_pwr8_ctr.c".}
{.compile: bearSymcPath & "aes_pwr8_ctrcbc.c".}
{.compile: bearSymcPath & "aes_small_cbcdec.c".}
{.compile: bearSymcPath & "aes_small_cbcenc.c".}
{.compile: bearSymcPath & "aes_small_ctr.c".}
{.compile: bearSymcPath & "aes_small_ctrcbc.c".}
{.compile: bearSymcPath & "aes_small_dec.c".}
{.compile: bearSymcPath & "aes_small_enc.c".}
{.compile: bearSymcPath & "aes_x86ni.c".}
{.compile: bearSymcPath & "aes_x86ni_cbcdec.c".}
{.compile: bearSymcPath & "aes_x86ni_cbcenc.c".}
{.compile: bearSymcPath & "aes_x86ni_ctr.c".}
{.compile: bearSymcPath & "aes_x86ni_ctrcbc.c".}
{.compile: bearSymcPath & "chacha20_ct.c".}
{.compile: bearSymcPath & "chacha20_sse2.c".}
{.compile: bearSymcPath & "des_ct.c".}
{.compile: bearSymcPath & "des_ct_cbcdec.c".}
{.compile: bearSymcPath & "des_ct_cbcenc.c".}
{.compile: bearSymcPath & "des_support.c".}
{.compile: bearSymcPath & "des_tab.c".}
{.compile: bearSymcPath & "des_tab_cbcdec.c".}
{.compile: bearSymcPath & "des_tab_cbcenc.c".}
{.compile: bearSymcPath & "poly1305_ctmul.c".}
{.compile: bearSymcPath & "poly1305_ctmul32.c".}
{.compile: bearSymcPath & "poly1305_ctmulq.c".}
{.compile: bearSymcPath & "poly1305_i15.c".}

{.compile: bearAeadPath & "ccm.c".}
{.compile: bearAeadPath & "eax.c".}
{.compile: bearAeadPath & "gcm.c".}

{.compile: bearX509Path & "asn1enc.c".}
{.compile: bearX509Path & "encode_ec_pk8der.c".}
{.compile: bearX509Path & "encode_ec_rawder.c".}
{.compile: bearX509Path & "encode_rsa_pk8der.c".}
{.compile: bearX509Path & "encode_rsa_rawder.c".}
{.compile: bearX509Path & "skey_decoder.c".}
{.compile: bearX509Path & "x509_decoder.c".}
{.compile: bearX509Path & "x509_knownkey.c".}
{.compile: bearX509Path & "x509_minimal.c".}
{.compile: bearX509Path & "x509_minimal_full.c".}

{.compile: bearRootPath & "settings.c".}

# This modules must be reimplemented using Nim, because it can be changed
# freely.
{.compile: bearToolsPath & "xmem.c".}
{.compile: bearToolsPath & "vector.c".}
{.compile: bearToolsPath & "names.c".}
{.compile: bearToolsPath & "certs.c".}
{.compile: bearToolsPath & "files.c".}

{.pragma: bearSslFunc, cdecl, gcsafe, noSideEffect, raises: [].}

type
  HashClass* {.importc: "br_hash_class", header: "bearssl_hash.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    desc* {.importc: "desc".}: uint32
    init* {.importc: "init".}: proc (ctx: ptr ptr HashClass) {.bearSslFunc.}
    update* {.importc: "update".}: proc (ctx: ptr ptr HashClass; data: pointer; len: int) {.
        bearSslFunc.}
    output* {.importc: "out".}: proc (ctx: ptr ptr HashClass; dst: pointer) {.bearSslFunc.}
    state* {.importc: "state".}: proc (ctx: ptr ptr HashClass; dst: pointer): uint64 {.
        bearSslFunc.}
    setState* {.importc: "set_state".}: proc (ctx: ptr ptr HashClass; stb: pointer;
        count: uint64) {.bearSslFunc.}

template hashdesc_Id*(id: untyped): untyped =
  ((uint32)(id) shl hashdesc_Id_Off)

const
  HASHDESC_ID_OFF* = 0
  HASHDESC_ID_MASK* = 0x000000FF

template hashdesc_Out*(size: untyped): untyped =
  ((uint32)(size) shl hashdesc_Out_Off)

const
  HASHDESC_OUT_OFF* = 8
  HASHDESC_OUT_MASK* = 0x0000007F

template hashdesc_State*(size: untyped): untyped =
  ((uint32)(size) shl hashdesc_State_Off)

const
  HASHDESC_STATE_OFF* = 15
  HASHDESC_STATE_MASK* = 0x000000FF

template hashdesc_Lblen*(ls: untyped): untyped =
  ((uint32)(ls) shl hashdesc_Lblen_Off)

const
  HASHDESC_LBLEN_OFF* = 23
  HASHDESC_LBLEN_MASK* = 0x0000000F
  HASHDESC_MD_PADDING* = (1'u32 shl 28)
  HASHDESC_MD_PADDING_128* = (1'u32 shl 29)
  HASHDESC_MD_PADDING_BE* = (1'u32 shl 30)

const
  md5ID* = 1

const
  md5SIZE* = 16

var md5Vtable* {.importc: "br_md5_vtable", header: "bearssl_hash.h".}: HashClass

type
  Md5Context* {.importc: "br_md5_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, cuchar]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[4, uint32]


proc md5Init*(ctx: ptr Md5Context) {.
    bearSslFunc, importc: "br_md5_init", header: "bearssl_hash.h".}

proc md5Update*(ctx: ptr Md5Context; data: pointer; len: int) {.
    bearSslFunc, importc: "br_md5_update", header: "bearssl_hash.h".}

proc md5Out*(ctx: ptr Md5Context; `out`: pointer) {.
    bearSslFunc, importc: "br_md5_out", header: "bearssl_hash.h".}

proc md5State*(ctx: ptr Md5Context; `out`: pointer): uint64 {.
    bearSslFunc, importc: "br_md5_state", header: "bearssl_hash.h".}

proc md5SetState*(ctx: ptr Md5Context; stb: pointer; count: uint64) {.
    bearSslFunc, importc: "br_md5_set_state", header: "bearssl_hash.h".}

const
  sha1ID* = 2

const
  sha1SIZE* = 20

var sha1Vtable* {.importc: "br_sha1_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha1Context* {.importc: "br_sha1_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, cuchar]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[5, uint32]


proc sha1Init*(ctx: ptr Sha1Context) {.
    bearSslFunc, importc: "br_sha1_init", header: "bearssl_hash.h".}

proc sha1Update*(ctx: ptr Sha1Context; data: pointer; len: int) {.
    bearSslFunc, importc: "br_sha1_update", header: "bearssl_hash.h".}

proc sha1Out*(ctx: ptr Sha1Context; `out`: pointer) {.
    bearSslFunc, importc: "br_sha1_out", header: "bearssl_hash.h".}

proc sha1State*(ctx: ptr Sha1Context; `out`: pointer): uint64 {.
    bearSslFunc, importc: "br_sha1_state", header: "bearssl_hash.h".}

proc sha1SetState*(ctx: ptr Sha1Context; stb: pointer; count: uint64) {.
    bearSslFunc, importc: "br_sha1_set_state", header: "bearssl_hash.h".}

const
  sha224ID* = 3

const
  sha224SIZE* = 28

var sha224Vtable* {.importc: "br_sha224_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha256Context* = Sha224Context
  Sha224Context* {.importc: "br_sha224_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, cuchar]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[8, uint32]


proc sha224Init*(ctx: ptr Sha224Context) {.
    bearSslFunc, importc: "br_sha224_init", header: "bearssl_hash.h".}

proc sha224Update*(ctx: ptr Sha224Context; data: pointer; len: int) {.
    bearSslFunc, importc: "br_sha224_update", header: "bearssl_hash.h".}

proc sha224Out*(ctx: ptr Sha224Context; `out`: pointer) {.
    bearSslFunc, importc: "br_sha224_out", header: "bearssl_hash.h".}

proc sha224State*(ctx: ptr Sha224Context; `out`: pointer): uint64 {.
    bearSslFunc, importc: "br_sha224_state", header: "bearssl_hash.h".}

proc sha224SetState*(ctx: ptr Sha224Context; stb: pointer; count: uint64) {.
    bearSslFunc, importc: "br_sha224_set_state", header: "bearssl_hash.h".}

const
  sha256ID* = 4

const
  sha256SIZE* = 32

var sha256Vtable* {.importc: "br_sha256_vtable", header: "bearssl_hash.h".}: HashClass

proc sha256Init*(ctx: ptr Sha256Context) {.
    bearSslFunc, importc: "br_sha256_init", header: "bearssl_hash.h".}

proc sha256Out*(ctx: ptr Sha256Context; `out`: pointer) {.
    bearSslFunc, importc: "br_sha256_out", header: "bearssl_hash.h".}

when false:
  proc sha256State*(ctx: ptr Sha256Context; `out`: pointer): uint64 {.
      bearSslFunc, importc: "br_sha256_state", header: "bearssl_hash.h".}
else:
  const
    sha256State* = sha224State

when false:
  proc sha256SetState*(ctx: ptr Sha256Context; stb: pointer; count: uint64) {.
      bearSslFunc, importc: "br_sha256_set_state", header: "bearssl_hash.h".}
else:
  const
    sha256SetState* = sha224SetState

const
  sha384ID* = 5

const
  sha384SIZE* = 48

var sha384Vtable* {.importc: "br_sha384_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha384Context* {.importc: "br_sha384_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[128, cuchar]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[8, uint64]


proc sha384Init*(ctx: ptr Sha384Context) {.
    bearSslFunc, importc: "br_sha384_init", header: "bearssl_hash.h".}

proc sha384Update*(ctx: ptr Sha384Context; data: pointer; len: int) {.
    bearSslFunc, importc: "br_sha384_update", header: "bearssl_hash.h".}

proc sha384Out*(ctx: ptr Sha384Context; `out`: pointer) {.
    bearSslFunc, importc: "br_sha384_out", header: "bearssl_hash.h".}

proc sha384State*(ctx: ptr Sha384Context; `out`: pointer): uint64 {.
    bearSslFunc, importc: "br_sha384_state", header: "bearssl_hash.h".}

proc sha384SetState*(ctx: ptr Sha384Context; stb: pointer; count: uint64) {.
    bearSslFunc, importc: "br_sha384_set_state", header: "bearssl_hash.h".}

const
  sha512ID* = 6

const
  sha512SIZE* = 64

var sha512Vtable* {.importc: "br_sha512_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha512Context* = Sha384Context

proc sha512Init*(ctx: ptr Sha512Context) {.
    bearSslFunc, importc: "br_sha512_init", header: "bearssl_hash.h".}

const
  sha512Update* = sha384Update

proc sha512Out*(ctx: ptr Sha512Context; `out`: pointer) {.
    bearSslFunc, importc: "br_sha512_out", header: "bearssl_hash.h".}

const
  md5sha1ID* = 0

const
  md5sha1SIZE* = 36

var md5sha1Vtable* {.importc: "br_md5sha1_vtable", header: "bearssl_hash.h".}: HashClass

type
  Md5sha1Context* {.importc: "br_md5sha1_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, cuchar]
    count* {.importc: "count".}: uint64
    valMd5* {.importc: "val_md5".}: array[4, uint32]
    valSha1* {.importc: "val_sha1".}: array[5, uint32]


proc md5sha1Init*(ctx: ptr Md5sha1Context) {.bearSslFunc, importc: "br_md5sha1_init",
    header: "bearssl_hash.h".}

proc md5sha1Update*(ctx: ptr Md5sha1Context; data: pointer; len: int) {.bearSslFunc,
    importc: "br_md5sha1_update", header: "bearssl_hash.h".}

proc md5sha1Out*(ctx: ptr Md5sha1Context; `out`: pointer) {.bearSslFunc,
    importc: "br_md5sha1_out", header: "bearssl_hash.h".}

proc md5sha1State*(ctx: ptr Md5sha1Context; `out`: pointer): uint64 {.bearSslFunc,
    importc: "br_md5sha1_state", header: "bearssl_hash.h".}

proc md5sha1SetState*(ctx: ptr Md5sha1Context; stb: pointer; count: uint64) {.bearSslFunc,
    importc: "br_md5sha1_set_state", header: "bearssl_hash.h".}

type
  HashCompatContext* {.importc: "br_hash_compat_context", header: "bearssl_hash.h",
                      union, bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    md5* {.importc: "md5".}: Md5Context
    sha1* {.importc: "sha1".}: Sha1Context
    sha224* {.importc: "sha224".}: Sha224Context
    sha256* {.importc: "sha256".}: Sha256Context
    sha384* {.importc: "sha384".}: Sha384Context
    sha512* {.importc: "sha512".}: Sha512Context
    md5sha1* {.importc: "md5sha1".}: Md5sha1Context


type
  MultihashContext* {.importc: "br_multihash_context", header: "bearssl_hash.h",
                     bycopy.} = object
    buf* {.importc: "buf".}: array[128, cuchar]
    count* {.importc: "count".}: uint64
    val32* {.importc: "val_32".}: array[25, uint32]
    val64* {.importc: "val_64".}: array[16, uint64]
    impl* {.importc: "impl".}: array[6, ptr HashClass]


proc multihashZero*(ctx: ptr MultihashContext) {.bearSslFunc, importc: "br_multihash_zero",
    header: "bearssl_hash.h".}

proc multihashSetimpl*(ctx: ptr MultihashContext; id: cint; impl: ptr HashClass) {.
    inline.} =
  ctx.impl[id - 1] = impl

proc multihashGetimpl*(ctx: ptr MultihashContext; id: cint): ptr HashClass {.inline,
    bearSslFunc.} =
  return ctx.impl[id - 1]

proc multihashInit*(ctx: ptr MultihashContext) {.bearSslFunc, importc: "br_multihash_init",
    header: "bearssl_hash.h".}

proc multihashUpdate*(ctx: ptr MultihashContext; data: pointer; len: int) {.bearSslFunc,
    importc: "br_multihash_update", header: "bearssl_hash.h".}

proc multihashOut*(ctx: ptr MultihashContext; id: cint; dst: pointer): int {.bearSslFunc,
    importc: "br_multihash_out", header: "bearssl_hash.h".}

type
  Ghash* = proc (y: pointer; h: pointer; data: pointer; len: int) {.bearSslFunc.}

proc ghashCtmul*(y: pointer; h: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_ghash_ctmul", header: "bearssl_hash.h".}

proc ghashCtmul32*(y: pointer; h: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_ghash_ctmul32", header: "bearssl_hash.h".}

proc ghashCtmul64*(y: pointer; h: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_ghash_ctmul64", header: "bearssl_hash.h".}

proc ghashPclmul*(y: pointer; h: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_ghash_pclmul", header: "bearssl_hash.h".}

proc ghashPclmulGet*(): Ghash {.bearSslFunc, importc: "br_ghash_pclmul_get",
                             header: "bearssl_hash.h".}

proc ghashPwr8*(y: pointer; h: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_ghash_pwr8", header: "bearssl_hash.h".}

proc ghashPwr8Get*(): Ghash {.bearSslFunc, importc: "br_ghash_pwr8_get",
                           header: "bearssl_hash.h".}

type
  HmacKeyContext* {.importc: "br_hmac_key_context", header: "bearssl_hmac.h", bycopy.} = object
    digVtable* {.importc: "dig_vtable".}: ptr HashClass
    ksi* {.importc: "ksi".}: array[64, cuchar]
    kso* {.importc: "kso".}: array[64, cuchar]


proc hmacKeyInit*(kc: ptr HmacKeyContext; digestVtable: ptr HashClass; key: pointer;
                 keyLen: int) {.bearSslFunc, importc: "br_hmac_key_init",
                                header: "bearssl_hmac.h".}

type
  HmacContext* {.importc: "br_hmac_context", header: "bearssl_hmac.h", bycopy.} = object
    dig* {.importc: "dig".}: HashCompatContext
    kso* {.importc: "kso".}: array[64, cuchar]
    outLen* {.importc: "out_len".}: int


proc hmacInit*(ctx: ptr HmacContext; kc: ptr HmacKeyContext; outLen: int) {.bearSslFunc,
    importc: "br_hmac_init", header: "bearssl_hmac.h".}

proc hmacSize*(ctx: ptr HmacContext): int {.inline.} =
  return ctx.outLen

proc hmacUpdate*(ctx: ptr HmacContext; data: pointer; len: int) {.bearSslFunc,
    importc: "br_hmac_update", header: "bearssl_hmac.h".}

proc hmacOut*(ctx: ptr HmacContext; `out`: pointer): int {.bearSslFunc,
    importc: "br_hmac_out", header: "bearssl_hmac.h".}

proc hmacOutCT*(ctx: ptr HmacContext; data: pointer; len: int; minLen: int;
               maxLen: int; `out`: pointer): int {.bearSslFunc,
    importc: "br_hmac_outCT", header: "bearssl_hmac.h".}

type
  PrngClass* {.importc: "br_prng_class", header: "bearssl_rand.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    init* {.importc: "init".}: proc (ctx: ptr ptr PrngClass; params: pointer;
                                 seed: pointer; seedLen: int) {.bearSslFunc.}
    generate* {.importc: "generate".}: proc (ctx: ptr ptr PrngClass; `out`: pointer;
        len: int) {.bearSslFunc.}
    update* {.importc: "update".}: proc (ctx: ptr ptr PrngClass; seed: pointer;
                                     seedLen: int) {.bearSslFunc.}

type
  HmacDrbgContext* {.importc: "br_hmac_drbg_context", header: "bearssl_rand.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr PrngClass
    k* {.importc: "K".}: array[64, cuchar]
    v* {.importc: "V".}: array[64, cuchar]
    digestClass* {.importc: "digest_class".}: ptr HashClass


var hmacDrbgVtable* {.importc: "br_hmac_drbg_vtable", header: "bearssl_rand.h".}: PrngClass

proc hmacDrbgInit*(ctx: ptr HmacDrbgContext; digestClass: ptr HashClass; seed: pointer;
                  seedLen: int) {.bearSslFunc, importc: "br_hmac_drbg_init",
                                  header: "bearssl_rand.h".}

proc hmacDrbgGenerate*(ctx: ptr HmacDrbgContext; `out`: pointer; len: int) {.bearSslFunc,
    importc: "br_hmac_drbg_generate", header: "bearssl_rand.h".}

proc hmacDrbgUpdate*(ctx: ptr HmacDrbgContext; seed: pointer; seedLen: int) {.bearSslFunc,
    importc: "br_hmac_drbg_update", header: "bearssl_rand.h".}

proc hmacDrbgGetHash*(ctx: ptr HmacDrbgContext): ptr HashClass {.inline.} =
  return ctx.digestClass

type
  PrngSeeder* = proc (ctx: ptr ptr PrngClass): cint {.bearSslFunc.}

proc prngSeederSystem*(name: cstringArray): PrngSeeder {.bearSslFunc,
    importc: "br_prng_seeder_system", header: "bearssl_rand.h".}

type
  TlsPrfSeedChunk* {.importc: "br_tls_prf_seed_chunk", header: "bearssl_prf.h",
                    bycopy.} = object
    data* {.importc: "data".}: pointer
    len* {.importc: "len".}: int


proc tls10Prf*(dst: pointer; len: int; secret: pointer; secretLen: int;
              label: cstring; seedNum: int; seed: ptr TlsPrfSeedChunk) {.bearSslFunc,
    importc: "br_tls10_prf", header: "bearssl_prf.h".}

proc tls12Sha256Prf*(dst: pointer; len: int; secret: pointer; secretLen: int;
                    label: cstring; seedNum: int; seed: ptr TlsPrfSeedChunk) {.bearSslFunc,
    importc: "br_tls12_sha256_prf", header: "bearssl_prf.h".}

proc tls12Sha384Prf*(dst: pointer; len: int; secret: pointer; secretLen: int;
                    label: cstring; seedNum: int; seed: ptr TlsPrfSeedChunk) {.bearSslFunc,
    importc: "br_tls12_sha384_prf", header: "bearssl_prf.h".}

type
  TlsPrfImpl* = proc (dst: pointer; len: int; secret: pointer; secretLen: int;
                   label: cstring; seedNum: int; seed: ptr TlsPrfSeedChunk) {.bearSslFunc.}

type
  BlockCbcencClass* {.importc: "br_block_cbcenc_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCbcencClass; key: pointer;
                                 keyLen: int) {.bearSslFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCbcencClass; iv: pointer;
                               data: pointer; len: int) {.bearSslFunc.}

type
  BlockCbcdecClass* {.importc: "br_block_cbcdec_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCbcdecClass; key: pointer;
                                 keyLen: int) {.bearSslFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCbcdecClass; iv: pointer;
                               data: pointer; len: int) {.bearSslFunc.}

type
  BlockCtrClass* {.importc: "br_block_ctr_class", header: "bearssl_block.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCtrClass; key: pointer;
                                 keyLen: int) {.bearSslFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCtrClass; iv: pointer; cc: uint32;
                               data: pointer; len: int): uint32 {.bearSslFunc.}

type
  BlockCtrcbcClass* {.importc: "br_block_ctrcbc_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCtrcbcClass; key: pointer;
                                 keyLen: int) {.bearSslFunc.}
    encrypt* {.importc: "encrypt".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                                       cbcmac: pointer; data: pointer; len: int) {.
        bearSslFunc.}
    decrypt* {.importc: "decrypt".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                                       cbcmac: pointer; data: pointer; len: int) {.
        bearSslFunc.}
    ctr* {.importc: "ctr".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                               data: pointer; len: int) {.bearSslFunc.}
    mac* {.importc: "mac".}: proc (ctx: ptr ptr BlockCtrcbcClass; cbcmac: pointer;
                               data: pointer; len: int) {.bearSslFunc.}

const
  aesBigBLOCK_SIZE* = 16

type
  AesBigCbcencKeys* {.importc: "br_aes_big_cbcenc_keys", header: "bearssl_block.h",
                     bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesBigCbcdecKeys* {.importc: "br_aes_big_cbcdec_keys", header: "bearssl_block.h",
                     bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesBigCtrKeys* {.importc: "br_aes_big_ctr_keys", header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesBigCtrcbcKeys* {.importc: "br_aes_big_ctrcbc_keys", header: "bearssl_block.h",
                     bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


var aesBigCbcencVtable* {.importc: "br_aes_big_cbcenc_vtable",
                        header: "bearssl_block.h".}: BlockCbcencClass

var aesBigCbcdecVtable* {.importc: "br_aes_big_cbcdec_vtable",
                        header: "bearssl_block.h".}: BlockCbcdecClass

var aesBigCtrVtable* {.importc: "br_aes_big_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass

var aesBigCtrcbcVtable* {.importc: "br_aes_big_ctrcbc_vtable",
                        header: "bearssl_block.h".}: BlockCtrcbcClass

proc aesBigCbcencInit*(ctx: ptr AesBigCbcencKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_big_cbcenc_init", header: "bearssl_block.h".}

proc aesBigCbcdecInit*(ctx: ptr AesBigCbcdecKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_big_cbcdec_init", header: "bearssl_block.h".}

proc aesBigCtrInit*(ctx: ptr AesBigCtrKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_big_ctr_init", header: "bearssl_block.h".}

proc aesBigCtrcbcInit*(ctx: ptr AesBigCtrcbcKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_big_ctrcbc_init", header: "bearssl_block.h".}

proc aesBigCbcencRun*(ctx: ptr AesBigCbcencKeys; iv: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_aes_big_cbcenc_run", header: "bearssl_block.h".}

proc aesBigCbcdecRun*(ctx: ptr AesBigCbcdecKeys; iv: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_aes_big_cbcdec_run", header: "bearssl_block.h".}

proc aesBigCtrRun*(ctx: ptr AesBigCtrKeys; iv: pointer; cc: uint32; data: pointer;
                  len: int): uint32 {.bearSslFunc, importc: "br_aes_big_ctr_run",
                                      header: "bearssl_block.h".}

proc aesBigCtrcbcEncrypt*(ctx: ptr AesBigCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                         data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_big_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesBigCtrcbcDecrypt*(ctx: ptr AesBigCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                         data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_big_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesBigCtrcbcCtr*(ctx: ptr AesBigCtrcbcKeys; ctr: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_aes_big_ctrcbc_ctr", header: "bearssl_block.h".}

proc aesBigCtrcbcMac*(ctx: ptr AesBigCtrcbcKeys; cbcmac: pointer; data: pointer;
                     len: int) {.bearSslFunc, importc: "br_aes_big_ctrcbc_mac",
                                 header: "bearssl_block.h".}

const
  aesSmallBLOCK_SIZE* = 16

type
  AesSmallCbcencKeys* {.importc: "br_aes_small_cbcenc_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesSmallCbcdecKeys* {.importc: "br_aes_small_cbcdec_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesSmallCtrKeys* {.importc: "br_aes_small_ctr_keys", header: "bearssl_block.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesSmallCtrcbcKeys* {.importc: "br_aes_small_ctrcbc_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


var aesSmallCbcencVtable* {.importc: "br_aes_small_cbcenc_vtable",
                          header: "bearssl_block.h".}: BlockCbcencClass

var aesSmallCbcdecVtable* {.importc: "br_aes_small_cbcdec_vtable",
                          header: "bearssl_block.h".}: BlockCbcdecClass

var aesSmallCtrVtable* {.importc: "br_aes_small_ctr_vtable",
                       header: "bearssl_block.h".}: BlockCtrClass

var aesSmallCtrcbcVtable* {.importc: "br_aes_small_ctrcbc_vtable",
                          header: "bearssl_block.h".}: BlockCtrcbcClass

proc aesSmallCbcencInit*(ctx: ptr AesSmallCbcencKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_small_cbcenc_init", header: "bearssl_block.h".}

proc aesSmallCbcdecInit*(ctx: ptr AesSmallCbcdecKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_small_cbcdec_init", header: "bearssl_block.h".}

proc aesSmallCtrInit*(ctx: ptr AesSmallCtrKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_small_ctr_init", header: "bearssl_block.h".}

proc aesSmallCtrcbcInit*(ctx: ptr AesSmallCtrcbcKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_small_ctrcbc_init", header: "bearssl_block.h".}

proc aesSmallCbcencRun*(ctx: ptr AesSmallCbcencKeys; iv: pointer; data: pointer;
                       len: int) {.bearSslFunc, importc: "br_aes_small_cbcenc_run",
                                   header: "bearssl_block.h".}

proc aesSmallCbcdecRun*(ctx: ptr AesSmallCbcdecKeys; iv: pointer; data: pointer;
                       len: int) {.bearSslFunc, importc: "br_aes_small_cbcdec_run",
                                   header: "bearssl_block.h".}

proc aesSmallCtrRun*(ctx: ptr AesSmallCtrKeys; iv: pointer; cc: uint32; data: pointer;
                    len: int): uint32 {.bearSslFunc, importc: "br_aes_small_ctr_run",
                                        header: "bearssl_block.h".}

proc aesSmallCtrcbcEncrypt*(ctx: ptr AesSmallCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_small_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesSmallCtrcbcDecrypt*(ctx: ptr AesSmallCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_small_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesSmallCtrcbcCtr*(ctx: ptr AesSmallCtrcbcKeys; ctr: pointer; data: pointer;
                       len: int) {.bearSslFunc, importc: "br_aes_small_ctrcbc_ctr",
                                   header: "bearssl_block.h".}

proc aesSmallCtrcbcMac*(ctx: ptr AesSmallCtrcbcKeys; cbcmac: pointer; data: pointer;
                       len: int) {.bearSslFunc, importc: "br_aes_small_ctrcbc_mac",
                                   header: "bearssl_block.h".}

const
  aesCtBLOCK_SIZE* = 16

type
  AesCtCbcencKeys* {.importc: "br_aes_ct_cbcenc_keys", header: "bearssl_block.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesCtCbcdecKeys* {.importc: "br_aes_ct_cbcdec_keys", header: "bearssl_block.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesCtCtrKeys* {.importc: "br_aes_ct_ctr_keys", header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesCtCtrcbcKeys* {.importc: "br_aes_ct_ctrcbc_keys", header: "bearssl_block.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    skey* {.importc: "skey".}: array[60, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


var aesCtCbcencVtable* {.importc: "br_aes_ct_cbcenc_vtable",
                       header: "bearssl_block.h".}: BlockCbcencClass

var aesCtCbcdecVtable* {.importc: "br_aes_ct_cbcdec_vtable",
                       header: "bearssl_block.h".}: BlockCbcdecClass

var aesCtCtrVtable* {.importc: "br_aes_ct_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass

var aesCtCtrcbcVtable* {.importc: "br_aes_ct_ctrcbc_vtable",
                       header: "bearssl_block.h".}: BlockCtrcbcClass

proc aesCtCbcencInit*(ctx: ptr AesCtCbcencKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct_cbcenc_init", header: "bearssl_block.h".}

proc aesCtCbcdecInit*(ctx: ptr AesCtCbcdecKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct_cbcdec_init", header: "bearssl_block.h".}

proc aesCtCtrInit*(ctx: ptr AesCtCtrKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct_ctr_init", header: "bearssl_block.h".}

proc aesCtCtrcbcInit*(ctx: ptr AesCtCtrcbcKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct_ctrcbc_init", header: "bearssl_block.h".}

proc aesCtCbcencRun*(ctx: ptr AesCtCbcencKeys; iv: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_aes_ct_cbcenc_run", header: "bearssl_block.h".}

proc aesCtCbcdecRun*(ctx: ptr AesCtCbcdecKeys; iv: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_aes_ct_cbcdec_run", header: "bearssl_block.h".}

proc aesCtCtrRun*(ctx: ptr AesCtCtrKeys; iv: pointer; cc: uint32; data: pointer;
                 len: int): uint32 {.bearSslFunc, importc: "br_aes_ct_ctr_run",
                                     header: "bearssl_block.h".}

proc aesCtCtrcbcEncrypt*(ctx: ptr AesCtCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                        data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesCtCtrcbcDecrypt*(ctx: ptr AesCtCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                        data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesCtCtrcbcCtr*(ctx: ptr AesCtCtrcbcKeys; ctr: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_aes_ct_ctrcbc_ctr", header: "bearssl_block.h".}

proc aesCtCtrcbcMac*(ctx: ptr AesCtCtrcbcKeys; cbcmac: pointer; data: pointer;
                    len: int) {.bearSslFunc, importc: "br_aes_ct_ctrcbc_mac",
                                header: "bearssl_block.h".}

const
  aesCt64BLOCK_SIZE* = 16

type
  AesCt64CbcencKeys* {.importc: "br_aes_ct64_cbcenc_keys",
                      header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: array[30, uint64]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesCt64CbcdecKeys* {.importc: "br_aes_ct64_cbcdec_keys",
                      header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: array[30, uint64]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesCt64CtrKeys* {.importc: "br_aes_ct64_ctr_keys", header: "bearssl_block.h",
                   bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    skey* {.importc: "skey".}: array[30, uint64]
    numRounds* {.importc: "num_rounds".}: cuint


type
  AesCt64CtrcbcKeys* {.importc: "br_aes_ct64_ctrcbc_keys",
                      header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    skey* {.importc: "skey".}: array[30, uint64]
    numRounds* {.importc: "num_rounds".}: cuint


var aesCt64CbcencVtable* {.importc: "br_aes_ct64_cbcenc_vtable",
                         header: "bearssl_block.h".}: BlockCbcencClass

var aesCt64CbcdecVtable* {.importc: "br_aes_ct64_cbcdec_vtable",
                         header: "bearssl_block.h".}: BlockCbcdecClass

var aesCt64CtrVtable* {.importc: "br_aes_ct64_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass

var aesCt64CtrcbcVtable* {.importc: "br_aes_ct64_ctrcbc_vtable",
                         header: "bearssl_block.h".}: BlockCtrcbcClass

proc aesCt64CbcencInit*(ctx: ptr AesCt64CbcencKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct64_cbcenc_init", header: "bearssl_block.h".}

proc aesCt64CbcdecInit*(ctx: ptr AesCt64CbcdecKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct64_cbcdec_init", header: "bearssl_block.h".}

proc aesCt64CtrInit*(ctx: ptr AesCt64CtrKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct64_ctr_init", header: "bearssl_block.h".}

proc aesCt64CtrcbcInit*(ctx: ptr AesCt64CtrcbcKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct64_ctrcbc_init", header: "bearssl_block.h".}

proc aesCt64CbcencRun*(ctx: ptr AesCt64CbcencKeys; iv: pointer; data: pointer;
                      len: int) {.bearSslFunc, importc: "br_aes_ct64_cbcenc_run",
                                  header: "bearssl_block.h".}

proc aesCt64CbcdecRun*(ctx: ptr AesCt64CbcdecKeys; iv: pointer; data: pointer;
                      len: int) {.bearSslFunc, importc: "br_aes_ct64_cbcdec_run",
                                  header: "bearssl_block.h".}

proc aesCt64CtrRun*(ctx: ptr AesCt64CtrKeys; iv: pointer; cc: uint32; data: pointer;
                   len: int): uint32 {.bearSslFunc, importc: "br_aes_ct64_ctr_run",
                                       header: "bearssl_block.h".}

proc aesCt64CtrcbcEncrypt*(ctx: ptr AesCt64CtrcbcKeys; ctr: pointer; cbcmac: pointer;
                          data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct64_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesCt64CtrcbcDecrypt*(ctx: ptr AesCt64CtrcbcKeys; ctr: pointer; cbcmac: pointer;
                          data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_ct64_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesCt64CtrcbcCtr*(ctx: ptr AesCt64CtrcbcKeys; ctr: pointer; data: pointer;
                      len: int) {.bearSslFunc, importc: "br_aes_ct64_ctrcbc_ctr",
                                  header: "bearssl_block.h".}

proc aesCt64CtrcbcMac*(ctx: ptr AesCt64CtrcbcKeys; cbcmac: pointer; data: pointer;
                      len: int) {.bearSslFunc, importc: "br_aes_ct64_ctrcbc_mac",
                                  header: "bearssl_block.h".}

const
  aesX86niBLOCK_SIZE* = 16

type
  INNER_C_UNION_1159666335* {.importc: "no_name", header: "bearssl_block.h",
                              bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, cuchar]

  AesX86niCbcencKeys* {.importc: "br_aes_x86ni_cbcenc_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: INNER_C_UNION_1159666335
    numRounds* {.importc: "num_rounds".}: cuint


type
  INNER_C_UNION_3830826214* {.importc: "no_name", header: "bearssl_block.h",
                              bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, cuchar]

  AesX86niCbcdecKeys* {.importc: "br_aes_x86ni_cbcdec_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: INNER_C_UNION_3830826214
    numRounds* {.importc: "num_rounds".}: cuint


type
  INNER_C_UNION_1063979105* {.importc: "no_name", header: "bearssl_block.h",
                              bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, cuchar]

  AesX86niCtrKeys* {.importc: "br_aes_x86ni_ctr_keys", header: "bearssl_block.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    skey* {.importc: "skey".}: INNER_C_UNION_1063979105
    numRounds* {.importc: "num_rounds".}: cuint


type
  INNER_C_UNION_220758887* {.importc: "no_name", header: "bearssl_block.h",
                             bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, cuchar]

  AesX86niCtrcbcKeys* {.importc: "br_aes_x86ni_ctrcbc_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    skey* {.importc: "skey".}: INNER_C_UNION_220758887
    numRounds* {.importc: "num_rounds".}: cuint


var aesX86niCbcencVtable* {.importc: "br_aes_x86ni_cbcenc_vtable",
                          header: "bearssl_block.h".}: BlockCbcencClass

var aesX86niCbcdecVtable* {.importc: "br_aes_x86ni_cbcdec_vtable",
                          header: "bearssl_block.h".}: BlockCbcdecClass

var aesX86niCtrVtable* {.importc: "br_aes_x86ni_ctr_vtable",
                       header: "bearssl_block.h".}: BlockCtrClass

var aesX86niCtrcbcVtable* {.importc: "br_aes_x86ni_ctrcbc_vtable",
                          header: "bearssl_block.h".}: BlockCtrcbcClass

proc aesX86niCbcencInit*(ctx: ptr AesX86niCbcencKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_x86ni_cbcenc_init", header: "bearssl_block.h".}

proc aesX86niCbcdecInit*(ctx: ptr AesX86niCbcdecKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_x86ni_cbcdec_init", header: "bearssl_block.h".}

proc aesX86niCtrInit*(ctx: ptr AesX86niCtrKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_x86ni_ctr_init", header: "bearssl_block.h".}

proc aesX86niCtrcbcInit*(ctx: ptr AesX86niCtrcbcKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_x86ni_ctrcbc_init", header: "bearssl_block.h".}

proc aesX86niCbcencRun*(ctx: ptr AesX86niCbcencKeys; iv: pointer; data: pointer;
                       len: int) {.bearSslFunc, importc: "br_aes_x86ni_cbcenc_run",
                                   header: "bearssl_block.h".}

proc aesX86niCbcdecRun*(ctx: ptr AesX86niCbcdecKeys; iv: pointer; data: pointer;
                       len: int) {.bearSslFunc, importc: "br_aes_x86ni_cbcdec_run",
                                   header: "bearssl_block.h".}

proc aesX86niCtrRun*(ctx: ptr AesX86niCtrKeys; iv: pointer; cc: uint32; data: pointer;
                    len: int): uint32 {.bearSslFunc, importc: "br_aes_x86ni_ctr_run",
                                        header: "bearssl_block.h".}

proc aesX86niCtrcbcEncrypt*(ctx: ptr AesX86niCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_x86ni_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesX86niCtrcbcDecrypt*(ctx: ptr AesX86niCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_x86ni_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesX86niCtrcbcCtr*(ctx: ptr AesX86niCtrcbcKeys; ctr: pointer; data: pointer;
                       len: int) {.bearSslFunc, importc: "br_aes_x86ni_ctrcbc_ctr",
                                   header: "bearssl_block.h".}

proc aesX86niCtrcbcMac*(ctx: ptr AesX86niCtrcbcKeys; cbcmac: pointer; data: pointer;
                       len: int) {.bearSslFunc, importc: "br_aes_x86ni_ctrcbc_mac",
                                   header: "bearssl_block.h".}

proc aesX86niCbcencGetVtable*(): ptr BlockCbcencClass {.bearSslFunc,
    importc: "br_aes_x86ni_cbcenc_get_vtable", header: "bearssl_block.h".}

proc aesX86niCbcdecGetVtable*(): ptr BlockCbcdecClass {.bearSslFunc,
    importc: "br_aes_x86ni_cbcdec_get_vtable", header: "bearssl_block.h".}

proc aesX86niCtrGetVtable*(): ptr BlockCtrClass {.bearSslFunc,
    importc: "br_aes_x86ni_ctr_get_vtable", header: "bearssl_block.h".}

proc aesX86niCtrcbcGetVtable*(): ptr BlockCtrcbcClass {.bearSslFunc,
    importc: "br_aes_x86ni_ctrcbc_get_vtable", header: "bearssl_block.h".}

const
  aesPwr8BLOCK_SIZE* = 16

type
  INNER_C_UNION_2338321047* {.importc: "no_name", header: "bearssl_block.h",
                              bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, cuchar]

  AesPwr8CbcencKeys* {.importc: "br_aes_pwr8_cbcenc_keys",
                      header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: INNER_C_UNION_2338321047
    numRounds* {.importc: "num_rounds".}: cuint


type
  INNER_C_UNION_714513630* {.importc: "no_name", header: "bearssl_block.h",
                             bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, cuchar]

  AesPwr8CbcdecKeys* {.importc: "br_aes_pwr8_cbcdec_keys",
                      header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: INNER_C_UNION_714513630
    numRounds* {.importc: "num_rounds".}: cuint


type
  INNER_C_UNION_4166260708* {.importc: "no_name", header: "bearssl_block.h",
                              bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, cuchar]

  AesPwr8CtrKeys* {.importc: "br_aes_pwr8_ctr_keys", header: "bearssl_block.h",
                   bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    skey* {.importc: "skey".}: INNER_C_UNION_4166260708
    numRounds* {.importc: "num_rounds".}: cuint


var aesPwr8CbcencVtable* {.importc: "br_aes_pwr8_cbcenc_vtable",
                         header: "bearssl_block.h".}: BlockCbcencClass

var aesPwr8CbcdecVtable* {.importc: "br_aes_pwr8_cbcdec_vtable",
                         header: "bearssl_block.h".}: BlockCbcdecClass

var aesPwr8CtrVtable* {.importc: "br_aes_pwr8_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass

proc aesPwr8CbcencInit*(ctx: ptr AesPwr8CbcencKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_pwr8_cbcenc_init", header: "bearssl_block.h".}

proc aesPwr8CbcdecInit*(ctx: ptr AesPwr8CbcdecKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_pwr8_cbcdec_init", header: "bearssl_block.h".}

proc aesPwr8CtrInit*(ctx: ptr AesPwr8CtrKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_aes_pwr8_ctr_init", header: "bearssl_block.h".}

proc aesPwr8CbcencRun*(ctx: ptr AesPwr8CbcencKeys; iv: pointer; data: pointer;
                      len: int) {.bearSslFunc, importc: "br_aes_pwr8_cbcenc_run",
                                  header: "bearssl_block.h".}

proc aesPwr8CbcdecRun*(ctx: ptr AesPwr8CbcdecKeys; iv: pointer; data: pointer;
                      len: int) {.bearSslFunc, importc: "br_aes_pwr8_cbcdec_run",
                                  header: "bearssl_block.h".}

proc aesPwr8CtrRun*(ctx: ptr AesPwr8CtrKeys; iv: pointer; cc: uint32; data: pointer;
                   len: int): uint32 {.bearSslFunc, importc: "br_aes_pwr8_ctr_run",
                                       header: "bearssl_block.h".}

proc aesPwr8CbcencGetVtable*(): ptr BlockCbcencClass {.bearSslFunc,
    importc: "br_aes_pwr8_cbcenc_get_vtable", header: "bearssl_block.h".}

proc aesPwr8CbcdecGetVtable*(): ptr BlockCbcdecClass {.bearSslFunc,
    importc: "br_aes_pwr8_cbcdec_get_vtable", header: "bearssl_block.h".}

proc aesPwr8CtrGetVtable*(): ptr BlockCtrClass {.bearSslFunc,
    importc: "br_aes_pwr8_ctr_get_vtable", header: "bearssl_block.h".}

type
  AesGenCbcencKeys* {.importc: "br_aes_gen_cbcenc_keys", header: "bearssl_block.h",
                      bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    cBig* {.importc: "c_big".}: AesBigCbcencKeys
    cSmall* {.importc: "c_small".}: AesSmallCbcencKeys
    cCt* {.importc: "c_ct".}: AesCtCbcencKeys
    cCt64* {.importc: "c_ct64".}: AesCt64CbcencKeys
    cX86ni* {.importc: "c_x86ni".}: AesX86niCbcencKeys
    cPwr8* {.importc: "c_pwr8".}: AesPwr8CbcencKeys


type
  AesGenCbcdecKeys* {.importc: "br_aes_gen_cbcdec_keys", header: "bearssl_block.h",
                      bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    cBig* {.importc: "c_big".}: AesBigCbcdecKeys
    cSmall* {.importc: "c_small".}: AesSmallCbcdecKeys
    cCt* {.importc: "c_ct".}: AesCtCbcdecKeys
    cCt64* {.importc: "c_ct64".}: AesCt64CbcdecKeys
    cX86ni* {.importc: "c_x86ni".}: AesX86niCbcdecKeys
    cPwr8* {.importc: "c_pwr8".}: AesPwr8CbcdecKeys


type
  AesGenCtrKeys* {.importc: "br_aes_gen_ctr_keys", header: "bearssl_block.h",
                   bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    cBig* {.importc: "c_big".}: AesBigCtrKeys
    cSmall* {.importc: "c_small".}: AesSmallCtrKeys
    cCt* {.importc: "c_ct".}: AesCtCtrKeys
    cCt64* {.importc: "c_ct64".}: AesCt64CtrKeys
    cX86ni* {.importc: "c_x86ni".}: AesX86niCtrKeys
    cPwr8* {.importc: "c_pwr8".}: AesPwr8CtrKeys


type
  AesGenCtrcbcKeys* {.importc: "br_aes_gen_ctrcbc_keys",
                      header: "bearssl_block.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    cBig* {.importc: "c_big".}: AesBigCtrcbcKeys
    cSmall* {.importc: "c_small".}: AesSmallCtrcbcKeys
    cCt* {.importc: "c_ct".}: AesCtCtrcbcKeys
    cCt64* {.importc: "c_ct64".}: AesCt64CtrcbcKeys


const
  desTabBLOCK_SIZE* = 8

type
  DesTabCbcencKeys* {.importc: "br_des_tab_cbcenc_keys", header: "bearssl_block.h",
                     bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: array[96, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  DesTabCbcdecKeys* {.importc: "br_des_tab_cbcdec_keys", header: "bearssl_block.h",
                     bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: array[96, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


var desTabCbcencVtable* {.importc: "br_des_tab_cbcenc_vtable",
                        header: "bearssl_block.h".}: BlockCbcencClass

var desTabCbcdecVtable* {.importc: "br_des_tab_cbcdec_vtable",
                        header: "bearssl_block.h".}: BlockCbcdecClass

proc desTabCbcencInit*(ctx: ptr DesTabCbcencKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_des_tab_cbcenc_init", header: "bearssl_block.h".}

proc desTabCbcdecInit*(ctx: ptr DesTabCbcdecKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_des_tab_cbcdec_init", header: "bearssl_block.h".}

proc desTabCbcencRun*(ctx: ptr DesTabCbcencKeys; iv: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_des_tab_cbcenc_run", header: "bearssl_block.h".}

proc desTabCbcdecRun*(ctx: ptr DesTabCbcdecKeys; iv: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_des_tab_cbcdec_run", header: "bearssl_block.h".}

const
  desCtBLOCK_SIZE* = 8

type
  DesCtCbcencKeys* {.importc: "br_des_ct_cbcenc_keys", header: "bearssl_block.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: array[96, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


type
  DesCtCbcdecKeys* {.importc: "br_des_ct_cbcdec_keys", header: "bearssl_block.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: array[96, uint32]
    numRounds* {.importc: "num_rounds".}: cuint


var desCtCbcencVtable* {.importc: "br_des_ct_cbcenc_vtable",
                       header: "bearssl_block.h".}: BlockCbcencClass

var desCtCbcdecVtable* {.importc: "br_des_ct_cbcdec_vtable",
                       header: "bearssl_block.h".}: BlockCbcdecClass

proc desCtCbcencInit*(ctx: ptr DesCtCbcencKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_des_ct_cbcenc_init", header: "bearssl_block.h".}

proc desCtCbcdecInit*(ctx: ptr DesCtCbcdecKeys; key: pointer; len: int) {.bearSslFunc,
    importc: "br_des_ct_cbcdec_init", header: "bearssl_block.h".}

proc desCtCbcencRun*(ctx: ptr DesCtCbcencKeys; iv: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_des_ct_cbcenc_run", header: "bearssl_block.h".}

proc desCtCbcdecRun*(ctx: ptr DesCtCbcdecKeys; iv: pointer; data: pointer; len: int) {.
    bearSslFunc, importc: "br_des_ct_cbcdec_run", header: "bearssl_block.h".}

type
  DesGenCbcencKeys* {.importc: "br_des_gen_cbcenc_keys",
                      header: "bearssl_block.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    tab* {.importc: "tab".}: DesTabCbcencKeys
    ct* {.importc: "ct".}: DesCtCbcencKeys


type
  DesGenCbcdecKeys* {.importc: "br_des_gen_cbcdec_keys",
                      header: "bearssl_block.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    cTab* {.importc: "c_tab".}: DesTabCbcdecKeys
    cCt* {.importc: "c_ct".}: DesCtCbcdecKeys


type
  Chacha20Run* = proc (key: pointer; iv: pointer; cc: uint32; data: pointer; len: int): uint32 {.
      bearSslFunc.}

proc chacha20CtRun*(key: pointer; iv: pointer; cc: uint32; data: pointer; len: int): uint32 {.
    bearSslFunc, importc: "br_chacha20_ct_run", header: "bearssl_block.h".}

proc chacha20Sse2Run*(key: pointer; iv: pointer; cc: uint32; data: pointer; len: int): uint32 {.
    bearSslFunc, importc: "br_chacha20_sse2_run", header: "bearssl_block.h".}

proc chacha20Sse2Get*(): Chacha20Run {.bearSslFunc, importc: "br_chacha20_sse2_get",
                                    header: "bearssl_block.h".}

type
  Poly1305Run* = proc (key: pointer; iv: pointer; data: pointer; len: int; aad: pointer;
                    aadLen: int; tag: pointer; ichacha: Chacha20Run; encrypt: cint) {.
      bearSslFunc.}

proc poly1305CtmulRun*(key: pointer; iv: pointer; data: pointer; len: int;
                      aad: pointer; aadLen: int; tag: pointer; ichacha: Chacha20Run;
                      encrypt: cint) {.bearSslFunc, importc: "br_poly1305_ctmul_run",
                                     header: "bearssl_block.h".}

proc poly1305Ctmul32Run*(key: pointer; iv: pointer; data: pointer; len: int;
                        aad: pointer; aadLen: int; tag: pointer;
                        ichacha: Chacha20Run; encrypt: cint) {.bearSslFunc,
    importc: "br_poly1305_ctmul32_run", header: "bearssl_block.h".}

proc poly1305I15Run*(key: pointer; iv: pointer; data: pointer; len: int; aad: pointer;
                    aadLen: int; tag: pointer; ichacha: Chacha20Run; encrypt: cint) {.
    bearSslFunc, importc: "br_poly1305_i15_run", header: "bearssl_block.h".}

proc poly1305CtmulqRun*(key: pointer; iv: pointer; data: pointer; len: int;
                       aad: pointer; aadLen: int; tag: pointer;
                       ichacha: Chacha20Run; encrypt: cint) {.bearSslFunc,
    importc: "br_poly1305_ctmulq_run", header: "bearssl_block.h".}

proc poly1305CtmulqGet*(): Poly1305Run {.bearSslFunc, importc: "br_poly1305_ctmulq_get",
                                      header: "bearssl_block.h".}

type
  AeadClass* {.importc: "br_aead_class", header: "bearssl_aead.h", bycopy.} = object
    tagSize* {.importc: "tag_size".}: int
    reset* {.importc: "reset".}: proc (cc: ptr ptr AeadClass; iv: pointer; len: int) {.
        bearSslFunc.}
    aadInject* {.importc: "aad_inject".}: proc (cc: ptr ptr AeadClass; data: pointer;
        len: int) {.bearSslFunc.}
    flip* {.importc: "flip".}: proc (cc: ptr ptr AeadClass) {.bearSslFunc.}
    run* {.importc: "run".}: proc (cc: ptr ptr AeadClass; encrypt: cint; data: pointer;
                               len: int) {.bearSslFunc.}
    getTag* {.importc: "get_tag".}: proc (cc: ptr ptr AeadClass; tag: pointer) {.bearSslFunc.}
    checkTag* {.importc: "check_tag".}: proc (cc: ptr ptr AeadClass; tag: pointer): uint32 {.
        bearSslFunc.}
    getTagTrunc* {.importc: "get_tag_trunc".}: proc (cc: ptr ptr AeadClass;
        tag: pointer; len: int) {.bearSslFunc.}
    checkTagTrunc* {.importc: "check_tag_trunc".}: proc (cc: ptr ptr AeadClass;
        tag: pointer; len: int): uint32 {.bearSslFunc.}

type
  GcmContext* {.importc: "br_gcm_context", header: "bearssl_aead.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr AeadClass
    bctx* {.importc: "bctx".}: ptr ptr BlockCtrClass
    gh* {.importc: "gh".}: Ghash
    h* {.importc: "h".}: array[16, cuchar]
    j01* {.importc: "j0_1".}: array[12, cuchar]
    buf* {.importc: "buf".}: array[16, cuchar]
    y* {.importc: "y".}: array[16, cuchar]
    j02* {.importc: "j0_2".}: uint32
    jc* {.importc: "jc".}: uint32
    countAad* {.importc: "count_aad".}: uint64
    countCtr* {.importc: "count_ctr".}: uint64


proc gcmInit*(ctx: ptr GcmContext; bctx: ptr ptr BlockCtrClass; gh: Ghash) {.bearSslFunc,
    importc: "br_gcm_init", header: "bearssl_aead.h".}

proc gcmReset*(ctx: ptr GcmContext; iv: pointer; len: int) {.bearSslFunc,
    importc: "br_gcm_reset", header: "bearssl_aead.h".}

proc gcmAadInject*(ctx: ptr GcmContext; data: pointer; len: int) {.bearSslFunc,
    importc: "br_gcm_aad_inject", header: "bearssl_aead.h".}

proc gcmFlip*(ctx: ptr GcmContext) {.bearSslFunc, importc: "br_gcm_flip",
                                 header: "bearssl_aead.h".}

proc gcmRun*(ctx: ptr GcmContext; encrypt: cint; data: pointer; len: int) {.bearSslFunc,
    importc: "br_gcm_run", header: "bearssl_aead.h".}

proc gcmGetTag*(ctx: ptr GcmContext; tag: pointer) {.bearSslFunc, importc: "br_gcm_get_tag",
    header: "bearssl_aead.h".}

proc gcmCheckTag*(ctx: ptr GcmContext; tag: pointer): uint32 {.bearSslFunc,
    importc: "br_gcm_check_tag", header: "bearssl_aead.h".}

proc gcmGetTagTrunc*(ctx: ptr GcmContext; tag: pointer; len: int) {.bearSslFunc,
    importc: "br_gcm_get_tag_trunc", header: "bearssl_aead.h".}

proc gcmCheckTagTrunc*(ctx: ptr GcmContext; tag: pointer; len: int): uint32 {.bearSslFunc,
    importc: "br_gcm_check_tag_trunc", header: "bearssl_aead.h".}

var gcmVtable* {.importc: "br_gcm_vtable", header: "bearssl_aead.h".}: AeadClass

type
  EaxContext* {.importc: "br_eax_context", header: "bearssl_aead.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr AeadClass
    bctx* {.importc: "bctx".}: ptr ptr BlockCtrcbcClass
    l2* {.importc: "L2".}: array[16, cuchar]
    l4* {.importc: "L4".}: array[16, cuchar]
    nonce* {.importc: "nonce".}: array[16, cuchar]
    head* {.importc: "head".}: array[16, cuchar]
    ctr* {.importc: "ctr".}: array[16, cuchar]
    cbcmac* {.importc: "cbcmac".}: array[16, cuchar]
    buf* {.importc: "buf".}: array[16, cuchar]
    `ptr`* {.importc: "ptr".}: int


type
  EaxState* {.importc: "br_eax_state", header: "bearssl_aead.h", bycopy.} = object
    st* {.importc: "st".}: array[3, array[16, cuchar]]


proc eaxInit*(ctx: ptr EaxContext; bctx: ptr ptr BlockCtrcbcClass) {.bearSslFunc,
    importc: "br_eax_init", header: "bearssl_aead.h".}

proc eaxCapture*(ctx: ptr EaxContext; st: ptr EaxState) {.bearSslFunc,
    importc: "br_eax_capture", header: "bearssl_aead.h".}

proc eaxReset*(ctx: ptr EaxContext; nonce: pointer; len: int) {.bearSslFunc,
    importc: "br_eax_reset", header: "bearssl_aead.h".}

proc eaxResetPreAad*(ctx: ptr EaxContext; st: ptr EaxState; nonce: pointer; len: int) {.
    bearSslFunc, importc: "br_eax_reset_pre_aad", header: "bearssl_aead.h".}

proc eaxResetPostAad*(ctx: ptr EaxContext; st: ptr EaxState; nonce: pointer; len: int) {.
    bearSslFunc, importc: "br_eax_reset_post_aad", header: "bearssl_aead.h".}

proc eaxAadInject*(ctx: ptr EaxContext; data: pointer; len: int) {.bearSslFunc,
    importc: "br_eax_aad_inject", header: "bearssl_aead.h".}

proc eaxFlip*(ctx: ptr EaxContext) {.bearSslFunc, importc: "br_eax_flip",
                                 header: "bearssl_aead.h".}

proc eaxGetAadMac*(ctx: ptr EaxContext; st: ptr EaxState) {.inline.} =
  copyMem(unsafeAddr st.st[1], unsafeAddr ctx.head, sizeof(ctx.head))

proc eaxRun*(ctx: ptr EaxContext; encrypt: cint; data: pointer; len: int) {.bearSslFunc,
    importc: "br_eax_run", header: "bearssl_aead.h".}

proc eaxGetTag*(ctx: ptr EaxContext; tag: pointer) {.bearSslFunc, importc: "br_eax_get_tag",
    header: "bearssl_aead.h".}

proc eaxCheckTag*(ctx: ptr EaxContext; tag: pointer): uint32 {.bearSslFunc,
    importc: "br_eax_check_tag", header: "bearssl_aead.h".}

proc eaxGetTagTrunc*(ctx: ptr EaxContext; tag: pointer; len: int) {.bearSslFunc,
    importc: "br_eax_get_tag_trunc", header: "bearssl_aead.h".}

proc eaxCheckTagTrunc*(ctx: ptr EaxContext; tag: pointer; len: int): uint32 {.bearSslFunc,
    importc: "br_eax_check_tag_trunc", header: "bearssl_aead.h".}

var eaxVtable* {.importc: "br_eax_vtable", header: "bearssl_aead.h".}: AeadClass

type
  CcmContext* {.importc: "br_ccm_context", header: "bearssl_aead.h", bycopy.} = object
    bctx* {.importc: "bctx".}: ptr ptr BlockCtrcbcClass
    ctr* {.importc: "ctr".}: array[16, cuchar]
    cbcmac* {.importc: "cbcmac".}: array[16, cuchar]
    tagmask* {.importc: "tagmask".}: array[16, cuchar]
    buf* {.importc: "buf".}: array[16, cuchar]
    `ptr`* {.importc: "ptr".}: int
    tagLen* {.importc: "tag_len".}: int


proc ccmInit*(ctx: ptr CcmContext; bctx: ptr ptr BlockCtrcbcClass) {.bearSslFunc,
    importc: "br_ccm_init", header: "bearssl_aead.h".}

proc ccmReset*(ctx: ptr CcmContext; nonce: pointer; nonceLen: int; aadLen: uint64;
              dataLen: uint64; tagLen: int): cint {.bearSslFunc, importc: "br_ccm_reset",
    header: "bearssl_aead.h".}

proc ccmAadInject*(ctx: ptr CcmContext; data: pointer; len: int) {.bearSslFunc,
    importc: "br_ccm_aad_inject", header: "bearssl_aead.h".}

proc ccmFlip*(ctx: ptr CcmContext) {.bearSslFunc, importc: "br_ccm_flip",
                                 header: "bearssl_aead.h".}

proc ccmRun*(ctx: ptr CcmContext; encrypt: cint; data: pointer; len: int) {.bearSslFunc,
    importc: "br_ccm_run", header: "bearssl_aead.h".}

proc ccmGetTag*(ctx: ptr CcmContext; tag: pointer): int {.bearSslFunc,
    importc: "br_ccm_get_tag", header: "bearssl_aead.h".}

proc ccmCheckTag*(ctx: ptr CcmContext; tag: pointer): uint32 {.bearSslFunc,
    importc: "br_ccm_check_tag", header: "bearssl_aead.h".}

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
  RsaPublic* = proc (x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.bearSslFunc.}

type
  RsaPkcs1Vrfy* = proc (x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.bearSslFunc.}

type
  RsaPrivate* = proc (x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.bearSslFunc.}

type
  RsaPkcs1Sign* = proc (hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.bearSslFunc.}

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

proc rsaI32Public*(x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.bearSslFunc,
    importc: "br_rsa_i32_public", header: "bearssl_rsa.h".}

proc rsaI32Pkcs1Vrfy*(x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.bearSslFunc,
    importc: "br_rsa_i32_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI32Private*(x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.bearSslFunc,
    importc: "br_rsa_i32_private", header: "bearssl_rsa.h".}

proc rsaI32Pkcs1Sign*(hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.bearSslFunc,
    importc: "br_rsa_i32_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI31Public*(x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.bearSslFunc,
    importc: "br_rsa_i31_public", header: "bearssl_rsa.h".}

proc rsaI31Pkcs1Vrfy*(x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.bearSslFunc,
    importc: "br_rsa_i31_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI31Private*(x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.bearSslFunc,
    importc: "br_rsa_i31_private", header: "bearssl_rsa.h".}

proc rsaI31Pkcs1Sign*(hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.bearSslFunc,
    importc: "br_rsa_i31_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI62Public*(x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.bearSslFunc,
    importc: "br_rsa_i62_public", header: "bearssl_rsa.h".}

proc rsaI62Pkcs1Vrfy*(x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.bearSslFunc,
    importc: "br_rsa_i62_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI62Private*(x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.bearSslFunc,
    importc: "br_rsa_i62_private", header: "bearssl_rsa.h".}

proc rsaI62Pkcs1Sign*(hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.bearSslFunc,
    importc: "br_rsa_i62_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaI62PublicGet*(): RsaPublic {.bearSslFunc, importc: "br_rsa_i62_public_get",
                                  header: "bearssl_rsa.h".}

proc rsaI62Pkcs1VrfyGet*(): RsaPkcs1Vrfy {.bearSslFunc,
                                        importc: "br_rsa_i62_pkcs1_vrfy_get",
                                        header: "bearssl_rsa.h".}

proc rsaI62PrivateGet*(): RsaPrivate {.bearSslFunc, importc: "br_rsa_i62_private_get",
                                    header: "bearssl_rsa.h".}

proc rsaI62Pkcs1SignGet*(): RsaPkcs1Sign {.bearSslFunc,
                                        importc: "br_rsa_i62_pkcs1_sign_get",
                                        header: "bearssl_rsa.h".}

proc rsaI15Public*(x: ptr cuchar; xlen: int; pk: ptr RsaPublicKey): uint32 {.bearSslFunc,
    importc: "br_rsa_i15_public", header: "bearssl_rsa.h".}

proc rsaI15Pkcs1Vrfy*(x: ptr cuchar; xlen: int; hashOid: ptr cuchar; hashLen: int;
                     pk: ptr RsaPublicKey; hashOut: ptr cuchar): uint32 {.bearSslFunc,
    importc: "br_rsa_i15_pkcs1_vrfy", header: "bearssl_rsa.h".}

proc rsaI15Private*(x: ptr cuchar; sk: ptr RsaPrivateKey): uint32 {.bearSslFunc,
    importc: "br_rsa_i15_private", header: "bearssl_rsa.h".}

proc rsaI15Pkcs1Sign*(hashOid: ptr cuchar; hash: ptr cuchar; hashLen: int;
                     sk: ptr RsaPrivateKey; x: ptr cuchar): uint32 {.bearSslFunc,
    importc: "br_rsa_i15_pkcs1_sign", header: "bearssl_rsa.h".}

proc rsaPublicGetDefault*(): RsaPublic {.bearSslFunc,
                                      importc: "br_rsa_public_get_default",
                                      header: "bearssl_rsa.h".}

proc rsaPrivateGetDefault*(): RsaPrivate {.bearSslFunc,
                                        importc: "br_rsa_private_get_default",
                                        header: "bearssl_rsa.h".}

proc rsaPkcs1VrfyGetDefault*(): RsaPkcs1Vrfy {.bearSslFunc,
    importc: "br_rsa_pkcs1_vrfy_get_default", header: "bearssl_rsa.h".}

proc rsaPkcs1SignGetDefault*(): RsaPkcs1Sign {.bearSslFunc,
    importc: "br_rsa_pkcs1_sign_get_default", header: "bearssl_rsa.h".}

proc rsaSslDecrypt*(core: RsaPrivate; sk: ptr RsaPrivateKey; data: ptr cuchar; len: int): uint32 {.
    bearSslFunc, importc: "br_rsa_ssl_decrypt", header: "bearssl_rsa.h".}

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
    q* {.importc: "q".}: ptr cuchar
    qlen* {.importc: "qlen".}: int


type
  EcPrivateKey* {.importc: "br_ec_private_key", header: "bearssl_ec.h", bycopy.} = object
    curve* {.importc: "curve".}: cint
    x* {.importc: "x".}: ptr cuchar
    xlen* {.importc: "xlen".}: int


type
  EcImpl* {.importc: "br_ec_impl", header: "bearssl_ec.h", bycopy.} = object
    supportedCurves* {.importc: "supported_curves".}: uint32
    generator* {.importc: "generator".}: proc (curve: cint; len: ptr int): ptr cuchar {.bearSslFunc.}
    order* {.importc: "order".}: proc (curve: cint; len: ptr int): ptr cuchar {.bearSslFunc.}
    xoff* {.importc: "xoff".}: proc (curve: cint; len: ptr int): int {.bearSslFunc.}
    mul* {.importc: "mul".}: proc (g: ptr cuchar; glen: int; x: ptr cuchar; xlen: int;
                               curve: cint): uint32 {.bearSslFunc.}
    mulgen* {.importc: "mulgen".}: proc (r: ptr cuchar; x: ptr cuchar; xlen: int;
                                     curve: cint): int {.bearSslFunc.}
    muladd* {.importc: "muladd".}: proc (a: ptr cuchar; b: ptr cuchar; len: int;
                                     x: ptr cuchar; xlen: int; y: ptr cuchar;
                                     ylen: int; curve: cint): uint32 {.bearSslFunc.}


var ecPrimeI31* {.importc: "br_ec_prime_i31", header: "bearssl_ec.h".}: EcImpl

var ecPrimeI15* {.importc: "br_ec_prime_i15", header: "bearssl_ec.h".}: EcImpl

var ecP256M15* {.importc: "br_ec_p256_m15", header: "bearssl_ec.h".}: EcImpl

var ecP256M31* {.importc: "br_ec_p256_m31", header: "bearssl_ec.h".}: EcImpl

var ecC25519I15* {.importc: "br_ec_c25519_i15", header: "bearssl_ec.h".}: EcImpl

var ecC25519I31* {.importc: "br_ec_c25519_i31", header: "bearssl_ec.h".}: EcImpl

var ecC25519M15* {.importc: "br_ec_c25519_m15", header: "bearssl_ec.h".}: EcImpl

var ecC25519M31* {.importc: "br_ec_c25519_m31", header: "bearssl_ec.h".}: EcImpl

var ecAllM15* {.importc: "br_ec_all_m15", header: "bearssl_ec.h".}: EcImpl

var ecAllM31* {.importc: "br_ec_all_m31", header: "bearssl_ec.h".}: EcImpl

proc ecGetDefault*(): ptr EcImpl {.bearSslFunc, importc: "br_ec_get_default",
                               header: "bearssl_ec.h".}

proc ecdsaRawToAsn1*(sig: pointer; sigLen: int): int {.bearSslFunc,
    importc: "br_ecdsa_raw_to_asn1", header: "bearssl_ec.h".}

proc ecdsaAsn1ToRaw*(sig: pointer; sigLen: int): int {.bearSslFunc,
    importc: "br_ecdsa_asn1_to_raw", header: "bearssl_ec.h".}

type
  EcdsaSign* = proc (impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                  sk: ptr EcPrivateKey; sig: pointer): int {.bearSslFunc.}

type
  EcdsaVrfy* = proc (impl: ptr EcImpl; hash: pointer; hashLen: int; pk: ptr EcPublicKey;
                  sig: pointer; sigLen: int): uint32 {.bearSslFunc.}

proc ecdsaI31SignAsn1*(impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                      sk: ptr EcPrivateKey; sig: pointer): int {.bearSslFunc,
    importc: "br_ecdsa_i31_sign_asn1", header: "bearssl_ec.h".}

proc ecdsaI31SignRaw*(impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                     sk: ptr EcPrivateKey; sig: pointer): int {.bearSslFunc,
    importc: "br_ecdsa_i31_sign_raw", header: "bearssl_ec.h".}

proc ecdsaI31VrfyAsn1*(impl: ptr EcImpl; hash: pointer; hashLen: int;
                      pk: ptr EcPublicKey; sig: pointer; sigLen: int): uint32 {.
    bearSslFunc, importc: "br_ecdsa_i31_vrfy_asn1", header: "bearssl_ec.h".}

proc ecdsaI31VrfyRaw*(impl: ptr EcImpl; hash: pointer; hashLen: int;
                     pk: ptr EcPublicKey; sig: pointer; sigLen: int): uint32 {.bearSslFunc,
    importc: "br_ecdsa_i31_vrfy_raw", header: "bearssl_ec.h".}

proc ecdsaI15SignAsn1*(impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                      sk: ptr EcPrivateKey; sig: pointer): int {.bearSslFunc,
    importc: "br_ecdsa_i15_sign_asn1", header: "bearssl_ec.h".}

proc ecdsaI15SignRaw*(impl: ptr EcImpl; hf: ptr HashClass; hashValue: pointer;
                     sk: ptr EcPrivateKey; sig: pointer): int {.bearSslFunc,
    importc: "br_ecdsa_i15_sign_raw", header: "bearssl_ec.h".}

proc ecdsaI15VrfyAsn1*(impl: ptr EcImpl; hash: pointer; hashLen: int;
                      pk: ptr EcPublicKey; sig: pointer; sigLen: int): uint32 {.
    bearSslFunc, importc: "br_ecdsa_i15_vrfy_asn1", header: "bearssl_ec.h".}

proc ecdsaI15VrfyRaw*(impl: ptr EcImpl; hash: pointer; hashLen: int;
                     pk: ptr EcPublicKey; sig: pointer; sigLen: int): uint32 {.bearSslFunc,
    importc: "br_ecdsa_i15_vrfy_raw", header: "bearssl_ec.h".}

proc ecdsaSignAsn1GetDefault*(): EcdsaSign {.bearSslFunc,
    importc: "br_ecdsa_sign_asn1_get_default", header: "bearssl_ec.h".}

proc ecdsaSignRawGetDefault*(): EcdsaSign {.bearSslFunc,
    importc: "br_ecdsa_sign_raw_get_default", header: "bearssl_ec.h".}

proc ecdsaVrfyAsn1GetDefault*(): EcdsaVrfy {.bearSslFunc,
    importc: "br_ecdsa_vrfy_asn1_get_default", header: "bearssl_ec.h".}

proc ecdsaVrfyRawGetDefault*(): EcdsaVrfy {.bearSslFunc,
    importc: "br_ecdsa_vrfy_raw_get_default", header: "bearssl_ec.h".}

const
  ERR_X509_OK* = 32

const
  ERR_X509_INVALID_VALUE* = 33

const
  ERR_X509_TRUNCATED* = 34

const
  ERR_X509_EMPTY_CHAIN* = 35

const
  ERR_X509_INNER_TRUNC* = 36

const
  ERR_X509_BAD_TAG_CLASS* = 37

const
  ERR_X509_BAD_TAG_VALUE* = 38

const
  ERR_X509_INDEFINITE_LENGTH* = 39

const
  ERR_X509_EXTRA_ELEMENT* = 40

const
  ERR_X509_UNEXPECTED* = 41

const
  ERR_X509_NOT_CONSTRUCTED* = 42

const
  ERR_X509_NOT_PRIMITIVE* = 43

const
  ERR_X509_PARTIAL_BYTE* = 44

const
  ERR_X509_BAD_BOOLEAN* = 45

const
  ERR_X509_OVERFLOW* = 46

const
  ERR_X509_BAD_DN* = 47

const
  ERR_X509_BAD_TIME* = 48

const
  ERR_X509_UNSUPPORTED* = 49

const
  ERR_X509_LIMIT_EXCEEDED* = 50

const
  ERR_X509_WRONG_KEY_TYPE* = 51

const
  ERR_X509_BAD_SIGNATURE* = 52

const
  ERR_X509_TIME_UNKNOWN* = 53

const
  ERR_X509_EXPIRED* = 54

const
  ERR_X509_DN_MISMATCH* = 55

const
  ERR_X509_BAD_SERVER_NAME* = 56

const
  ERR_X509_CRITICAL_EXTENSION* = 57

const
  ERR_X509_NOT_CA* = 58

const
  ERR_X509_FORBIDDEN_KEY_USAGE* = 59

const
  ERR_X509_WEAK_PUBLIC_KEY* = 60

const
  ERR_X509_NOT_TRUSTED* = 62

type
  INNER_C_UNION_2211491720* {.importc: "no_name", header: "bearssl_x509.h",
                              bycopy, union.} = object
    rsa* {.importc: "rsa".}: RsaPublicKey
    ec* {.importc: "ec".}: EcPublicKey

  X509Pkey* {.importc: "br_x509_pkey", header: "bearssl_x509.h", bycopy.} = object
    keyType* {.importc: "key_type".}: cuchar
    key* {.importc: "key".}: INNER_C_UNION_2211491720


type
  X500Name* {.importc: "br_x500_name", header: "bearssl_x509.h", bycopy.} = object
    data* {.importc: "data".}: ptr cuchar
    len* {.importc: "len".}: int


type
  X509TrustAnchor* {.importc: "br_x509_trust_anchor", header: "bearssl_x509.h",
                    bycopy.} = object
    dn* {.importc: "dn".}: X500Name
    flags* {.importc: "flags".}: cuint
    pkey* {.importc: "pkey".}: X509Pkey


const
  X509_TA_CA* = 0x00000001

const
  KEYTYPE_RSA* = 1

const
  KEYTYPE_EC* = 2

const
  KEYTYPE_KEYX* = 0x00000010

const
  KEYTYPE_SIGN* = 0x00000020

type
  X509Class* {.importc: "br_x509_class", header: "bearssl_x509.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    startChain* {.importc: "start_chain".}: proc (ctx: ptr ptr X509Class;
        serverName: cstring) {.bearSslFunc.}
    startCert* {.importc: "start_cert".}: proc (ctx: ptr ptr X509Class; length: uint32) {.
        bearSslFunc.}
    append* {.importc: "append".}: proc (ctx: ptr ptr X509Class; buf: ptr cuchar;
                                     len: int) {.bearSslFunc.}
    endCert* {.importc: "end_cert".}: proc (ctx: ptr ptr X509Class) {.bearSslFunc.}
    endChain* {.importc: "end_chain".}: proc (ctx: ptr ptr X509Class): cuint {.bearSslFunc.}
    getPkey* {.importc: "get_pkey".}: proc (ctx: ptr ptr X509Class; usages: ptr cuint): ptr X509Pkey {.
        bearSslFunc.}

type
  X509KnownkeyContext* {.importc: "br_x509_knownkey_context",
                        header: "bearssl_x509.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class
    pkey* {.importc: "pkey".}: X509Pkey
    usages* {.importc: "usages".}: cuint


var x509KnownkeyVtable* {.importc: "br_x509_knownkey_vtable",
                        header: "bearssl_x509.h".}: X509Class

proc x509KnownkeyInitRsa*(ctx: ptr X509KnownkeyContext; pk: ptr RsaPublicKey;
                         usages: cuint) {.bearSslFunc,
                                        importc: "br_x509_knownkey_init_rsa",
                                        header: "bearssl_x509.h".}

proc x509KnownkeyInitEc*(ctx: ptr X509KnownkeyContext; pk: ptr EcPublicKey;
                        usages: cuint) {.bearSslFunc,
                                       importc: "br_x509_knownkey_init_ec",
                                       header: "bearssl_x509.h".}

const
  X509_BUFSIZE_KEY* = 520
  X509_BUFSIZE_SIG* = 512

type
  NameElement* {.importc: "br_name_element", header: "bearssl_x509.h", bycopy.} = object
    oid* {.importc: "oid".}: ptr cuchar
    buf* {.importc: "buf".}: cstring
    len* {.importc: "len".}: int
    status* {.importc: "status".}: cint


type
  INNER_C_STRUCT_573696436* {.importc: "no_name", header: "bearssl_x509.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr cuchar

  X509MinimalContext* {.importc: "br_x509_minimal_context",
                       header: "bearssl_x509.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class
    pkey* {.importc: "pkey".}: X509Pkey
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_573696436
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    serverName* {.importc: "server_name".}: cstring
    keyUsages* {.importc: "key_usages".}: cuchar
    days* {.importc: "days".}: uint32
    seconds* {.importc: "seconds".}: uint32
    certLength* {.importc: "cert_length".}: uint32
    numCerts* {.importc: "num_certs".}: uint32
    hbuf* {.importc: "hbuf".}: ptr cuchar
    hlen* {.importc: "hlen".}: int
    pad* {.importc: "pad".}: array[256, cuchar]
    eePkeyData* {.importc: "ee_pkey_data".}: array[X509_BUFSIZE_KEY, cuchar]
    pkeyData* {.importc: "pkey_data".}: array[X509_BUFSIZE_KEY, cuchar]
    certSignerKeyType* {.importc: "cert_signer_key_type".}: cuchar
    certSigHashOid* {.importc: "cert_sig_hash_oid".}: uint16
    certSigHashLen* {.importc: "cert_sig_hash_len".}: cuchar
    certSig* {.importc: "cert_sig".}: array[X509_BUFSIZE_SIG, cuchar]
    certSigLen* {.importc: "cert_sig_len".}: uint16
    minRsaSize* {.importc: "min_rsa_size".}: int16
    trustAnchors* {.importc: "trust_anchors".}: ptr X509TrustAnchor
    trustAnchorsNum* {.importc: "trust_anchors_num".}: int
    doMhash* {.importc: "do_mhash".}: cuchar
    mhash* {.importc: "mhash".}: MultihashContext
    tbsHash* {.importc: "tbs_hash".}: array[64, cuchar]
    doDnHash* {.importc: "do_dn_hash".}: cuchar
    dnHashImpl* {.importc: "dn_hash_impl".}: ptr HashClass
    dnHash* {.importc: "dn_hash".}: HashCompatContext
    currentDnHash* {.importc: "current_dn_hash".}: array[64, cuchar]
    nextDnHash* {.importc: "next_dn_hash".}: array[64, cuchar]
    savedDnHash* {.importc: "saved_dn_hash".}: array[64, cuchar]
    nameElts* {.importc: "name_elts".}: ptr NameElement
    numNameElts* {.importc: "num_name_elts".}: int
    irsa* {.importc: "irsa".}: RsaPkcs1Vrfy
    iecdsa* {.importc: "iecdsa".}: EcdsaVrfy
    iec* {.importc: "iec".}: ptr EcImpl


var x509MinimalVtable* {.importc: "br_x509_minimal_vtable", header: "bearssl_x509.h".}: X509Class

proc x509MinimalInit*(ctx: ptr X509MinimalContext; dnHashImpl: ptr HashClass;
                     trustAnchors: ptr X509TrustAnchor; trustAnchorsNum: int) {.
    bearSslFunc, importc: "br_x509_minimal_init", header: "bearssl_x509.h".}

proc x509MinimalSetHash*(ctx: ptr X509MinimalContext; id: cint; impl: ptr HashClass) {.
    inline.} =
  multihashSetimpl(addr(ctx.mhash), id, impl)

proc x509MinimalSetRsa*(ctx: ptr X509MinimalContext; irsa: RsaPkcs1Vrfy) {.inline,
    bearSslFunc.} =
  ctx.irsa = irsa

proc x509MinimalSetEcdsa*(ctx: ptr X509MinimalContext; iec: ptr EcImpl;
                         iecdsa: EcdsaVrfy) {.inline.} =
  ctx.iecdsa = iecdsa
  ctx.iec = iec

proc x509MinimalInitFull*(ctx: ptr X509MinimalContext;
                         trustAnchors: ptr X509TrustAnchor; trustAnchorsNum: int) {.
    bearSslFunc, importc: "br_x509_minimal_init_full", header: "bearssl_x509.h".}

proc x509MinimalSetTime*(ctx: ptr X509MinimalContext; days: uint32; seconds: uint32) {.
    inline.} =
  ctx.days = days
  ctx.seconds = seconds

proc x509MinimalSetMinrsa*(ctx: ptr X509MinimalContext; byteLength: cint) {.inline,
    bearSslFunc.} =
  ctx.minRsaSize = (int16)(byteLength - 128)

proc x509MinimalSetNameElements*(ctx: ptr X509MinimalContext; elts: ptr NameElement;
                                numElts: int) {.inline.} =
  ctx.nameElts = elts
  ctx.numNameElts = numElts

type
  INNER_C_STRUCT_161597942* {.importc: "no_name", header: "bearssl_x509.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr cuchar

  X509DecoderContext* {.importc: "br_x509_decoder_context",
                       header: "bearssl_x509.h", bycopy.} = object
    pkey* {.importc: "pkey".}: X509Pkey
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_161597942
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    pad* {.importc: "pad".}: array[256, cuchar]
    decoded* {.importc: "decoded".}: bool
    notbeforeDays* {.importc: "notbefore_days".}: uint32
    notbeforeSeconds* {.importc: "notbefore_seconds".}: uint32
    notafterDays* {.importc: "notafter_days".}: uint32
    notafterSeconds* {.importc: "notafter_seconds".}: uint32
    isCA* {.importc: "isCA".}: bool
    copyDn* {.importc: "copy_dn".}: cuchar
    appendDnCtx* {.importc: "append_dn_ctx".}: pointer
    appendDn* {.importc: "append_dn".}: proc (ctx: pointer; buf: pointer; len: int) {.
        bearSslFunc.}
    hbuf* {.importc: "hbuf".}: ptr cuchar
    hlen* {.importc: "hlen".}: int
    pkeyData* {.importc: "pkey_data".}: array[X509_BUFSIZE_KEY, cuchar]
    signerKeyType* {.importc: "signer_key_type".}: cuchar
    signerHashId* {.importc: "signer_hash_id".}: cuchar


proc x509DecoderInit*(ctx: ptr X509DecoderContext; appendDn: proc (ctx: pointer;
    buf: pointer; len: int) {.bearSslFunc.}; appendDnCtx: pointer) {.bearSslFunc,
    importc: "br_x509_decoder_init", header: "bearssl_x509.h".}

proc x509DecoderPush*(ctx: ptr X509DecoderContext; data: pointer; len: int) {.bearSslFunc,
    importc: "br_x509_decoder_push", header: "bearssl_x509.h".}

proc x509DecoderGetPkey*(ctx: ptr X509DecoderContext): ptr X509Pkey {.inline.} =
  if ctx.decoded and ctx.err == 0:
    return addr(ctx.pkey)
  else:
    return nil

proc x509DecoderLastError*(ctx: ptr X509DecoderContext): cint {.inline.} =
  if ctx.err != 0:
    return ctx.err
  if not ctx.decoded:
    return ERR_X509_TRUNCATED
  return 0

proc x509DecoderIsCA*(ctx: ptr X509DecoderContext): cint {.inline.} =
  return cint ctx.isCA

proc x509DecoderGetSignerKeyType*(ctx: ptr X509DecoderContext): cint {.inline.} =
  return cint ctx.signerKeyType

proc x509DecoderGetSignerHashId*(ctx: ptr X509DecoderContext): cint {.inline.} =
  return cint ctx.signerHashId

type
  X509Certificate* {.importc: "br_x509_certificate", header: "bearssl_x509.h", bycopy.} = object
    data* {.importc: "data".}: ptr cuchar
    dataLen* {.importc: "data_len".}: int


type
  INNER_C_UNION_3754611343* {.importc: "no_name", header: "bearssl_x509.h",
                              bycopy, union.} = object
    rsa* {.importc: "rsa".}: RsaPrivateKey
    ec* {.importc: "ec".}: EcPrivateKey

  INNER_C_STRUCT_3633027466* {.importc: "no_name", header: "bearssl_x509.h",
                               bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr cuchar

  SkeyDecoderContext* {.importc: "br_skey_decoder_context",
                       header: "bearssl_x509.h", bycopy.} = object
    key* {.importc: "key".}: INNER_C_UNION_3754611343
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_3633027466
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    hbuf* {.importc: "hbuf".}: ptr cuchar
    hlen* {.importc: "hlen".}: int
    pad* {.importc: "pad".}: array[256, cuchar]
    keyType* {.importc: "key_type".}: cuchar
    keyData* {.importc: "key_data".}: array[3 * X509_BUFSIZE_SIG, cuchar]


proc skeyDecoderInit*(ctx: ptr SkeyDecoderContext) {.bearSslFunc,
    importc: "br_skey_decoder_init", header: "bearssl_x509.h".}

proc skeyDecoderPush*(ctx: ptr SkeyDecoderContext; data: pointer; len: int) {.bearSslFunc,
    importc: "br_skey_decoder_push", header: "bearssl_x509.h".}

proc skeyDecoderLastError*(ctx: ptr SkeyDecoderContext): cint {.inline.} =
  if ctx.err != 0:
    return ctx.err
  if ctx.keyType == '\0'.cuchar:
    return ERR_X509_TRUNCATED
  return 0

proc skeyDecoderKeyType*(ctx: ptr SkeyDecoderContext): cint {.inline.} =
  if ctx.err == 0:
    return cint ctx.keyType
  else:
    return 0

const
  SSL_BUFSIZE_INPUT* = (16384 + 325)

const
  SSL_BUFSIZE_OUTPUT* = (16384 + 85)

const
  SSL_BUFSIZE_MONO* = SSL_BUFSIZE_INPUT

const
  SSL_BUFSIZE_BIDI* = (SSL_BUFSIZE_INPUT + SSL_BUFSIZE_OUTPUT)

const
  SSL30* = 0x00000300

const
  TLS10* = 0x00000301

const
  TLS11* = 0x00000302

const
  TLS12* = 0x00000303

const
  ERR_OK* = 0

const
  ERR_BAD_PARAM* = 1

const
  ERR_BAD_STATE* = 2

const
  ERR_UNSUPPORTED_VERSION* = 3

const
  ERR_BAD_VERSION* = 4

const
  ERR_BAD_LENGTH* = 5

const
  ERR_TOO_LARGE* = 6

const
  ERR_BAD_MAC* = 7

const
  ERR_NO_RANDOM* = 8

const
  ERR_UNKNOWN_TYPE* = 9

const
  ERR_UNEXPECTED* = 10

const
  ERR_BAD_CCS* = 12

const
  ERR_BAD_ALERT* = 13

const
  ERR_BAD_HANDSHAKE* = 14

const
  ERR_OVERSIZED_ID* = 15

const
  ERR_BAD_CIPHER_SUITE* = 16

const
  ERR_BAD_COMPRESSION* = 17

const
  ERR_BAD_FRAGLEN* = 18

const
  ERR_BAD_SECRENEG* = 19

const
  ERR_EXTRA_EXTENSION* = 20

const
  ERR_BAD_SNI* = 21

const
  ERR_BAD_HELLO_DONE* = 22

const
  ERR_LIMIT_EXCEEDED* = 23

const
  ERR_BAD_FINISHED* = 24

const
  ERR_RESUME_MISMATCH* = 25

const
  ERR_INVALID_ALGORITHM* = 26

const
  ERR_BAD_SIGNATURE* = 27

const
  ERR_WRONG_KEY_USAGE* = 28

const
  ERR_NO_CLIENT_AUTH* = 29

const
  ERR_IO* = 31

const
  ERR_RECV_FATAL_ALERT* = 256

const
  ERR_SEND_FATAL_ALERT* = 512

type
  SslrecInClass* {.importc: "br_sslrec_in_class", header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    checkLength* {.importc: "check_length".}: proc (ctx: ptr ptr SslrecInClass;
        recordLen: int): cint {.bearSslFunc.}
    decrypt* {.importc: "decrypt".}: proc (ctx: ptr ptr SslrecInClass; recordType: cint;
                                       version: cuint; payload: pointer;
                                       len: ptr int): ptr cuchar {.bearSslFunc.}

type
  SslrecOutClass* {.importc: "br_sslrec_out_class", header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    maxPlaintext* {.importc: "max_plaintext".}: proc (ctx: ptr ptr SslrecOutClass;
        start: ptr int; `end`: ptr int) {.bearSslFunc.}
    encrypt* {.importc: "encrypt".}: proc (ctx: ptr ptr SslrecOutClass;
                                       recordType: cint; version: cuint;
                                       plaintext: pointer; len: ptr int): ptr cuchar {.
        bearSslFunc.}

type
  SslrecOutClearContext* {.importc: "br_sslrec_out_clear_context",
                          header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslrecOutClass


var sslrecOutClearVtable* {.importc: "br_sslrec_out_clear_vtable",
                          header: "bearssl_ssl.h".}: SslrecOutClass

type
  SslrecInCbcClass* {.importc: "br_sslrec_in_cbc_class", header: "bearssl_ssl.h",
                     bycopy.} = object
    inner* {.importc: "inner".}: SslrecInClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecInCbcClass;
                                 bcImpl: ptr BlockCbcdecClass; bcKey: pointer;
                                 bcKeyLen: int; digImpl: ptr HashClass;
                                 macKey: pointer; macKeyLen: int;
                                 macOutLen: int; iv: pointer) {.bearSslFunc.}

type
  SslrecOutCbcClass* {.importc: "br_sslrec_out_cbc_class",
                      header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecOutCbcClass;
                                 bcImpl: ptr BlockCbcencClass; bcKey: pointer;
                                 bcKeyLen: int; digImpl: ptr HashClass;
                                 macKey: pointer; macKeyLen: int;
                                 macOutLen: int; iv: pointer) {.bearSslFunc.}

type
  INNER_C_UNION_2105460304* {.importc: "no_name", header: "bearssl_ssl.h",
                              bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    aes* {.importc: "aes".}: AesGenCbcdecKeys
    des* {.importc: "des".}: DesGenCbcdecKeys

  SslrecInCbcContext* {.importc: "br_sslrec_in_cbc_context",
                       header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslrecInCbcClass
    seq* {.importc: "seq".}: uint64
    bc* {.importc: "bc".}: INNER_C_UNION_2105460304
    mac* {.importc: "mac".}: HmacKeyContext
    macLen* {.importc: "mac_len".}: int
    iv* {.importc: "iv".}: array[16, cuchar]
    explicitIV* {.importc: "explicit_IV".}: cint


var sslrecInCbcVtable* {.importc: "br_sslrec_in_cbc_vtable", header: "bearssl_ssl.h".}: SslrecInCbcClass

type
  INNER_C_UNION_3724465237* {.importc: "no_name", header: "bearssl_ssl.h",
                              bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    aes* {.importc: "aes".}: AesGenCbcencKeys
    des* {.importc: "des".}: DesGenCbcencKeys

  SslrecOutCbcContext* {.importc: "br_sslrec_out_cbc_context",
                        header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslrecOutCbcClass
    seq* {.importc: "seq".}: uint64
    bc* {.importc: "bc".}: INNER_C_UNION_3724465237
    mac* {.importc: "mac".}: HmacKeyContext
    macLen* {.importc: "mac_len".}: int
    iv* {.importc: "iv".}: array[16, cuchar]
    explicitIV* {.importc: "explicit_IV".}: cint


var sslrecOutCbcVtable* {.importc: "br_sslrec_out_cbc_vtable",
                        header: "bearssl_ssl.h".}: SslrecOutCbcClass

type
  SslrecInGcmClass* {.importc: "br_sslrec_in_gcm_class", header: "bearssl_ssl.h",
                     bycopy.} = object
    inner* {.importc: "inner".}: SslrecInClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecInGcmClass;
                                 bcImpl: ptr BlockCtrClass; key: pointer;
                                 keyLen: int; ghImpl: Ghash; iv: pointer) {.bearSslFunc.}

type
  SslrecOutGcmClass* {.importc: "br_sslrec_out_gcm_class",
                      header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecOutGcmClass;
                                 bcImpl: ptr BlockCtrClass; key: pointer;
                                 keyLen: int; ghImpl: Ghash; iv: pointer) {.bearSslFunc.}

type
  INNER_C_UNION_536016210* {.importc: "no_name", header: "bearssl_ssl.h",
                             bycopy, union.} = object
    gen* {.importc: "gen".}: pointer
    `in`* {.importc: "in".}: ptr SslrecInGcmClass
    `out`* {.importc: "out".}: ptr SslrecOutGcmClass

  INNER_C_UNION_1283557389* {.importc: "no_name", header: "bearssl_ssl.h",
                              bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    aes* {.importc: "aes".}: AesGenCtrKeys

  SslrecGcmContext* {.importc: "br_sslrec_gcm_context", header: "bearssl_ssl.h",
                     bycopy.} = object
    vtable* {.importc: "vtable".}: INNER_C_UNION_536016210
    seq* {.importc: "seq".}: uint64
    bc* {.importc: "bc".}: INNER_C_UNION_1283557389
    gh* {.importc: "gh".}: Ghash
    iv* {.importc: "iv".}: array[4, cuchar]
    h* {.importc: "h".}: array[16, cuchar]


var sslrecInGcmVtable* {.importc: "br_sslrec_in_gcm_vtable", header: "bearssl_ssl.h".}: SslrecInGcmClass

var sslrecOutGcmVtable* {.importc: "br_sslrec_out_gcm_vtable",
                        header: "bearssl_ssl.h".}: SslrecOutGcmClass

type
  SslrecInChapolClass* {.importc: "br_sslrec_in_chapol_class",
                        header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecInClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecInChapolClass;
                                 ichacha: Chacha20Run; ipoly: Poly1305Run;
                                 key: pointer; iv: pointer) {.bearSslFunc.}

type
  SslrecOutChapolClass* {.importc: "br_sslrec_out_chapol_class",
                         header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecOutChapolClass;
                                 ichacha: Chacha20Run; ipoly: Poly1305Run;
                                 key: pointer; iv: pointer) {.bearSslFunc.}

type
  INNER_C_UNION_1683842004* {.importc: "no_name", header: "bearssl_ssl.h",
                              bycopy, union.} = object
    gen* {.importc: "gen".}: pointer
    `in`* {.importc: "in".}: ptr SslrecInChapolClass
    `out`* {.importc: "out".}: ptr SslrecOutChapolClass

  SslrecChapolContext* {.importc: "br_sslrec_chapol_context",
                        header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: INNER_C_UNION_1683842004
    seq* {.importc: "seq".}: uint64
    key* {.importc: "key".}: array[32, cuchar]
    iv* {.importc: "iv".}: array[12, cuchar]
    ichacha* {.importc: "ichacha".}: Chacha20Run
    ipoly* {.importc: "ipoly".}: Poly1305Run


var sslrecInChapolVtable* {.importc: "br_sslrec_in_chapol_vtable",
                          header: "bearssl_ssl.h".}: SslrecInChapolClass

var sslrecOutChapolVtable* {.importc: "br_sslrec_out_chapol_vtable",
                           header: "bearssl_ssl.h".}: SslrecOutChapolClass

type
  SslSessionParameters* {.importc: "br_ssl_session_parameters",
                         header: "bearssl_ssl.h", bycopy.} = object
    sessionId* {.importc: "session_id".}: array[32, cuchar]
    sessionIdLen* {.importc: "session_id_len".}: byte
    version* {.importc: "version".}: uint16
    cipherSuite* {.importc: "cipher_suite".}: uint16
    masterSecret* {.importc: "master_secret".}: array[48, cuchar]


const
  MAX_CIPHER_SUITES* = 40

type
  INNER_C_UNION_861939089* {.importc: "no_name", header: "bearssl_ssl.h",
                             bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr SslrecInClass
    cbc* {.importc: "cbc".}: SslrecInCbcContext
    gcm* {.importc: "gcm".}: SslrecGcmContext
    chapol* {.importc: "chapol".}: SslrecChapolContext

  INNER_C_UNION_1609480268* {.importc: "no_name", header: "bearssl_ssl.h",
                              bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr SslrecOutClass
    clear* {.importc: "clear".}: SslrecOutClearContext
    cbc* {.importc: "cbc".}: SslrecOutCbcContext
    gcm* {.importc: "gcm".}: SslrecGcmContext
    chapol* {.importc: "chapol".}: SslrecChapolContext

  INNER_C_STRUCT_671658464* {.importc: "no_name", header: "bearssl_ssl.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr cuchar

  SslEngineContext* {.importc: "br_ssl_engine_context", header: "bearssl_ssl.h",
                     bycopy.} = object
    err* {.importc: "err".}: cint
    ibuf* {.importc: "ibuf".}: ptr cuchar
    obuf* {.importc: "obuf".}: ptr cuchar
    ibufLen* {.importc: "ibuf_len".}: int
    obufLen* {.importc: "obuf_len".}: int
    maxFragLen* {.importc: "max_frag_len".}: uint16
    logMaxFragLen* {.importc: "log_max_frag_len".}: cuchar
    peerLogMaxFragLen* {.importc: "peer_log_max_frag_len".}: cuchar
    ixa* {.importc: "ixa".}: int
    ixb* {.importc: "ixb".}: int
    ixc* {.importc: "ixc".}: int
    oxa* {.importc: "oxa".}: int
    oxb* {.importc: "oxb".}: int
    oxc* {.importc: "oxc".}: int
    iomode* {.importc: "iomode".}: cuchar
    incrypt* {.importc: "incrypt".}: cuchar
    shutdownRecv* {.importc: "shutdown_recv".}: cuchar
    recordTypeIn* {.importc: "record_type_in".}: cuchar
    recordTypeOut* {.importc: "record_type_out".}: cuchar
    versionIn* {.importc: "version_in".}: uint16
    versionOut* {.importc: "version_out".}: uint16
    `in`* {.importc: "in".}: INNER_C_UNION_861939089
    `out`* {.importc: "out".}: INNER_C_UNION_1609480268
    applicationData* {.importc: "application_data".}: cuchar
    rng* {.importc: "rng".}: HmacDrbgContext
    rngInitDone* {.importc: "rng_init_done".}: cint
    rngOsRandDone* {.importc: "rng_os_rand_done".}: cint
    versionMin* {.importc: "version_min".}: uint16
    versionMax* {.importc: "version_max".}: uint16
    suitesBuf* {.importc: "suites_buf".}: array[MAX_CIPHER_SUITES, uint16]
    suitesNum* {.importc: "suites_num".}: cuchar
    serverName* {.importc: "server_name".}: array[256, char]
    clientRandom* {.importc: "client_random".}: array[32, cuchar]
    serverRandom* {.importc: "server_random".}: array[32, cuchar]
    session* {.importc: "session".}: SslSessionParameters
    ecdheCurve* {.importc: "ecdhe_curve".}: cuchar
    ecdhePoint* {.importc: "ecdhe_point".}: array[133, cuchar]
    ecdhePointLen* {.importc: "ecdhe_point_len".}: cuchar
    reneg* {.importc: "reneg".}: cuchar
    savedFinished* {.importc: "saved_finished".}: array[24, cuchar]
    flags* {.importc: "flags".}: uint32
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_671658464
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    pad* {.importc: "pad".}: array[512, cuchar]
    hbufIn* {.importc: "hbuf_in".}: ptr cuchar
    hbufOut* {.importc: "hbuf_out".}: ptr cuchar
    savedHbufOut* {.importc: "saved_hbuf_out".}: ptr cuchar
    hlenIn* {.importc: "hlen_in".}: int
    hlenOut* {.importc: "hlen_out".}: int
    hsrun* {.importc: "hsrun".}: proc (ctx: pointer) {.bearSslFunc.}
    action* {.importc: "action".}: cuchar
    alert* {.importc: "alert".}: cuchar
    closeReceived* {.importc: "close_received".}: cuchar
    mhash* {.importc: "mhash".}: MultihashContext
    x509ctx* {.importc: "x509ctx".}: ptr ptr X509Class
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: int
    certCur* {.importc: "cert_cur".}: ptr cuchar
    certLen* {.importc: "cert_len".}: int
    protocolNames* {.importc: "protocol_names".}: cstringArray
    protocolNamesNum* {.importc: "protocol_names_num".}: uint16
    selectedProtocol* {.importc: "selected_protocol".}: uint16
    prf10* {.importc: "prf10".}: TlsPrfImpl
    prfSha256* {.importc: "prf_sha256".}: TlsPrfImpl
    prfSha384* {.importc: "prf_sha384".}: TlsPrfImpl
    iaesCbcenc* {.importc: "iaes_cbcenc".}: ptr BlockCbcencClass
    iaesCbcdec* {.importc: "iaes_cbcdec".}: ptr BlockCbcdecClass
    iaesCtr* {.importc: "iaes_ctr".}: ptr BlockCtrClass
    idesCbcenc* {.importc: "ides_cbcenc".}: ptr BlockCbcencClass
    idesCbcdec* {.importc: "ides_cbcdec".}: ptr BlockCbcdecClass
    ighash* {.importc: "ighash".}: Ghash
    ichacha* {.importc: "ichacha".}: Chacha20Run
    ipoly* {.importc: "ipoly".}: Poly1305Run
    icbcIn* {.importc: "icbc_in".}: ptr SslrecInCbcClass
    icbcOut* {.importc: "icbc_out".}: ptr SslrecOutCbcClass
    igcmIn* {.importc: "igcm_in".}: ptr SslrecInGcmClass
    igcmOut* {.importc: "igcm_out".}: ptr SslrecOutGcmClass
    ichapolIn* {.importc: "ichapol_in".}: ptr SslrecInChapolClass
    ichapolOut* {.importc: "ichapol_out".}: ptr SslrecOutChapolClass
    iec* {.importc: "iec".}: ptr EcImpl
    irsavrfy* {.importc: "irsavrfy".}: RsaPkcs1Vrfy
    iecdsa* {.importc: "iecdsa".}: EcdsaVrfy


proc sslEngineGetFlags*(cc: ptr SslEngineContext): uint32 {.inline.} =
  return cc.flags

proc sslEngineSetAllFlags*(cc: ptr SslEngineContext; flags: uint32) {.inline.} =
  cc.flags = flags

proc sslEngineAddFlags*(cc: ptr SslEngineContext; flags: uint32) {.inline.} =
  cc.flags = cc.flags or flags

proc sslEngineRemoveFlags*(cc: ptr SslEngineContext; flags: uint32) {.inline.} =
  cc.flags = cc.flags and not flags

const
  OPT_ENFORCE_SERVER_PREFERENCES* = (1'u32 shl 0)

const
  OPT_NO_RENEGOTIATION* = (1'u32 shl 1)

const
  OPT_TOLERATE_NO_CLIENT_AUTH* = (1'u32 shl 2)

const
  OPT_FAIL_ON_ALPN_MISMATCH* = (1'u32 shl 3)

proc sslEngineSetVersions*(cc: ptr SslEngineContext; versionMin: uint16;
                          versionMax: uint16) {.inline.} =
  cc.versionMin = versionMin
  cc.versionMax = versionMax

proc sslEngineSetSuites*(cc: ptr SslEngineContext; suites: ptr uint16;
                        suitesNum: int) {.bearSslFunc,
    importc: "br_ssl_engine_set_suites", header: "bearssl_ssl.h".}

proc sslEngineSetX509*(cc: ptr SslEngineContext; x509ctx: ptr ptr X509Class) {.inline,
    bearSslFunc.} =
  cc.x509ctx = x509ctx

proc sslEngineSetProtocolNames*(ctx: ptr SslEngineContext; names: cstringArray;
                               num: int) {.inline.} =
  ctx.protocolNames = names
  ctx.protocolNamesNum = uint16 num

proc sslEngineGetSelectedProtocol*(ctx: ptr SslEngineContext): cstring {.inline.} =
  var k: cuint
  k = ctx.selectedProtocol
  return if (k == 0 or k == 0x0000FFFF): nil else: ctx.protocolNames[k - 1]

proc sslEngineSetHash*(ctx: ptr SslEngineContext; id: cint; impl: ptr HashClass) {.
    inline.} =
  multihashSetimpl(addr(ctx.mhash), id, impl)

proc sslEngineGetHash*(ctx: ptr SslEngineContext; id: cint): ptr HashClass {.inline,
    bearSslFunc.} =
  return multihashGetimpl(addr(ctx.mhash), id)

proc sslEngineSetPrf10*(cc: ptr SslEngineContext; impl: TlsPrfImpl) {.inline.} =
  cc.prf10 = impl

proc sslEngineSetPrfSha256*(cc: ptr SslEngineContext; impl: TlsPrfImpl) {.inline.} =
  cc.prfSha256 = impl

proc sslEngineSetPrfSha384*(cc: ptr SslEngineContext; impl: TlsPrfImpl) {.inline.} =
  cc.prfSha384 = impl

proc sslEngineSetAesCbc*(cc: ptr SslEngineContext; implEnc: ptr BlockCbcencClass;
                        implDec: ptr BlockCbcdecClass) {.inline.} =
  cc.iaesCbcenc = implEnc
  cc.iaesCbcdec = implDec

proc sslEngineSetDefaultAesCbc*(cc: ptr SslEngineContext) {.bearSslFunc,
    importc: "br_ssl_engine_set_default_aes_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetAesCtr*(cc: ptr SslEngineContext; impl: ptr BlockCtrClass) {.inline,
    bearSslFunc.} =
  cc.iaesCtr = impl

proc sslEngineSetDefaultAesGcm*(cc: ptr SslEngineContext) {.bearSslFunc,
    importc: "br_ssl_engine_set_default_aes_gcm", header: "bearssl_ssl.h".}

proc sslEngineSetDesCbc*(cc: ptr SslEngineContext; implEnc: ptr BlockCbcencClass;
                        implDec: ptr BlockCbcdecClass) {.inline.} =
  cc.idesCbcenc = implEnc
  cc.idesCbcdec = implDec

proc sslEngineSetDefaultDesCbc*(cc: ptr SslEngineContext) {.bearSslFunc,
    importc: "br_ssl_engine_set_default_des_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetGhash*(cc: ptr SslEngineContext; impl: Ghash) {.inline.} =
  cc.ighash = impl

proc sslEngineSetChacha20*(cc: ptr SslEngineContext; ichacha: Chacha20Run) {.inline,
    bearSslFunc.} =
  cc.ichacha = ichacha

proc sslEngineSetPoly1305*(cc: ptr SslEngineContext; ipoly: Poly1305Run) {.inline,
    bearSslFunc.} =
  cc.ipoly = ipoly

proc sslEngineSetDefaultChapol*(cc: ptr SslEngineContext) {.bearSslFunc,
    importc: "br_ssl_engine_set_default_chapol", header: "bearssl_ssl.h".}

proc sslEngineSetCbc*(cc: ptr SslEngineContext; implIn: ptr SslrecInCbcClass;
                     implOut: ptr SslrecOutCbcClass) {.inline.} =
  cc.icbcIn = implIn
  cc.icbcOut = implOut

proc sslEngineSetGcm*(cc: ptr SslEngineContext; implIn: ptr SslrecInGcmClass;
                     implOut: ptr SslrecOutGcmClass) {.inline.} =
  cc.igcmIn = implIn
  cc.igcmOut = implOut

proc sslEngineSetChapol*(cc: ptr SslEngineContext; implIn: ptr SslrecInChapolClass;
                        implOut: ptr SslrecOutChapolClass) {.inline.} =
  cc.ichapolIn = implIn
  cc.ichapolOut = implOut

proc sslEngineSetEc*(cc: ptr SslEngineContext; iec: ptr EcImpl) {.inline.} =
  cc.iec = iec

proc sslEngineSetDefaultEc*(cc: ptr SslEngineContext) {.bearSslFunc,
    importc: "br_ssl_engine_set_default_ec", header: "bearssl_ssl.h".}

proc sslEngineGetEc*(cc: ptr SslEngineContext): ptr EcImpl {.inline.} =
  return cc.iec

proc sslEngineSetRsavrfy*(cc: ptr SslEngineContext; irsavrfy: RsaPkcs1Vrfy) {.inline,
    bearSslFunc.} =
  cc.irsavrfy = irsavrfy

proc sslEngineSetDefaultRsavrfy*(cc: ptr SslEngineContext) {.bearSslFunc,
    importc: "br_ssl_engine_set_default_rsavrfy", header: "bearssl_ssl.h".}

proc sslEngineGetRsavrfy*(cc: ptr SslEngineContext): RsaPkcs1Vrfy {.inline.} =
  return cc.irsavrfy

proc sslEngineSetEcdsa*(cc: ptr SslEngineContext; iecdsa: EcdsaVrfy) {.inline.} =
  cc.iecdsa = iecdsa

proc sslEngineSetDefaultEcdsa*(cc: ptr SslEngineContext) {.bearSslFunc,
    importc: "br_ssl_engine_set_default_ecdsa", header: "bearssl_ssl.h".}

proc sslEngineGetEcdsa*(cc: ptr SslEngineContext): EcdsaVrfy {.inline.} =
  return cc.iecdsa

proc sslEngineSetBuffer*(cc: ptr SslEngineContext, iobuf: ptr byte,
                         iobufLen: uint, bidi: cint) {.
     bearSslFunc, importc: "br_ssl_engine_set_buffer", header: "bearssl_ssl.h".}

proc sslEngineSetBuffersBidi*(cc: ptr SslEngineContext, ibuf: ptr byte,
                              ibufLen: uint, obuf: ptr byte, obufLen: uint) {.
    bearSslFunc, importc: "br_ssl_engine_set_buffers_bidi", header: "bearssl_ssl.h".}

proc sslEngineInjectEntropy*(cc: ptr SslEngineContext; data: pointer; len: int) {.
    bearSslFunc, importc: "br_ssl_engine_inject_entropy", header: "bearssl_ssl.h".}

proc sslEngineGetServerName*(cc: ptr SslEngineContext): cstring {.inline.} =
  return addr cc.serverName

proc sslEngineGetVersion*(cc: ptr SslEngineContext): cuint {.inline.} =
  return cc.session.version

proc sslEngineGetSessionParameters*(cc: ptr SslEngineContext;
                                   pp: ptr SslSessionParameters) {.inline.} =
  copyMem(pp, addr(cc.session), sizeof(pp[]))

proc sslEngineSetSessionParameters*(cc: ptr SslEngineContext;
                                   pp: ptr SslSessionParameters) {.inline.} =
  copyMem(addr(cc.session), pp, sizeof(pp[]))

proc sslEngineGetEcdheCurve*(cc: ptr SslEngineContext): cint {.inline.} =
  return cint cc.ecdheCurve

proc sslEngineCurrentState*(cc: ptr SslEngineContext): cuint {.bearSslFunc,
    importc: "br_ssl_engine_current_state", header: "bearssl_ssl.h".}

const
  SSL_CLOSED* = 0x00000001

const
  SSL_SENDREC* = 0x00000002

const
  SSL_RECVREC* = 0x00000004

const
  SSL_SENDAPP* = 0x00000008

const
  SSL_RECVAPP* = 0x00000010

proc sslEngineLastError*(cc: ptr SslEngineContext): cint {.inline.} =
  return cc.err

proc sslEngineSendappBuf*(cc: ptr SslEngineContext,
                          length: var uint): ptr byte {.
     bearSslFunc, importc: "br_ssl_engine_sendapp_buf", header: "bearssl_ssl.h".}

proc sslEngineSendappAck*(cc: ptr SslEngineContext,
                          length: uint) {.
     bearSslFunc, importc: "br_ssl_engine_sendapp_ack", header: "bearssl_ssl.h".}

proc sslEngineRecvappBuf*(cc: ptr SslEngineContext,
                          length: var uint): ptr byte {.
     bearSslFunc, importc: "br_ssl_engine_recvapp_buf", header: "bearssl_ssl.h".}

proc sslEngineRecvappAck*(cc: ptr SslEngineContext,
                          length: uint) {.
     bearSslFunc, importc: "br_ssl_engine_recvapp_ack", header: "bearssl_ssl.h".}

proc sslEngineSendrecBuf*(cc: ptr SslEngineContext,
                          length: var uint): ptr byte {.
     bearSslFunc, importc: "br_ssl_engine_sendrec_buf", header: "bearssl_ssl.h".}

proc sslEngineSendrecAck*(cc: ptr SslEngineContext,
                          length: uint) {.
     bearSslFunc, importc: "br_ssl_engine_sendrec_ack", header: "bearssl_ssl.h".}

proc sslEngineRecvrecBuf*(cc: ptr SslEngineContext,
                          length: var uint): ptr byte {.
     bearSslFunc, importc: "br_ssl_engine_recvrec_buf", header: "bearssl_ssl.h".}

proc sslEngineRecvrecAck*(cc: ptr SslEngineContext; length: uint) {.
     bearSslFunc, importc: "br_ssl_engine_recvrec_ack", header: "bearssl_ssl.h".}

proc sslEngineFlush*(cc: ptr SslEngineContext; force: cint) {.
     bearSslFunc, importc: "br_ssl_engine_flush", header: "bearssl_ssl.h".}

proc sslEngineClose*(cc: ptr SslEngineContext) {.
     bearSslFunc, importc: "br_ssl_engine_close", header: "bearssl_ssl.h".}

proc sslEngineRenegotiate*(cc: ptr SslEngineContext): cint {.
    bearSslFunc, importc: "br_ssl_engine_renegotiate", header: "bearssl_ssl.h".}

proc sslKeyExport*(cc: ptr SslEngineContext; dst: pointer; len: int; label: cstring;
                   context: pointer; contextLen: int): cint {.bearSslFunc,
    importc: "br_ssl_key_export", header: "bearssl_ssl.h".}

type
  SslClientCertificate* {.importc: "br_ssl_client_certificate",
                         header: "bearssl_ssl.h", bycopy.} = object
    authType* {.importc: "auth_type".}: cint
    hashId* {.importc: "hash_id".}: cint
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: int


const
  AUTH_ECDH* = 0

const
  AUTH_RSA* = 1

const
  AUTH_ECDSA* = 3

type
  INNER_C_UNION_2478042450* {.importc: "no_name", header: "bearssl_ssl.h",
                              bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr SslClientCertificateClass
    singleRsa* {.importc: "single_rsa".}: SslClientCertificateRsaContext
    singleEc* {.importc: "single_ec".}: SslClientCertificateEcContext

  SslClientContext* {.importc: "br_ssl_client_context", header: "bearssl_ssl.h",
                     bycopy.} = object
    eng* {.importc: "eng".}: SslEngineContext
    minClienthelloLen* {.importc: "min_clienthello_len".}: uint16
    hashes* {.importc: "hashes".}: uint32
    serverCurve* {.importc: "server_curve".}: cint
    clientAuthVtable* {.importc: "client_auth_vtable".}: ptr ptr SslClientCertificateClass
    authType* {.importc: "auth_type".}: cuchar
    hashId* {.importc: "hash_id".}: cuchar
    clientAuth* {.importc: "client_auth".}: INNER_C_UNION_2478042450
    irsapub* {.importc: "irsapub".}: RsaPublic

  SslClientCertificateClass* {.importc: "br_ssl_client_certificate_class",
                              header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    startNameList* {.importc: "start_name_list".}: proc (
        pctx: ptr ptr SslClientCertificateClass) {.bearSslFunc.}
    startName* {.importc: "start_name".}: proc (
        pctx: ptr ptr SslClientCertificateClass; len: int) {.bearSslFunc.}
    appendName* {.importc: "append_name".}: proc (
        pctx: ptr ptr SslClientCertificateClass; data: ptr cuchar; len: int) {.bearSslFunc.}
    endName* {.importc: "end_name".}: proc (pctx: ptr ptr SslClientCertificateClass) {.
        bearSslFunc.}
    endNameList* {.importc: "end_name_list".}: proc (
        pctx: ptr ptr SslClientCertificateClass) {.bearSslFunc.}
    choose* {.importc: "choose".}: proc (pctx: ptr ptr SslClientCertificateClass;
                                     cc: ptr SslClientContext; authTypes: uint32;
                                     choices: ptr SslClientCertificate) {.bearSslFunc.}
    doKeyx* {.importc: "do_keyx".}: proc (pctx: ptr ptr SslClientCertificateClass;
                                      data: ptr cuchar; len: ptr int): uint32 {.
        bearSslFunc.}
    doSign* {.importc: "do_sign".}: proc (pctx: ptr ptr SslClientCertificateClass;
                                      hashId: cint; hvLen: int; data: ptr cuchar;
                                      len: int): int {.bearSslFunc.}

  SslClientCertificateRsaContext* {.importc: "br_ssl_client_certificate_rsa_context",
                                   header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslClientCertificateClass
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: int
    sk* {.importc: "sk".}: ptr RsaPrivateKey
    irsasign* {.importc: "irsasign".}: RsaPkcs1Sign

  SslClientCertificateEcContext* {.importc: "br_ssl_client_certificate_ec_context",
                                  header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslClientCertificateClass
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: int
    sk* {.importc: "sk".}: ptr EcPrivateKey
    allowedUsages* {.importc: "allowed_usages".}: cuint
    issuerKeyType* {.importc: "issuer_key_type".}: cuint
    mhash* {.importc: "mhash".}: ptr MultihashContext
    iec* {.importc: "iec".}: ptr EcImpl
    iecdsa* {.importc: "iecdsa".}: EcdsaSign



proc sslClientGetServerHashes*(cc: ptr SslClientContext): uint32 {.inline.} =
  return cc.hashes

proc sslClientGetServerCurve*(cc: ptr SslClientContext): cint {.inline.} =
  return cc.serverCurve

proc sslClientInitFull*(cc: ptr SslClientContext; xc: ptr X509MinimalContext;
                       trustAnchors: ptr X509TrustAnchor; trustAnchorsNum: int) {.
    bearSslFunc, importc: "br_ssl_client_init_full", header: "bearssl_ssl.h".}

proc sslClientZero*(cc: ptr SslClientContext) {.bearSslFunc, importc: "br_ssl_client_zero",
    header: "bearssl_ssl.h".}

proc sslClientSetClientCertificate*(cc: ptr SslClientContext;
                                   pctx: ptr ptr SslClientCertificateClass) {.
    inline.} =
  cc.clientAuthVtable = pctx

proc sslClientSetRsapub*(cc: ptr SslClientContext; irsapub: RsaPublic) {.inline.} =
  cc.irsapub = irsapub

proc sslClientSetDefaultRsapub*(cc: ptr SslClientContext) {.bearSslFunc,
    importc: "br_ssl_client_set_default_rsapub", header: "bearssl_ssl.h".}

proc sslClientSetMinClienthelloLen*(cc: ptr SslClientContext; len: uint16) {.inline,
    bearSslFunc.} =
  cc.minClienthelloLen = len

proc sslClientReset*(cc: ptr SslClientContext; serverName: cstring;
                    resumeSession: cint): cint {.bearSslFunc,
    importc: "br_ssl_client_reset", header: "bearssl_ssl.h".}

proc sslClientForgetSession*(cc: ptr SslClientContext) {.inline.} =
  cc.eng.session.sessionIdLen = 0

proc sslClientSetSingleRsa*(cc: ptr SslClientContext; chain: ptr X509Certificate;
                           chainLen: int; sk: ptr RsaPrivateKey;
                           irsasign: RsaPkcs1Sign) {.bearSslFunc,
    importc: "br_ssl_client_set_single_rsa", header: "bearssl_ssl.h".}

proc sslClientSetSingleEc*(cc: ptr SslClientContext; chain: ptr X509Certificate;
                          chainLen: int; sk: ptr EcPrivateKey;
                          allowedUsages: cuint; certIssuerKeyType: cuint;
                          iec: ptr EcImpl; iecdsa: EcdsaSign) {.bearSslFunc,
    importc: "br_ssl_client_set_single_ec", header: "bearssl_ssl.h".}

type
  SuiteTranslated* = array[2, uint16]

when not defined(DOXYGEN_IGNORE):
  const
    SSLKEYX_RSA* = 0
    SSLKEYX_ECDHE_RSA* = 1
    SSLKEYX_ECDHE_ECDSA* = 2
    SSLKEYX_ECDH_RSA* = 3
    SSLKEYX_ECDH_ECDSA* = 4
    SSLENC_3DES_CBC* = 0
    SSLENC_AES128_CBC* = 1
    SSLENC_AES256_CBC* = 2
    SSLENC_AES128_GCM* = 3
    SSLENC_AES256_GCM* = 4
    SSLENC_CHACHA20* = 5
    SSLMAC_AEAD* = 0
    SSLMAC_SHA1* = sha1ID
    SSLMAC_SHA256* = sha256ID
    SSLMAC_SHA384* = sha384ID
    SSLPRF_SHA256* = sha256ID
    SSLPRF_SHA384* = sha384ID

type
  SslServerChoices* {.importc: "br_ssl_server_choices", header: "bearssl_ssl.h",
                     bycopy.} = object
    cipherSuite* {.importc: "cipher_suite".}: uint16
    algoId* {.importc: "algo_id".}: cuint
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: int

  SslServerPolicyClass* {.importc: "br_ssl_server_policy_class",
                         header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    choose* {.importc: "choose".}: proc (pctx: ptr ptr SslServerPolicyClass;
                                     cc: ptr SslServerContext;
                                     choices: ptr SslServerChoices): cint {.bearSslFunc.}
    doKeyx* {.importc: "do_keyx".}: proc (pctx: ptr ptr SslServerPolicyClass;
                                      data: ptr cuchar; len: ptr int): uint32 {.
        bearSslFunc.}
    doSign* {.importc: "do_sign".}: proc (pctx: ptr ptr SslServerPolicyClass;
                                      algoId: cuint; data: ptr cuchar; hvLen: int;
                                      len: int): int {.bearSslFunc.}

  SslServerPolicyRsaContext* {.importc: "br_ssl_server_policy_rsa_context",
                              header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslServerPolicyClass
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: int
    sk* {.importc: "sk".}: ptr RsaPrivateKey
    allowedUsages* {.importc: "allowed_usages".}: cuint
    irsacore* {.importc: "irsacore".}: RsaPrivate
    irsasign* {.importc: "irsasign".}: RsaPkcs1Sign

  SslServerPolicyEcContext* {.importc: "br_ssl_server_policy_ec_context",
                             header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslServerPolicyClass
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: int
    sk* {.importc: "sk".}: ptr EcPrivateKey
    allowedUsages* {.importc: "allowed_usages".}: cuint
    certIssuerKeyType* {.importc: "cert_issuer_key_type".}: cuint
    mhash* {.importc: "mhash".}: ptr MultihashContext
    iec* {.importc: "iec".}: ptr EcImpl
    iecdsa* {.importc: "iecdsa".}: EcdsaSign

  INNER_C_UNION_537875083* {.importc: "no_name", header: "bearssl_ssl.h",
                             bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr SslServerPolicyClass
    singleRsa* {.importc: "single_rsa".}: SslServerPolicyRsaContext
    singleEc* {.importc: "single_ec".}: SslServerPolicyEcContext

  SslServerContext* {.importc: "br_ssl_server_context", header: "bearssl_ssl.h",
                     bycopy.} = object
    eng* {.importc: "eng".}: SslEngineContext
    clientMaxVersion* {.importc: "client_max_version".}: uint16
    cacheVtable* {.importc: "cache_vtable".}: ptr ptr SslSessionCacheClass
    clientSuites* {.importc: "client_suites".}: array[MAX_CIPHER_SUITES,
        SuiteTranslated]
    clientSuitesNum* {.importc: "client_suites_num".}: cuchar
    hashes* {.importc: "hashes".}: uint32
    curves* {.importc: "curves".}: uint32
    policyVtable* {.importc: "policy_vtable".}: ptr ptr SslServerPolicyClass
    signHashId* {.importc: "sign_hash_id".}: uint16
    chainHandler* {.importc: "chain_handler".}: INNER_C_UNION_537875083
    ecdheKey* {.importc: "ecdhe_key".}: array[70, cuchar]
    ecdheKeyLen* {.importc: "ecdhe_key_len".}: int
    taNames* {.importc: "ta_names".}: ptr X500Name
    tas* {.importc: "tas".}: ptr X509TrustAnchor
    numTas* {.importc: "num_tas".}: int
    curDnIndex* {.importc: "cur_dn_index".}: int
    curDn* {.importc: "cur_dn".}: ptr cuchar
    curDnLen* {.importc: "cur_dn_len".}: int
    hashCV* {.importc: "hash_CV".}: array[64, cuchar]
    hashCV_len* {.importc: "hash_CV_len".}: int
    hashCV_id* {.importc: "hash_CV_id".}: cint


  SslSessionCacheClass* {.importc: "br_ssl_session_cache_class",
                         header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    save* {.importc: "save".}: proc (ctx: ptr ptr SslSessionCacheClass;
                                 serverCtx: ptr SslServerContext;
                                 params: ptr SslSessionParameters) {.bearSslFunc.}
    load* {.importc: "load".}: proc (ctx: ptr ptr SslSessionCacheClass;
                                 serverCtx: ptr SslServerContext;
                                 params: ptr SslSessionParameters): cint {.bearSslFunc.}

  SslSessionCacheLru* {.importc: "br_ssl_session_cache_lru",
                       header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslSessionCacheClass
    store* {.importc: "store".}: ptr cuchar
    storeLen* {.importc: "store_len".}: int
    storePtr* {.importc: "store_ptr".}: int
    indexKey* {.importc: "index_key".}: array[32, cuchar]
    hash* {.importc: "hash".}: ptr HashClass
    initDone* {.importc: "init_done".}: cint
    head* {.importc: "head".}: uint32
    tail* {.importc: "tail".}: uint32
    root* {.importc: "root".}: uint32


proc sslSessionCacheLruInit*(cc: ptr SslSessionCacheLru; store: ptr cuchar;
                            storeLen: int) {.bearSslFunc,
    importc: "br_ssl_session_cache_lru_init", header: "bearssl_ssl.h".}

proc sslSessionCacheLruForget*(cc: ptr SslSessionCacheLru; id: ptr cuchar) {.bearSslFunc,
    importc: "br_ssl_session_cache_lru_forget", header: "bearssl_ssl.h".}


proc sslServerInitFullRsa*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                          chainLen: int; sk: ptr RsaPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_full_rsa", header: "bearssl_ssl.h".}

proc sslServerInitFullEc*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; certIssuerKeyType: cuint;
                         sk: ptr EcPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_full_ec", header: "bearssl_ssl.h".}

proc sslServerInitMinr2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr RsaPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_minr2g", header: "bearssl_ssl.h".}

proc sslServerInitMine2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr RsaPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_mine2g", header: "bearssl_ssl.h".}

proc sslServerInitMinf2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr EcPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_minf2g", header: "bearssl_ssl.h".}

proc sslServerInitMinu2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr EcPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_minu2g", header: "bearssl_ssl.h".}

proc sslServerInitMinv2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr EcPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_minv2g", header: "bearssl_ssl.h".}

proc sslServerInitMine2c*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr RsaPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_mine2c", header: "bearssl_ssl.h".}

proc sslServerInitMinf2c*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr EcPrivateKey) {.bearSslFunc,
    importc: "br_ssl_server_init_minf2c", header: "bearssl_ssl.h".}

proc sslServerGetClientSuites*(cc: ptr SslServerContext; num: ptr int):
    ptr array[MAX_CIPHER_SUITES, SuiteTranslated] {.
    inline.} =
  num[] = int cc.clientSuitesNum
  return addr cc.clientSuites

proc sslServerGetClientHashes*(cc: ptr SslServerContext): uint32 {.inline.} =
  return cc.hashes

proc sslServerGetClientCurves*(cc: ptr SslServerContext): uint32 {.inline.} =
  return cc.curves

proc sslServerZero*(cc: ptr SslServerContext) {.bearSslFunc, importc: "br_ssl_server_zero",
    header: "bearssl_ssl.h".}

proc sslServerSetPolicy*(cc: ptr SslServerContext;
                        pctx: ptr ptr SslServerPolicyClass) {.inline.} =
  cc.policyVtable = pctx

proc sslServerSetSingleRsa*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                           chainLen: int; sk: ptr RsaPrivateKey;
                           allowedUsages: cuint; irsacore: RsaPrivate;
                           irsasign: RsaPkcs1Sign) {.bearSslFunc,
    importc: "br_ssl_server_set_single_rsa", header: "bearssl_ssl.h".}

proc sslServerSetSingleEc*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                          chainLen: int; sk: ptr EcPrivateKey;
                          allowedUsages: cuint; certIssuerKeyType: cuint;
                          iec: ptr EcImpl; iecdsa: EcdsaSign) {.bearSslFunc,
    importc: "br_ssl_server_set_single_ec", header: "bearssl_ssl.h".}

proc sslServerSetTrustAnchorNames*(cc: ptr SslServerContext; taNames: ptr X500Name;
                                  num: int) {.inline.} =
  cc.taNames = taNames
  cc.tas = nil
  cc.numTas = num

proc sslServerSetTrustAnchorNamesAlt*(cc: ptr SslServerContext;
                                     tas: ptr X509TrustAnchor; num: int) {.inline,
    bearSslFunc.} =
  cc.taNames = nil
  cc.tas = tas
  cc.numTas = num

proc sslServerSetCache*(cc: ptr SslServerContext;
                       vtable: ptr ptr SslSessionCacheClass) {.inline.} =
  cc.cacheVtable = vtable

proc sslServerReset*(cc: ptr SslServerContext): cint {.bearSslFunc,
    importc: "br_ssl_server_reset", header: "bearssl_ssl.h".}

type
  SslioContext* {.importc: "br_sslio_context", header: "bearssl_ssl.h", bycopy.} = object
    engine* {.importc: "engine".}: ptr SslEngineContext
    lowRead* {.importc: "low_read".}: proc (readContext: pointer; data: ptr cuchar;
                                        len: int): cint {.bearSslFunc.}
    readContext* {.importc: "read_context".}: pointer
    lowWrite* {.importc: "low_write".}: proc (writeContext: pointer; data: ptr cuchar;
        len: int): cint {.bearSslFunc.}
    writeContext* {.importc: "write_context".}: pointer


proc sslioInit*(ctx: ptr SslioContext; engine: ptr SslEngineContext; lowRead: proc (
    readContext: pointer; data: ptr cuchar; len: int): cint {.bearSslFunc.};
               readContext: pointer; lowWrite: proc (writeContext: pointer;
    data: ptr cuchar; len: int): cint {.bearSslFunc.}; writeContext: pointer) {.bearSslFunc,
    importc: "br_sslio_init", header: "bearssl_ssl.h".}

proc sslioRead*(cc: ptr SslioContext; dst: pointer; len: int): cint {.bearSslFunc,
    importc: "br_sslio_read", header: "bearssl_ssl.h".}

proc sslioReadAll*(cc: ptr SslioContext; dst: pointer; len: int): cint {.bearSslFunc,
    importc: "br_sslio_read_all", header: "bearssl_ssl.h".}

proc sslioWrite*(cc: ptr SslioContext; src: pointer; len: int): cint {.bearSslFunc,
    importc: "br_sslio_write", header: "bearssl_ssl.h".}

proc sslioWriteAll*(cc: ptr SslioContext; src: pointer; len: int): cint {.bearSslFunc,
    importc: "br_sslio_write_all", header: "bearssl_ssl.h".}

proc sslioFlush*(cc: ptr SslioContext): cint {.bearSslFunc, importc: "br_sslio_flush",
    header: "bearssl_ssl.h".}

proc sslioClose*(cc: ptr SslioContext): cint {.bearSslFunc, importc: "br_sslio_close",
    header: "bearssl_ssl.h".}

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
  INNER_C_STRUCT_1475532182* {.importc: "no_name", header: "bearssl_pem.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr cuchar

  PemDecoderContext* {.importc: "br_pem_decoder_context", header: "bearssl_pem.h",
                      bycopy.} = object
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_1475532182
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    hbuf* {.importc: "hbuf".}: ptr cuchar
    hlen* {.importc: "hlen".}: int
    dest* {.importc: "dest".}: proc (destCtx: pointer; src: pointer; len: int) {.bearSslFunc.}
    destCtx* {.importc: "dest_ctx".}: pointer
    event* {.importc: "event".}: cuchar
    name* {.importc: "name".}: array[128, char]
    buf* {.importc: "buf".}: array[255, cuchar]
    `ptr`* {.importc: "ptr".}: int


proc pemDecoderInit*(ctx: ptr PemDecoderContext) {.bearSslFunc,
    importc: "br_pem_decoder_init", header: "bearssl_pem.h".}

proc pemDecoderPush*(ctx: ptr PemDecoderContext; data: pointer; len: int): int {.
    bearSslFunc, importc: "br_pem_decoder_push", header: "bearssl_pem.h".}

proc pemDecoderSetdest*(ctx: ptr PemDecoderContext; dest: proc (destCtx: pointer;
    src: pointer; len: int) {.bearSslFunc.}; destCtx: pointer) {.inline.} =
  ctx.dest = dest
  ctx.destCtx = destCtx

proc pemDecoderEvent*(ctx: ptr PemDecoderContext): cint {.bearSslFunc,
    importc: "br_pem_decoder_event", header: "bearssl_pem.h".}

const
  PEM_BEGIN_OBJ* = 1

const
  PEM_END_OBJ* = 2

const
  PEM_ERROR* = 3

proc pemDecoderName*(ctx: ptr PemDecoderContext): cstring {.inline.} =
  return addr ctx.name

type
  ConfigOption* {.importc: "br_config_option", header: "bearssl.h", bycopy.} = object
    name* {.importc: "name".}: cstring
    value* {.importc: "value".}: clong


proc getConfig*(): ptr ConfigOption {.bearSslFunc, importc: "br_get_config",
  header: "bearssl.h".}

const
  BR_EC_SECP256R1* = 23
  BR_EC_SECP384R1* = 24
  BR_EC_SECP521R1* = 25

  BR_EC_KBUF_PRIV_MAX_SIZE* = 72
  BR_EC_KBUF_PUB_MAX_SIZE* = 145

type
  X509NoAnchorContext* {.importc: "x509_noanchor_context",
                         header: "brssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class

proc initNoAnchor*(xwc: ptr X509NoAnchorContext, inner: ptr ptr X509Class) {.
     bearSslFunc, importc: "x509_noanchor_init", header: "brssl.h".}

# Following declarations are used inside `nim-libp2p`.

type
  BrHashClass* = HashClass
  BrMd5Context* = Md5Context
  BrMd5sha1Context* = Md5sha1Context
  BrSha512Context* = Sha384Context
  BrSha384Context* = Sha384Context
  BrSha256Context* = Sha224Context
  BrSha224Context*  = Sha224Context
  BrHashCompatContext* = HashCompatContext
  BrPrngClass* = PrngClass
  BrHmacDrbgContext* = HmacDrbgContext
  BrRsaPublicKey* = RsaPublicKey
  BrRsaPrivateKey* = RsaPrivateKey
  BrEcPublicKey* = EcPublicKey
  BrEcPrivateKey* = EcPrivateKey
  BrEcImplementation* = EcImpl
  BrPrngSeeder* = PrngSeeder
  BrRsaKeygen* = proc (ctx: ptr ptr BrPrngClass,
                       sk: ptr BrRsaPrivateKey, bufsec: ptr byte,
                       pk: ptr BrRsaPublicKey, bufpub: ptr byte,
                       size: cuint, pubexp: uint32): uint32 {.bearSslFunc.}
  BrRsaComputeModulus* = proc (n: pointer,
                               sk: ptr BrRsaPrivateKey): int {.bearSslFunc.}
  BrRsaComputePubexp* = proc (sk: ptr BrRsaPrivateKey): uint32 {.bearSslFunc.}
  BrRsaComputePrivexp* = proc (d: pointer,
                               sk: ptr BrRsaPrivateKey,
                               pubexp: uint32): int {.bearSslFunc.}
  BrRsaPkcs1Verify* = proc (x: ptr cuchar, xlen: int,
                            hash_oid: ptr cuchar, hash_len: int,
                            pk: ptr BrRsaPublicKey,
                            hash_out: ptr cuchar): uint32 {.bearSslFunc.}
  BrPemDecoderProc* = proc (destctx: pointer, src: pointer,
                            length: int) {.bearSslFunc.}
  BrRsaPkcs1Sign* = RsaPkcs1Sign

proc brPrngSeederSystem*(name: cstringArray): BrPrngSeeder {.bearSslFunc,
     importc: "br_prng_seeder_system", header: "bearssl_rand.h".}

proc brHmacDrbgInit*(ctx: ptr BrHmacDrbgContext, digestClass: ptr BrHashClass,
                     seed: pointer, seedLen: int) {.
     bearSslFunc, importc: "br_hmac_drbg_init", header: "bearssl_rand.h".}

proc brHmacDrbgGenerate*(ctx: ptr BrHmacDrbgContext, outs: pointer, len: csize_t) {.
     bearSslFunc, importc: "br_hmac_drbg_generate", header: "bearssl_rand.h".}

proc brHmacDrbgGenerate*(ctx: var BrHmacDrbgContext, outp: var openArray[byte]) =
  brHmacDrbgGenerate(addr ctx, addr outp, csize_t(outp.len))

proc brRsaKeygenGetDefault*(): BrRsaKeygen {.
     bearSslFunc, importc: "br_rsa_keygen_get_default", header: "bearssl_rsa.h".}

proc BrRsaPkcs1SignGetDefault*(): BrRsaPkcs1Sign {.
     bearSslFunc, importc: "br_rsa_pkcs1_sign_get_default", header: "bearssl_rsa.h".}

proc BrRsaPkcs1VrfyGetDefault*(): BrRsaPkcs1Verify {.
     bearSslFunc, importc: "br_rsa_pkcs1_vrfy_get_default", header: "bearssl_rsa.h".}

proc brRsaComputeModulusGetDefault*(): BrRsaComputeModulus {.
     bearSslFunc, importc: "br_rsa_compute_modulus_get_default",
     header: "bearssl_rsa.h".}

proc brRsaComputePubexpGetDefault*(): BrRsaComputePubexp {.
     bearSslFunc, importc: "br_rsa_compute_pubexp_get_default",
     header: "bearssl_rsa.h".}

proc brRsaComputePrivexpGetDefault*(): BrRsaComputePrivexp {.
     bearSslFunc, importc: "br_rsa_compute_privexp_get_default",
     header: "bearssl_rsa.h".}

proc brEcGetDefault*(): ptr BrEcImplementation {.
     bearSslFunc, importc: "br_ec_get_default", header: "bearssl_ec.h".}

proc brEcKeygen*(ctx: ptr ptr BrPrngClass, impl: ptr BrEcImplementation,
                 sk: ptr BrEcPrivateKey, keybuf: ptr byte,
                 curve: cint): int {.bearSslFunc,
     importc: "br_ec_keygen", header: "bearssl_ec.h".}

proc brEcComputePublicKey*(impl: ptr BrEcImplementation, pk: ptr BrEcPublicKey,
                           kbuf: ptr byte, sk: ptr BrEcPrivateKey): int {.
     bearSslFunc, importc: "br_ec_compute_pub", header: "bearssl_ec.h".}

proc brEcdsaSignRaw*(impl: ptr BrEcImplementation, hf: ptr BrHashClass,
                     value: pointer, sk: ptr BrEcPrivateKey,
                     sig: pointer): int {.
     bearSslFunc, importc: "br_ecdsa_i31_sign_raw", header: "bearssl_ec.h".}

proc brEcdsaVerifyRaw*(impl: ptr BrEcImplementation, hash: pointer,
                       hashlen: int, pk: ptr BrEcPublicKey, sig: pointer,
                       siglen: int): uint32 {.
     bearSslFunc, importc: "br_ecdsa_i31_vrfy_raw", header: "bearssl_ec.h".}

proc brEcdsaSignAsn1*(impl: ptr BrEcImplementation, hf: ptr BrHashClass,
                     value: pointer, sk: ptr BrEcPrivateKey,
                     sig: pointer): int {.
     bearSslFunc, importc: "br_ecdsa_i31_sign_asn1", header: "bearssl_ec.h".}

proc brEcdsaVerifyAsn1*(impl: ptr BrEcImplementation, hash: pointer,
                        hashlen: int, pk: ptr BrEcPublicKey, sig: pointer,
                        siglen: int): uint32 {.
     bearSslFunc, importc: "br_ecdsa_i31_vrfy_asn1", header: "bearssl_ec.h".}

template brRsaPrivateKeyBufferSize*(size: int): int =
  # BR_RSA_KBUF_PRIV_SIZE(size)
  (5 * ((size + 15) shr 4))

template brRsaPublicKeyBufferSize*(size: int): int =
  # BR_RSA_KBUF_PUB_SIZE(size)
  (4 + ((size + 7) shr 3))
