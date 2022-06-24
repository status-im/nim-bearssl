import
  "."/[csources, intx]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearSymcPath = bearSrcPath & "symcipher/"

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

type
  BlockCbcencClass* {.importc: "br_block_cbcenc_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: uint
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCbcencClass; key: pointer;
                                 keyLen: uint) {.importcFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCbcencClass; iv: pointer;
                               data: pointer; len: uint) {.importcFunc.}



type
  BlockCbcdecClass* {.importc: "br_block_cbcdec_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: uint
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCbcdecClass; key: pointer;
                                 keyLen: uint) {.importcFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCbcdecClass; iv: pointer;
                               data: pointer; len: uint) {.importcFunc.}



type
  BlockCtrClass* {.importc: "br_block_ctr_class", header: "bearssl_block.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: uint
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCtrClass; key: pointer;
                                 keyLen: uint) {.importcFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCtrClass; iv: pointer; cc: uint32;
                               data: pointer; len: uint): uint32 {.importcFunc.}



type
  BlockCtrcbcClass* {.importc: "br_block_ctrcbc_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: uint
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCtrcbcClass; key: pointer;
                                 keyLen: uint) {.importcFunc.}
    encrypt* {.importc: "encrypt".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                                       cbcmac: pointer; data: pointer; len: uint) {.
        importcFunc.}
    decrypt* {.importc: "decrypt".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                                       cbcmac: pointer; data: pointer; len: uint) {.
        importcFunc.}
    ctr* {.importc: "ctr".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                               data: pointer; len: uint) {.importcFunc.}
    mac* {.importc: "mac".}: proc (ctx: ptr ptr BlockCtrcbcClass; cbcmac: pointer;
                               data: pointer; len: uint) {.importcFunc.}



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


var aesBigCbcencVtable* {.importc: "br_aes_big_cbcenc_vtable", header: "bearssl_block.h".}: BlockCbcencClass


var aesBigCbcdecVtable* {.importc: "br_aes_big_cbcdec_vtable", header: "bearssl_block.h".}: BlockCbcdecClass


var aesBigCtrVtable* {.importc: "br_aes_big_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass


var aesBigCtrcbcVtable* {.importc: "br_aes_big_ctrcbc_vtable", header: "bearssl_block.h".}: BlockCtrcbcClass


proc aesBigCbcencInit*(ctx: var AesBigCbcencKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_big_cbcenc_init", header: "bearssl_block.h".}

proc aesBigCbcdecInit*(ctx: var AesBigCbcdecKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_big_cbcdec_init", header: "bearssl_block.h".}

proc aesBigCtrInit*(ctx: var AesBigCtrKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_big_ctr_init", header: "bearssl_block.h".}

proc aesBigCtrcbcInit*(ctx: var AesBigCtrcbcKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_big_ctrcbc_init", header: "bearssl_block.h".}

proc aesBigCbcencRun*(ctx: var AesBigCbcencKeys; iv: pointer; data: pointer;
                     len: uint) {.importcFunc, importc: "br_aes_big_cbcenc_run",
                                   header: "bearssl_block.h".}

proc aesBigCbcdecRun*(ctx: var AesBigCbcdecKeys; iv: pointer; data: pointer;
                     len: uint) {.importcFunc, importc: "br_aes_big_cbcdec_run",
                                   header: "bearssl_block.h".}

proc aesBigCtrRun*(ctx: var AesBigCtrKeys; iv: pointer; cc: uint32; data: pointer;
                  len: uint): uint32 {.importcFunc, importc: "br_aes_big_ctr_run",
                                        header: "bearssl_block.h".}

proc aesBigCtrcbcEncrypt*(ctx: var AesBigCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                         data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_big_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesBigCtrcbcDecrypt*(ctx: var AesBigCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                         data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_big_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesBigCtrcbcCtr*(ctx: var AesBigCtrcbcKeys; ctr: pointer; data: pointer;
                     len: uint) {.importcFunc, importc: "br_aes_big_ctrcbc_ctr",
                                   header: "bearssl_block.h".}

proc aesBigCtrcbcMac*(ctx: var AesBigCtrcbcKeys; cbcmac: pointer; data: pointer;
                     len: uint) {.importcFunc, importc: "br_aes_big_ctrcbc_mac",
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


var aesSmallCbcencVtable* {.importc: "br_aes_small_cbcenc_vtable", header: "bearssl_block.h".}: BlockCbcencClass


var aesSmallCbcdecVtable* {.importc: "br_aes_small_cbcdec_vtable", header: "bearssl_block.h".}: BlockCbcdecClass


var aesSmallCtrVtable* {.importc: "br_aes_small_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass


var aesSmallCtrcbcVtable* {.importc: "br_aes_small_ctrcbc_vtable", header: "bearssl_block.h".}: BlockCtrcbcClass


proc aesSmallCbcencInit*(ctx: var AesSmallCbcencKeys; key: pointer; len: uint) {.
    importcFunc, importc: "br_aes_small_cbcenc_init", header: "bearssl_block.h".}

proc aesSmallCbcdecInit*(ctx: var AesSmallCbcdecKeys; key: pointer; len: uint) {.
    importcFunc, importc: "br_aes_small_cbcdec_init", header: "bearssl_block.h".}

proc aesSmallCtrInit*(ctx: var AesSmallCtrKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_small_ctr_init", header: "bearssl_block.h".}

proc aesSmallCtrcbcInit*(ctx: var AesSmallCtrcbcKeys; key: pointer; len: uint) {.
    importcFunc, importc: "br_aes_small_ctrcbc_init", header: "bearssl_block.h".}

proc aesSmallCbcencRun*(ctx: var AesSmallCbcencKeys; iv: pointer; data: pointer;
                       len: uint) {.importcFunc, importc: "br_aes_small_cbcenc_run",
                                     header: "bearssl_block.h".}

proc aesSmallCbcdecRun*(ctx: var AesSmallCbcdecKeys; iv: pointer; data: pointer;
                       len: uint) {.importcFunc, importc: "br_aes_small_cbcdec_run",
                                     header: "bearssl_block.h".}

proc aesSmallCtrRun*(ctx: var AesSmallCtrKeys; iv: pointer; cc: uint32; data: pointer;
                    len: uint): uint32 {.importcFunc, importc: "br_aes_small_ctr_run",
    header: "bearssl_block.h".}

proc aesSmallCtrcbcEncrypt*(ctx: var AesSmallCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_small_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesSmallCtrcbcDecrypt*(ctx: var AesSmallCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_small_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesSmallCtrcbcCtr*(ctx: var AesSmallCtrcbcKeys; ctr: pointer; data: pointer;
                       len: uint) {.importcFunc, importc: "br_aes_small_ctrcbc_ctr",
                                     header: "bearssl_block.h".}

proc aesSmallCtrcbcMac*(ctx: var AesSmallCtrcbcKeys; cbcmac: pointer; data: pointer;
                       len: uint) {.importcFunc, importc: "br_aes_small_ctrcbc_mac",
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


var aesCtCbcencVtable* {.importc: "br_aes_ct_cbcenc_vtable", header: "bearssl_block.h".}: BlockCbcencClass


var aesCtCbcdecVtable* {.importc: "br_aes_ct_cbcdec_vtable", header: "bearssl_block.h".}: BlockCbcdecClass


var aesCtCtrVtable* {.importc: "br_aes_ct_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass


var aesCtCtrcbcVtable* {.importc: "br_aes_ct_ctrcbc_vtable", header: "bearssl_block.h".}: BlockCtrcbcClass


proc aesCtCbcencInit*(ctx: var AesCtCbcencKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct_cbcenc_init", header: "bearssl_block.h".}

proc aesCtCbcdecInit*(ctx: var AesCtCbcdecKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct_cbcdec_init", header: "bearssl_block.h".}

proc aesCtCtrInit*(ctx: var AesCtCtrKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct_ctr_init", header: "bearssl_block.h".}

proc aesCtCtrcbcInit*(ctx: var AesCtCtrcbcKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct_ctrcbc_init", header: "bearssl_block.h".}

proc aesCtCbcencRun*(ctx: var AesCtCbcencKeys; iv: pointer; data: pointer; len: uint) {.
    importcFunc, importc: "br_aes_ct_cbcenc_run", header: "bearssl_block.h".}

proc aesCtCbcdecRun*(ctx: var AesCtCbcdecKeys; iv: pointer; data: pointer; len: uint) {.
    importcFunc, importc: "br_aes_ct_cbcdec_run", header: "bearssl_block.h".}

proc aesCtCtrRun*(ctx: var AesCtCtrKeys; iv: pointer; cc: uint32; data: pointer;
                 len: uint): uint32 {.importcFunc, importc: "br_aes_ct_ctr_run",
                                       header: "bearssl_block.h".}

proc aesCtCtrcbcEncrypt*(ctx: var AesCtCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                        data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesCtCtrcbcDecrypt*(ctx: var AesCtCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                        data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesCtCtrcbcCtr*(ctx: var AesCtCtrcbcKeys; ctr: pointer; data: pointer; len: uint) {.
    importcFunc, importc: "br_aes_ct_ctrcbc_ctr", header: "bearssl_block.h".}

proc aesCtCtrcbcMac*(ctx: var AesCtCtrcbcKeys; cbcmac: pointer; data: pointer;
                    len: uint) {.importcFunc, importc: "br_aes_ct_ctrcbc_mac",
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


var aesCt64CbcencVtable* {.importc: "br_aes_ct64_cbcenc_vtable", header: "bearssl_block.h".}: BlockCbcencClass


var aesCt64CbcdecVtable* {.importc: "br_aes_ct64_cbcdec_vtable", header: "bearssl_block.h".}: BlockCbcdecClass


var aesCt64CtrVtable* {.importc: "br_aes_ct64_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass


var aesCt64CtrcbcVtable* {.importc: "br_aes_ct64_ctrcbc_vtable", header: "bearssl_block.h".}: BlockCtrcbcClass


proc aesCt64CbcencInit*(ctx: var AesCt64CbcencKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct64_cbcenc_init", header: "bearssl_block.h".}

proc aesCt64CbcdecInit*(ctx: var AesCt64CbcdecKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct64_cbcdec_init", header: "bearssl_block.h".}

proc aesCt64CtrInit*(ctx: var AesCt64CtrKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct64_ctr_init", header: "bearssl_block.h".}

proc aesCt64CtrcbcInit*(ctx: var AesCt64CtrcbcKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct64_ctrcbc_init", header: "bearssl_block.h".}

proc aesCt64CbcencRun*(ctx: var AesCt64CbcencKeys; iv: pointer; data: pointer;
                      len: uint) {.importcFunc, importc: "br_aes_ct64_cbcenc_run",
                                    header: "bearssl_block.h".}

proc aesCt64CbcdecRun*(ctx: var AesCt64CbcdecKeys; iv: pointer; data: pointer;
                      len: uint) {.importcFunc, importc: "br_aes_ct64_cbcdec_run",
                                    header: "bearssl_block.h".}

proc aesCt64CtrRun*(ctx: var AesCt64CtrKeys; iv: pointer; cc: uint32; data: pointer;
                   len: uint): uint32 {.importcFunc, importc: "br_aes_ct64_ctr_run",
    header: "bearssl_block.h".}

proc aesCt64CtrcbcEncrypt*(ctx: var AesCt64CtrcbcKeys; ctr: pointer; cbcmac: pointer;
                          data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct64_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesCt64CtrcbcDecrypt*(ctx: var AesCt64CtrcbcKeys; ctr: pointer; cbcmac: pointer;
                          data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_ct64_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesCt64CtrcbcCtr*(ctx: var AesCt64CtrcbcKeys; ctr: pointer; data: pointer;
                      len: uint) {.importcFunc, importc: "br_aes_ct64_ctrcbc_ctr",
                                    header: "bearssl_block.h".}

proc aesCt64CtrcbcMac*(ctx: var AesCt64CtrcbcKeys; cbcmac: pointer; data: pointer;
                      len: uint) {.importcFunc, importc: "br_aes_ct64_ctrcbc_mac",
                                    header: "bearssl_block.h".}

const
  aesX86niBLOCK_SIZE* = 16


type
  INNER_C_UNION_bearssl_block_1* {.importc: "br_aes_x86ni_cbcenc_keys::no_name",
                                  header: "bearssl_block.h", bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, byte]

  AesX86niCbcencKeys* {.importc: "br_aes_x86ni_cbcenc_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: INNER_C_UNION_bearssl_block_1
    numRounds* {.importc: "num_rounds".}: cuint



type
  INNER_C_UNION_bearssl_block_3* {.importc: "br_aes_x86ni_cbcdec_keys::no_name",
                                  header: "bearssl_block.h", bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, byte]

  AesX86niCbcdecKeys* {.importc: "br_aes_x86ni_cbcdec_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: INNER_C_UNION_bearssl_block_3
    numRounds* {.importc: "num_rounds".}: cuint



type
  INNER_C_UNION_bearssl_block_5* {.importc: "br_aes_x86ni_ctr_keys::no_name",
                                  header: "bearssl_block.h", bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, byte]

  AesX86niCtrKeys* {.importc: "br_aes_x86ni_ctr_keys", header: "bearssl_block.h",
                    bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    skey* {.importc: "skey".}: INNER_C_UNION_bearssl_block_5
    numRounds* {.importc: "num_rounds".}: cuint



type
  INNER_C_UNION_bearssl_block_7* {.importc: "br_aes_x86ni_ctrcbc_keys::no_name",
                                  header: "bearssl_block.h", bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, byte]

  AesX86niCtrcbcKeys* {.importc: "br_aes_x86ni_ctrcbc_keys",
                       header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    skey* {.importc: "skey".}: INNER_C_UNION_bearssl_block_7
    numRounds* {.importc: "num_rounds".}: cuint


var aesX86niCbcencVtable* {.importc: "br_aes_x86ni_cbcenc_vtable", header: "bearssl_block.h".}: BlockCbcencClass


var aesX86niCbcdecVtable* {.importc: "br_aes_x86ni_cbcdec_vtable", header: "bearssl_block.h".}: BlockCbcdecClass


var aesX86niCtrVtable* {.importc: "br_aes_x86ni_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass


var aesX86niCtrcbcVtable* {.importc: "br_aes_x86ni_ctrcbc_vtable", header: "bearssl_block.h".}: BlockCtrcbcClass


proc aesX86niCbcencInit*(ctx: var AesX86niCbcencKeys; key: pointer; len: uint) {.
    importcFunc, importc: "br_aes_x86ni_cbcenc_init", header: "bearssl_block.h".}

proc aesX86niCbcdecInit*(ctx: var AesX86niCbcdecKeys; key: pointer; len: uint) {.
    importcFunc, importc: "br_aes_x86ni_cbcdec_init", header: "bearssl_block.h".}

proc aesX86niCtrInit*(ctx: var AesX86niCtrKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_x86ni_ctr_init", header: "bearssl_block.h".}

proc aesX86niCtrcbcInit*(ctx: var AesX86niCtrcbcKeys; key: pointer; len: uint) {.
    importcFunc, importc: "br_aes_x86ni_ctrcbc_init", header: "bearssl_block.h".}

proc aesX86niCbcencRun*(ctx: var AesX86niCbcencKeys; iv: pointer; data: pointer;
                       len: uint) {.importcFunc, importc: "br_aes_x86ni_cbcenc_run",
                                     header: "bearssl_block.h".}

proc aesX86niCbcdecRun*(ctx: var AesX86niCbcdecKeys; iv: pointer; data: pointer;
                       len: uint) {.importcFunc, importc: "br_aes_x86ni_cbcdec_run",
                                     header: "bearssl_block.h".}

proc aesX86niCtrRun*(ctx: var AesX86niCtrKeys; iv: pointer; cc: uint32; data: pointer;
                    len: uint): uint32 {.importcFunc, importc: "br_aes_x86ni_ctr_run",
    header: "bearssl_block.h".}

proc aesX86niCtrcbcEncrypt*(ctx: var AesX86niCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_x86ni_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesX86niCtrcbcDecrypt*(ctx: var AesX86niCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_x86ni_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesX86niCtrcbcCtr*(ctx: var AesX86niCtrcbcKeys; ctr: pointer; data: pointer;
                       len: uint) {.importcFunc, importc: "br_aes_x86ni_ctrcbc_ctr",
                                     header: "bearssl_block.h".}

proc aesX86niCtrcbcMac*(ctx: var AesX86niCtrcbcKeys; cbcmac: pointer; data: pointer;
                       len: uint) {.importcFunc, importc: "br_aes_x86ni_ctrcbc_mac",
                                     header: "bearssl_block.h".}

proc aesX86niCbcencGetVtable*(): ptr BlockCbcencClass {.importcFunc,
    importc: "br_aes_x86ni_cbcenc_get_vtable", header: "bearssl_block.h".}

proc aesX86niCbcdecGetVtable*(): ptr BlockCbcdecClass {.importcFunc,
    importc: "br_aes_x86ni_cbcdec_get_vtable", header: "bearssl_block.h".}

proc aesX86niCtrGetVtable*(): ptr BlockCtrClass {.importcFunc,
    importc: "br_aes_x86ni_ctr_get_vtable", header: "bearssl_block.h".}

proc aesX86niCtrcbcGetVtable*(): ptr BlockCtrcbcClass {.importcFunc,
    importc: "br_aes_x86ni_ctrcbc_get_vtable", header: "bearssl_block.h".}

const
  aesPwr8BLOCK_SIZE* = 16


type
  INNER_C_UNION_bearssl_block_9* {.importc: "br_aes_pwr8_cbcenc_keys::no_name",
                                  header: "bearssl_block.h", bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, byte]

  AesPwr8CbcencKeys* {.importc: "br_aes_pwr8_cbcenc_keys",
                      header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    skey* {.importc: "skey".}: INNER_C_UNION_bearssl_block_9
    numRounds* {.importc: "num_rounds".}: cuint



type
  INNER_C_UNION_bearssl_block_11* {.importc: "br_aes_pwr8_cbcdec_keys::no_name",
                                   header: "bearssl_block.h", bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, byte]

  AesPwr8CbcdecKeys* {.importc: "br_aes_pwr8_cbcdec_keys",
                      header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    skey* {.importc: "skey".}: INNER_C_UNION_bearssl_block_11
    numRounds* {.importc: "num_rounds".}: cuint



type
  INNER_C_UNION_bearssl_block_13* {.importc: "br_aes_pwr8_ctr_keys::no_name",
                                   header: "bearssl_block.h", bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, byte]

  AesPwr8CtrKeys* {.importc: "br_aes_pwr8_ctr_keys", header: "bearssl_block.h",
                   bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    skey* {.importc: "skey".}: INNER_C_UNION_bearssl_block_13
    numRounds* {.importc: "num_rounds".}: cuint



type
  INNER_C_UNION_bearssl_block_15* {.importc: "br_aes_pwr8_ctrcbc_keys::no_name",
                                   header: "bearssl_block.h", bycopy, union.} = object
    skni* {.importc: "skni".}: array[16 * 15, byte]

  AesPwr8CtrcbcKeys* {.importc: "br_aes_pwr8_ctrcbc_keys",
                      header: "bearssl_block.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    skey* {.importc: "skey".}: INNER_C_UNION_bearssl_block_15
    numRounds* {.importc: "num_rounds".}: cuint


var aesPwr8CbcencVtable* {.importc: "br_aes_pwr8_cbcenc_vtable", header: "bearssl_block.h".}: BlockCbcencClass


var aesPwr8CbcdecVtable* {.importc: "br_aes_pwr8_cbcdec_vtable", header: "bearssl_block.h".}: BlockCbcdecClass


var aesPwr8CtrVtable* {.importc: "br_aes_pwr8_ctr_vtable", header: "bearssl_block.h".}: BlockCtrClass


var aesPwr8CtrcbcVtable* {.importc: "br_aes_pwr8_ctrcbc_vtable", header: "bearssl_block.h".}: BlockCtrcbcClass


proc aesPwr8CbcencInit*(ctx: var AesPwr8CbcencKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_pwr8_cbcenc_init", header: "bearssl_block.h".}

proc aesPwr8CbcdecInit*(ctx: var AesPwr8CbcdecKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_pwr8_cbcdec_init", header: "bearssl_block.h".}

proc aesPwr8CtrInit*(ctx: var AesPwr8CtrKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_pwr8_ctr_init", header: "bearssl_block.h".}

proc aesPwr8CtrcbcInit*(ctx: var AesPwr8CtrcbcKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_aes_pwr8_ctrcbc_init", header: "bearssl_block.h".}

proc aesPwr8CbcencRun*(ctx: var AesPwr8CbcencKeys; iv: pointer; data: pointer;
                      len: uint) {.importcFunc, importc: "br_aes_pwr8_cbcenc_run",
                                    header: "bearssl_block.h".}

proc aesPwr8CbcdecRun*(ctx: var AesPwr8CbcdecKeys; iv: pointer; data: pointer;
                      len: uint) {.importcFunc, importc: "br_aes_pwr8_cbcdec_run",
                                    header: "bearssl_block.h".}

proc aesPwr8CtrRun*(ctx: var AesPwr8CtrKeys; iv: pointer; cc: uint32; data: pointer;
                   len: uint): uint32 {.importcFunc, importc: "br_aes_pwr8_ctr_run",
    header: "bearssl_block.h".}

proc aesPwr8CtrcbcEncrypt*(ctx: var AesPwr8CtrcbcKeys; ctr: pointer; cbcmac: pointer;
                          data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_pwr8_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesPwr8CtrcbcDecrypt*(ctx: var AesPwr8CtrcbcKeys; ctr: pointer; cbcmac: pointer;
                          data: pointer; len: uint) {.importcFunc,
    importc: "br_aes_pwr8_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesPwr8CtrcbcCtr*(ctx: var AesPwr8CtrcbcKeys; ctr: pointer; data: pointer;
                      len: uint) {.importcFunc, importc: "br_aes_pwr8_ctrcbc_ctr",
                                    header: "bearssl_block.h".}

proc aesPwr8CtrcbcMac*(ctx: var AesPwr8CtrcbcKeys; cbcmac: pointer; data: pointer;
                      len: uint) {.importcFunc, importc: "br_aes_pwr8_ctrcbc_mac",
                                    header: "bearssl_block.h".}

proc aesPwr8CbcencGetVtable*(): ptr BlockCbcencClass {.importcFunc,
    importc: "br_aes_pwr8_cbcenc_get_vtable", header: "bearssl_block.h".}

proc aesPwr8CbcdecGetVtable*(): ptr BlockCbcdecClass {.importcFunc,
    importc: "br_aes_pwr8_cbcdec_get_vtable", header: "bearssl_block.h".}

proc aesPwr8CtrGetVtable*(): ptr BlockCtrClass {.importcFunc,
    importc: "br_aes_pwr8_ctr_get_vtable", header: "bearssl_block.h".}

proc aesPwr8CtrcbcGetVtable*(): ptr BlockCtrcbcClass {.importcFunc,
    importc: "br_aes_pwr8_ctrcbc_get_vtable", header: "bearssl_block.h".}

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
  AesGenCtrKeys* {.importc: "br_aes_gen_ctr_keys", header: "bearssl_block.h", bycopy,
                  union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    cBig* {.importc: "c_big".}: AesBigCtrKeys
    cSmall* {.importc: "c_small".}: AesSmallCtrKeys
    cCt* {.importc: "c_ct".}: AesCtCtrKeys
    cCt64* {.importc: "c_ct64".}: AesCt64CtrKeys
    cX86ni* {.importc: "c_x86ni".}: AesX86niCtrKeys
    cPwr8* {.importc: "c_pwr8".}: AesPwr8CtrKeys



type
  AesGenCtrcbcKeys* {.importc: "br_aes_gen_ctrcbc_keys", header: "bearssl_block.h",
                     bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    cBig* {.importc: "c_big".}: AesBigCtrcbcKeys
    cSmall* {.importc: "c_small".}: AesSmallCtrcbcKeys
    cCt* {.importc: "c_ct".}: AesCtCtrcbcKeys
    cCt64* {.importc: "c_ct64".}: AesCt64CtrcbcKeys
    cX86ni* {.importc: "c_x86ni".}: AesX86niCtrcbcKeys
    cPwr8* {.importc: "c_pwr8".}: AesPwr8CtrcbcKeys



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


var desTabCbcencVtable* {.importc: "br_des_tab_cbcenc_vtable", header: "bearssl_block.h".}: BlockCbcencClass


var desTabCbcdecVtable* {.importc: "br_des_tab_cbcdec_vtable", header: "bearssl_block.h".}: BlockCbcdecClass


proc desTabCbcencInit*(ctx: var DesTabCbcencKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_des_tab_cbcenc_init", header: "bearssl_block.h".}

proc desTabCbcdecInit*(ctx: var DesTabCbcdecKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_des_tab_cbcdec_init", header: "bearssl_block.h".}

proc desTabCbcencRun*(ctx: var DesTabCbcencKeys; iv: pointer; data: pointer;
                     len: uint) {.importcFunc, importc: "br_des_tab_cbcenc_run",
                                   header: "bearssl_block.h".}

proc desTabCbcdecRun*(ctx: var DesTabCbcdecKeys; iv: pointer; data: pointer;
                     len: uint) {.importcFunc, importc: "br_des_tab_cbcdec_run",
                                   header: "bearssl_block.h".}

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


var desCtCbcencVtable* {.importc: "br_des_ct_cbcenc_vtable", header: "bearssl_block.h".}: BlockCbcencClass


var desCtCbcdecVtable* {.importc: "br_des_ct_cbcdec_vtable", header: "bearssl_block.h".}: BlockCbcdecClass


proc desCtCbcencInit*(ctx: var DesCtCbcencKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_des_ct_cbcenc_init", header: "bearssl_block.h".}

proc desCtCbcdecInit*(ctx: var DesCtCbcdecKeys; key: pointer; len: uint) {.importcFunc,
    importc: "br_des_ct_cbcdec_init", header: "bearssl_block.h".}

proc desCtCbcencRun*(ctx: var DesCtCbcencKeys; iv: pointer; data: pointer; len: uint) {.
    importcFunc, importc: "br_des_ct_cbcenc_run", header: "bearssl_block.h".}

proc desCtCbcdecRun*(ctx: var DesCtCbcdecKeys; iv: pointer; data: pointer; len: uint) {.
    importcFunc, importc: "br_des_ct_cbcdec_run", header: "bearssl_block.h".}

type
  DesGenCbcencKeys* {.importc: "br_des_gen_cbcenc_keys", header: "bearssl_block.h",
                     bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    tab* {.importc: "tab".}: DesTabCbcencKeys
    ct* {.importc: "ct".}: DesCtCbcencKeys



type
  DesGenCbcdecKeys* {.importc: "br_des_gen_cbcdec_keys", header: "bearssl_block.h",
                     bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    cTab* {.importc: "c_tab".}: DesTabCbcdecKeys
    cCt* {.importc: "c_ct".}: DesCtCbcdecKeys



type
  Chacha20Run* {.importc: "br_chacha20_run".} = proc (key: pointer; iv: pointer; cc: uint32; data: pointer; len: uint): uint32 {.
      importcFunc.}


proc chacha20CtRun*(key: pointer; iv: pointer; cc: uint32; data: pointer; len: uint): uint32 {.
    importcFunc, importc: "br_chacha20_ct_run", header: "bearssl_block.h".}

proc chacha20Sse2Run*(key: pointer; iv: pointer; cc: uint32; data: pointer; len: uint): uint32 {.
    importcFunc, importc: "br_chacha20_sse2_run", header: "bearssl_block.h".}

proc chacha20Sse2Get*(): Chacha20Run {.importcFunc, importc: "br_chacha20_sse2_get",
                                    header: "bearssl_block.h".}

type
  Poly1305Run* {.importc: "br_poly1305_run".} = proc (key: pointer; iv: pointer; data: pointer; len: uint;
                    aad: pointer; aadLen: uint; tag: pointer; ichacha: Chacha20Run;
                    encrypt: cint) {.importcFunc.}


proc poly1305CtmulRun*(key: pointer; iv: pointer; data: pointer; len: uint;
                      aad: pointer; aadLen: uint; tag: pointer;
                      ichacha: Chacha20Run; encrypt: cint) {.importcFunc,
    importc: "br_poly1305_ctmul_run", header: "bearssl_block.h".}

proc poly1305Ctmul32Run*(key: pointer; iv: pointer; data: pointer; len: uint;
                        aad: pointer; aadLen: uint; tag: pointer;
                        ichacha: Chacha20Run; encrypt: cint) {.importcFunc,
    importc: "br_poly1305_ctmul32_run", header: "bearssl_block.h".}

proc poly1305I15Run*(key: pointer; iv: pointer; data: pointer; len: uint;
                    aad: pointer; aadLen: uint; tag: pointer; ichacha: Chacha20Run;
                    encrypt: cint) {.importcFunc, importc: "br_poly1305_i15_run",
                                   header: "bearssl_block.h".}

proc poly1305CtmulqRun*(key: pointer; iv: pointer; data: pointer; len: uint;
                       aad: pointer; aadLen: uint; tag: pointer;
                       ichacha: Chacha20Run; encrypt: cint) {.importcFunc,
    importc: "br_poly1305_ctmulq_run", header: "bearssl_block.h".}

proc poly1305CtmulqGet*(): Poly1305Run {.importcFunc, importc: "br_poly1305_ctmulq_get",
                                      header: "bearssl_block.h".}
