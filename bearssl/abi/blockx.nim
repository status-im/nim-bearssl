import
  "."/[csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_block.h".}
{.used.}

const
  bearSymcPath = bearSrcPath / "symcipher"

{.compile: bearSymcPath / "aes_big_cbcdec.c".}
{.compile: bearSymcPath / "aes_big_cbcenc.c".}
{.compile: bearSymcPath / "aes_big_ctr.c".}
{.compile: bearSymcPath / "aes_big_ctrcbc.c".}
{.compile: bearSymcPath / "aes_big_dec.c".}
{.compile: bearSymcPath / "aes_big_enc.c".}
{.compile: bearSymcPath / "aes_common.c".}
{.compile: bearSymcPath / "aes_ct.c".}
{.compile: bearSymcPath / "aes_ct64.c".}
{.compile: bearSymcPath / "aes_ct64_cbcdec.c".}
{.compile: bearSymcPath / "aes_ct64_cbcenc.c".}
{.compile: bearSymcPath / "aes_ct64_ctr.c".}
{.compile: bearSymcPath / "aes_ct64_ctrcbc.c".}
{.compile: bearSymcPath / "aes_ct64_dec.c".}
{.compile: bearSymcPath / "aes_ct64_enc.c".}
{.compile: bearSymcPath / "aes_ct_cbcdec.c".}
{.compile: bearSymcPath / "aes_ct_cbcenc.c".}
{.compile: bearSymcPath / "aes_ct_ctr.c".}
{.compile: bearSymcPath / "aes_ct_ctrcbc.c".}
{.compile: bearSymcPath / "aes_ct_dec.c".}
{.compile: bearSymcPath / "aes_ct_enc.c".}
{.compile: bearSymcPath / "aes_pwr8.c".}
{.compile: bearSymcPath / "aes_pwr8_cbcdec.c".}
{.compile: bearSymcPath / "aes_pwr8_cbcenc.c".}
{.compile: bearSymcPath / "aes_pwr8_ctr.c".}
{.compile: bearSymcPath / "aes_pwr8_ctrcbc.c".}
{.compile: bearSymcPath / "aes_small_cbcdec.c".}
{.compile: bearSymcPath / "aes_small_cbcenc.c".}
{.compile: bearSymcPath / "aes_small_ctr.c".}
{.compile: bearSymcPath / "aes_small_ctrcbc.c".}
{.compile: bearSymcPath / "aes_small_dec.c".}
{.compile: bearSymcPath / "aes_small_enc.c".}
{.compile: bearSymcPath / "aes_x86ni.c".}
{.compile: bearSymcPath / "aes_x86ni_cbcdec.c".}
{.compile: bearSymcPath / "aes_x86ni_cbcenc.c".}
{.compile: bearSymcPath / "aes_x86ni_ctr.c".}
{.compile: bearSymcPath / "aes_x86ni_ctrcbc.c".}
{.compile: bearSymcPath / "chacha20_ct.c".}
{.compile: bearSymcPath / "chacha20_sse2.c".}
{.compile: bearSymcPath / "des_ct.c".}
{.compile: bearSymcPath / "des_ct_cbcdec.c".}
{.compile: bearSymcPath / "des_ct_cbcenc.c".}
{.compile: bearSymcPath / "des_support.c".}
{.compile: bearSymcPath / "des_tab.c".}
{.compile: bearSymcPath / "des_tab_cbcdec.c".}
{.compile: bearSymcPath / "des_tab_cbcenc.c".}
{.compile: bearSymcPath / "poly1305_ctmul.c".}
{.compile: bearSymcPath / "poly1305_ctmul32.c".}
{.compile: bearSymcPath / "poly1305_ctmulq.c".}
{.compile: bearSymcPath / "poly1305_i15.c".}

type
  BlockCbcencClass* {.importc: "br_block_cbcenc_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCbcencClass; key: pointer;
                                 keyLen: int) {.importcFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCbcencClass; iv: pointer;
                               data: pointer; len: int) {.importcFunc.}

type
  BlockCbcdecClass* {.importc: "br_block_cbcdec_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCbcdecClass; key: pointer;
                                 keyLen: int) {.importcFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCbcdecClass; iv: pointer;
                               data: pointer; len: int) {.importcFunc.}

type
  BlockCtrClass* {.importc: "br_block_ctr_class", header: "bearssl_block.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCtrClass; key: pointer;
                                 keyLen: int) {.importcFunc.}
    run* {.importc: "run".}: proc (ctx: ptr ptr BlockCtrClass; iv: pointer; cc: uint32;
                               data: pointer; len: int): uint32 {.importcFunc.}

type
  BlockCtrcbcClass* {.importc: "br_block_ctrcbc_class", header: "bearssl_block.h",
                     bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    blockSize* {.importc: "block_size".}: cuint
    logBlockSize* {.importc: "log_block_size".}: cuint
    init* {.importc: "init".}: proc (ctx: ptr ptr BlockCtrcbcClass; key: pointer;
                                 keyLen: int) {.importcFunc.}
    encrypt* {.importc: "encrypt".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                                       cbcmac: pointer; data: pointer; len: int) {.
        importcFunc.}
    decrypt* {.importc: "decrypt".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                                       cbcmac: pointer; data: pointer; len: int) {.
        importcFunc.}
    ctr* {.importc: "ctr".}: proc (ctx: ptr ptr BlockCtrcbcClass; ctr: pointer;
                               data: pointer; len: int) {.importcFunc.}
    mac* {.importc: "mac".}: proc (ctx: ptr ptr BlockCtrcbcClass; cbcmac: pointer;
                               data: pointer; len: int) {.importcFunc.}

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

proc aesBigCbcencInit*(ctx: ptr AesBigCbcencKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_big_cbcenc_init", header: "bearssl_block.h".}

proc aesBigCbcdecInit*(ctx: ptr AesBigCbcdecKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_big_cbcdec_init", header: "bearssl_block.h".}

proc aesBigCtrInit*(ctx: ptr AesBigCtrKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_big_ctr_init", header: "bearssl_block.h".}

proc aesBigCtrcbcInit*(ctx: ptr AesBigCtrcbcKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_big_ctrcbc_init", header: "bearssl_block.h".}

proc aesBigCbcencRun*(ctx: ptr AesBigCbcencKeys; iv: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_aes_big_cbcenc_run", header: "bearssl_block.h".}

proc aesBigCbcdecRun*(ctx: ptr AesBigCbcdecKeys; iv: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_aes_big_cbcdec_run", header: "bearssl_block.h".}

proc aesBigCtrRun*(ctx: ptr AesBigCtrKeys; iv: pointer; cc: uint32; data: pointer;
                  len: int): uint32 {.importcFunc, importc: "br_aes_big_ctr_run",
                                      header: "bearssl_block.h".}

proc aesBigCtrcbcEncrypt*(ctx: ptr AesBigCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                         data: pointer; len: int) {.importcFunc,
    importc: "br_aes_big_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesBigCtrcbcDecrypt*(ctx: ptr AesBigCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                         data: pointer; len: int) {.importcFunc,
    importc: "br_aes_big_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesBigCtrcbcCtr*(ctx: ptr AesBigCtrcbcKeys; ctr: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_aes_big_ctrcbc_ctr", header: "bearssl_block.h".}

proc aesBigCtrcbcMac*(ctx: ptr AesBigCtrcbcKeys; cbcmac: pointer; data: pointer;
                     len: int) {.importcFunc, importc: "br_aes_big_ctrcbc_mac",
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

proc aesSmallCbcencInit*(ctx: ptr AesSmallCbcencKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_small_cbcenc_init", header: "bearssl_block.h".}

proc aesSmallCbcdecInit*(ctx: ptr AesSmallCbcdecKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_small_cbcdec_init", header: "bearssl_block.h".}

proc aesSmallCtrInit*(ctx: ptr AesSmallCtrKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_small_ctr_init", header: "bearssl_block.h".}

proc aesSmallCtrcbcInit*(ctx: ptr AesSmallCtrcbcKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_small_ctrcbc_init", header: "bearssl_block.h".}

proc aesSmallCbcencRun*(ctx: ptr AesSmallCbcencKeys; iv: pointer; data: pointer;
                       len: int) {.importcFunc, importc: "br_aes_small_cbcenc_run",
                                   header: "bearssl_block.h".}

proc aesSmallCbcdecRun*(ctx: ptr AesSmallCbcdecKeys; iv: pointer; data: pointer;
                       len: int) {.importcFunc, importc: "br_aes_small_cbcdec_run",
                                   header: "bearssl_block.h".}

proc aesSmallCtrRun*(ctx: ptr AesSmallCtrKeys; iv: pointer; cc: uint32; data: pointer;
                    len: int): uint32 {.importcFunc, importc: "br_aes_small_ctr_run",
                                        header: "bearssl_block.h".}

proc aesSmallCtrcbcEncrypt*(ctx: ptr AesSmallCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: int) {.importcFunc,
    importc: "br_aes_small_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesSmallCtrcbcDecrypt*(ctx: ptr AesSmallCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: int) {.importcFunc,
    importc: "br_aes_small_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesSmallCtrcbcCtr*(ctx: ptr AesSmallCtrcbcKeys; ctr: pointer; data: pointer;
                       len: int) {.importcFunc, importc: "br_aes_small_ctrcbc_ctr",
                                   header: "bearssl_block.h".}

proc aesSmallCtrcbcMac*(ctx: ptr AesSmallCtrcbcKeys; cbcmac: pointer; data: pointer;
                       len: int) {.importcFunc, importc: "br_aes_small_ctrcbc_mac",
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

proc aesCtCbcencInit*(ctx: ptr AesCtCbcencKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct_cbcenc_init", header: "bearssl_block.h".}

proc aesCtCbcdecInit*(ctx: ptr AesCtCbcdecKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct_cbcdec_init", header: "bearssl_block.h".}

proc aesCtCtrInit*(ctx: ptr AesCtCtrKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct_ctr_init", header: "bearssl_block.h".}

proc aesCtCtrcbcInit*(ctx: ptr AesCtCtrcbcKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct_ctrcbc_init", header: "bearssl_block.h".}

proc aesCtCbcencRun*(ctx: ptr AesCtCbcencKeys; iv: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_aes_ct_cbcenc_run", header: "bearssl_block.h".}

proc aesCtCbcdecRun*(ctx: ptr AesCtCbcdecKeys; iv: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_aes_ct_cbcdec_run", header: "bearssl_block.h".}

proc aesCtCtrRun*(ctx: ptr AesCtCtrKeys; iv: pointer; cc: uint32; data: pointer;
                 len: int): uint32 {.importcFunc, importc: "br_aes_ct_ctr_run",
                                     header: "bearssl_block.h".}

proc aesCtCtrcbcEncrypt*(ctx: ptr AesCtCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                        data: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesCtCtrcbcDecrypt*(ctx: ptr AesCtCtrcbcKeys; ctr: pointer; cbcmac: pointer;
                        data: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesCtCtrcbcCtr*(ctx: ptr AesCtCtrcbcKeys; ctr: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_aes_ct_ctrcbc_ctr", header: "bearssl_block.h".}

proc aesCtCtrcbcMac*(ctx: ptr AesCtCtrcbcKeys; cbcmac: pointer; data: pointer;
                    len: int) {.importcFunc, importc: "br_aes_ct_ctrcbc_mac",
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

proc aesCt64CbcencInit*(ctx: ptr AesCt64CbcencKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct64_cbcenc_init", header: "bearssl_block.h".}

proc aesCt64CbcdecInit*(ctx: ptr AesCt64CbcdecKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct64_cbcdec_init", header: "bearssl_block.h".}

proc aesCt64CtrInit*(ctx: ptr AesCt64CtrKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct64_ctr_init", header: "bearssl_block.h".}

proc aesCt64CtrcbcInit*(ctx: ptr AesCt64CtrcbcKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct64_ctrcbc_init", header: "bearssl_block.h".}

proc aesCt64CbcencRun*(ctx: ptr AesCt64CbcencKeys; iv: pointer; data: pointer;
                      len: int) {.importcFunc, importc: "br_aes_ct64_cbcenc_run",
                                  header: "bearssl_block.h".}

proc aesCt64CbcdecRun*(ctx: ptr AesCt64CbcdecKeys; iv: pointer; data: pointer;
                      len: int) {.importcFunc, importc: "br_aes_ct64_cbcdec_run",
                                  header: "bearssl_block.h".}

proc aesCt64CtrRun*(ctx: ptr AesCt64CtrKeys; iv: pointer; cc: uint32; data: pointer;
                   len: int): uint32 {.importcFunc, importc: "br_aes_ct64_ctr_run",
                                       header: "bearssl_block.h".}

proc aesCt64CtrcbcEncrypt*(ctx: ptr AesCt64CtrcbcKeys; ctr: pointer; cbcmac: pointer;
                          data: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct64_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesCt64CtrcbcDecrypt*(ctx: ptr AesCt64CtrcbcKeys; ctr: pointer; cbcmac: pointer;
                          data: pointer; len: int) {.importcFunc,
    importc: "br_aes_ct64_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesCt64CtrcbcCtr*(ctx: ptr AesCt64CtrcbcKeys; ctr: pointer; data: pointer;
                      len: int) {.importcFunc, importc: "br_aes_ct64_ctrcbc_ctr",
                                  header: "bearssl_block.h".}

proc aesCt64CtrcbcMac*(ctx: ptr AesCt64CtrcbcKeys; cbcmac: pointer; data: pointer;
                      len: int) {.importcFunc, importc: "br_aes_ct64_ctrcbc_mac",
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

proc aesX86niCbcencInit*(ctx: ptr AesX86niCbcencKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_x86ni_cbcenc_init", header: "bearssl_block.h".}

proc aesX86niCbcdecInit*(ctx: ptr AesX86niCbcdecKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_x86ni_cbcdec_init", header: "bearssl_block.h".}

proc aesX86niCtrInit*(ctx: ptr AesX86niCtrKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_x86ni_ctr_init", header: "bearssl_block.h".}

proc aesX86niCtrcbcInit*(ctx: ptr AesX86niCtrcbcKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_x86ni_ctrcbc_init", header: "bearssl_block.h".}

proc aesX86niCbcencRun*(ctx: ptr AesX86niCbcencKeys; iv: pointer; data: pointer;
                       len: int) {.importcFunc, importc: "br_aes_x86ni_cbcenc_run",
                                   header: "bearssl_block.h".}

proc aesX86niCbcdecRun*(ctx: ptr AesX86niCbcdecKeys; iv: pointer; data: pointer;
                       len: int) {.importcFunc, importc: "br_aes_x86ni_cbcdec_run",
                                   header: "bearssl_block.h".}

proc aesX86niCtrRun*(ctx: ptr AesX86niCtrKeys; iv: pointer; cc: uint32; data: pointer;
                    len: int): uint32 {.importcFunc, importc: "br_aes_x86ni_ctr_run",
                                        header: "bearssl_block.h".}

proc aesX86niCtrcbcEncrypt*(ctx: ptr AesX86niCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: int) {.importcFunc,
    importc: "br_aes_x86ni_ctrcbc_encrypt", header: "bearssl_block.h".}

proc aesX86niCtrcbcDecrypt*(ctx: ptr AesX86niCtrcbcKeys; ctr: pointer;
                           cbcmac: pointer; data: pointer; len: int) {.importcFunc,
    importc: "br_aes_x86ni_ctrcbc_decrypt", header: "bearssl_block.h".}

proc aesX86niCtrcbcCtr*(ctx: ptr AesX86niCtrcbcKeys; ctr: pointer; data: pointer;
                       len: int) {.importcFunc, importc: "br_aes_x86ni_ctrcbc_ctr",
                                   header: "bearssl_block.h".}

proc aesX86niCtrcbcMac*(ctx: ptr AesX86niCtrcbcKeys; cbcmac: pointer; data: pointer;
                       len: int) {.importcFunc, importc: "br_aes_x86ni_ctrcbc_mac",
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

proc aesPwr8CbcencInit*(ctx: ptr AesPwr8CbcencKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_pwr8_cbcenc_init", header: "bearssl_block.h".}

proc aesPwr8CbcdecInit*(ctx: ptr AesPwr8CbcdecKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_pwr8_cbcdec_init", header: "bearssl_block.h".}

proc aesPwr8CtrInit*(ctx: ptr AesPwr8CtrKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_aes_pwr8_ctr_init", header: "bearssl_block.h".}

proc aesPwr8CbcencRun*(ctx: ptr AesPwr8CbcencKeys; iv: pointer; data: pointer;
                      len: int) {.importcFunc, importc: "br_aes_pwr8_cbcenc_run",
                                  header: "bearssl_block.h".}

proc aesPwr8CbcdecRun*(ctx: ptr AesPwr8CbcdecKeys; iv: pointer; data: pointer;
                      len: int) {.importcFunc, importc: "br_aes_pwr8_cbcdec_run",
                                  header: "bearssl_block.h".}

proc aesPwr8CtrRun*(ctx: ptr AesPwr8CtrKeys; iv: pointer; cc: uint32; data: pointer;
                   len: int): uint32 {.importcFunc, importc: "br_aes_pwr8_ctr_run",
                                       header: "bearssl_block.h".}

proc aesPwr8CbcencGetVtable*(): ptr BlockCbcencClass {.importcFunc,
    importc: "br_aes_pwr8_cbcenc_get_vtable", header: "bearssl_block.h".}

proc aesPwr8CbcdecGetVtable*(): ptr BlockCbcdecClass {.importcFunc,
    importc: "br_aes_pwr8_cbcdec_get_vtable", header: "bearssl_block.h".}

proc aesPwr8CtrGetVtable*(): ptr BlockCtrClass {.importcFunc,
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

proc desTabCbcencInit*(ctx: ptr DesTabCbcencKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_des_tab_cbcenc_init", header: "bearssl_block.h".}

proc desTabCbcdecInit*(ctx: ptr DesTabCbcdecKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_des_tab_cbcdec_init", header: "bearssl_block.h".}

proc desTabCbcencRun*(ctx: ptr DesTabCbcencKeys; iv: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_des_tab_cbcenc_run", header: "bearssl_block.h".}

proc desTabCbcdecRun*(ctx: ptr DesTabCbcdecKeys; iv: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_des_tab_cbcdec_run", header: "bearssl_block.h".}

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

proc desCtCbcencInit*(ctx: ptr DesCtCbcencKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_des_ct_cbcenc_init", header: "bearssl_block.h".}

proc desCtCbcdecInit*(ctx: ptr DesCtCbcdecKeys; key: pointer; len: int) {.importcFunc,
    importc: "br_des_ct_cbcdec_init", header: "bearssl_block.h".}

proc desCtCbcencRun*(ctx: ptr DesCtCbcencKeys; iv: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_des_ct_cbcenc_run", header: "bearssl_block.h".}

proc desCtCbcdecRun*(ctx: ptr DesCtCbcdecKeys; iv: pointer; data: pointer; len: int) {.
    importcFunc, importc: "br_des_ct_cbcdec_run", header: "bearssl_block.h".}

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
      importcFunc.}

proc chacha20CtRun*(key: pointer; iv: pointer; cc: uint32; data: pointer; len: int): uint32 {.
    importcFunc, importc: "br_chacha20_ct_run", header: "bearssl_block.h".}

proc chacha20Sse2Run*(key: pointer; iv: pointer; cc: uint32; data: pointer; len: int): uint32 {.
    importcFunc, importc: "br_chacha20_sse2_run", header: "bearssl_block.h".}

proc chacha20Sse2Get*(): Chacha20Run {.importcFunc, importc: "br_chacha20_sse2_get",
                                    header: "bearssl_block.h".}

type
  Poly1305Run* = proc (key: pointer; iv: pointer; data: pointer; len: int; aad: pointer;
                    aadLen: int; tag: pointer; ichacha: Chacha20Run; encrypt: cint) {.
      importcFunc.}

proc poly1305CtmulRun*(key: pointer; iv: pointer; data: pointer; len: int;
                      aad: pointer; aadLen: int; tag: pointer; ichacha: Chacha20Run;
                      encrypt: cint) {.importcFunc, importc: "br_poly1305_ctmul_run",
                                     header: "bearssl_block.h".}

proc poly1305Ctmul32Run*(key: pointer; iv: pointer; data: pointer; len: int;
                        aad: pointer; aadLen: int; tag: pointer;
                        ichacha: Chacha20Run; encrypt: cint) {.importcFunc,
    importc: "br_poly1305_ctmul32_run", header: "bearssl_block.h".}

proc poly1305I15Run*(key: pointer; iv: pointer; data: pointer; len: int; aad: pointer;
                    aadLen: int; tag: pointer; ichacha: Chacha20Run; encrypt: cint) {.
    importcFunc, importc: "br_poly1305_i15_run", header: "bearssl_block.h".}

proc poly1305CtmulqRun*(key: pointer; iv: pointer; data: pointer; len: int;
                       aad: pointer; aadLen: int; tag: pointer;
                       ichacha: Chacha20Run; encrypt: cint) {.importcFunc,
    importc: "br_poly1305_ctmulq_run", header: "bearssl_block.h".}

proc poly1305CtmulqGet*(): Poly1305Run {.importcFunc, importc: "br_poly1305_ctmulq_get",
                                      header: "bearssl_block.h".}

