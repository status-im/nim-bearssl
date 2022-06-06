import
  "."/[blockx, csources, ec, hash, hmac, prf, rand, rsa, x509]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_ssl.h".}
{.used.}

const
  bearSslPath = bearSrcPath / "ssl"

{.compile: bearSslPath / "ssl_ccert_single_ec.c".}
{.compile: bearSslPath / "ssl_ccert_single_rsa.c".}
{.compile: bearSslPath / "ssl_client.c".}
{.compile: bearSslPath / "ssl_client_default_rsapub.c".}
{.compile: bearSslPath / "ssl_client_full.c".}
{.compile: bearSslPath / "ssl_engine.c".}
{.compile: bearSslPath / "ssl_engine_default_aescbc.c".}
{.compile: bearSslPath / "ssl_engine_default_aesccm.c".}
{.compile: bearSslPath / "ssl_engine_default_aesgcm.c".}
{.compile: bearSslPath / "ssl_engine_default_chapol.c".}
{.compile: bearSslPath / "ssl_engine_default_descbc.c".}
{.compile: bearSslPath / "ssl_engine_default_ec.c".}
{.compile: bearSslPath / "ssl_engine_default_ecdsa.c".}
{.compile: bearSslPath / "ssl_engine_default_rsavrfy.c".}
{.compile: bearSslPath / "ssl_hashes.c".}
{.compile: bearSslPath / "ssl_hs_client.c".}
{.compile: bearSslPath / "ssl_hs_server.c".}
{.compile: bearSslPath / "ssl_io.c".}
{.compile: bearSslPath / "ssl_keyexport.c".}
{.compile: bearSslPath / "ssl_lru.c".}
{.compile: bearSslPath / "ssl_rec_cbc.c".}
{.compile: bearSslPath / "ssl_rec_ccm.c".}
{.compile: bearSslPath / "ssl_rec_chapol.c".}
{.compile: bearSslPath / "ssl_rec_gcm.c".}
{.compile: bearSslPath / "ssl_scert_single_ec.c".}
{.compile: bearSslPath / "ssl_scert_single_rsa.c".}
{.compile: bearSslPath / "ssl_server.c".}
{.compile: bearSslPath / "ssl_server_full_ec.c".}
{.compile: bearSslPath / "ssl_server_full_rsa.c".}
{.compile: bearSslPath / "ssl_server_mine2c.c".}
{.compile: bearSslPath / "ssl_server_mine2g.c".}
{.compile: bearSslPath / "ssl_server_minf2c.c".}
{.compile: bearSslPath / "ssl_server_minf2g.c".}
{.compile: bearSslPath / "ssl_server_minr2g.c".}
{.compile: bearSslPath / "ssl_server_minu2g.c".}
{.compile: bearSslPath / "ssl_server_minv2g.c".}

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
        recordLen: int): cint {.importcFunc.}
    decrypt* {.importc: "decrypt".}: proc (ctx: ptr ptr SslrecInClass; recordType: cint;
                                       version: cuint; payload: pointer;
                                       len: ptr int): ptr cuchar {.importcFunc.}

type
  SslrecOutClass* {.importc: "br_sslrec_out_class", header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    maxPlaintext* {.importc: "max_plaintext".}: proc (ctx: ptr ptr SslrecOutClass;
        start: ptr int; `end`: ptr int) {.importcFunc.}
    encrypt* {.importc: "encrypt".}: proc (ctx: ptr ptr SslrecOutClass;
                                       recordType: cint; version: cuint;
                                       plaintext: pointer; len: ptr int): ptr cuchar {.
        importcFunc.}

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
                                 macOutLen: int; iv: pointer) {.importcFunc.}

type
  SslrecOutCbcClass* {.importc: "br_sslrec_out_cbc_class",
                      header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecOutCbcClass;
                                 bcImpl: ptr BlockCbcencClass; bcKey: pointer;
                                 bcKeyLen: int; digImpl: ptr HashClass;
                                 macKey: pointer; macKeyLen: int;
                                 macOutLen: int; iv: pointer) {.importcFunc.}

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
                                 keyLen: int; ghImpl: Ghash; iv: pointer) {.importcFunc.}

type
  SslrecOutGcmClass* {.importc: "br_sslrec_out_gcm_class",
                      header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecOutGcmClass;
                                 bcImpl: ptr BlockCtrClass; key: pointer;
                                 keyLen: int; ghImpl: Ghash; iv: pointer) {.importcFunc.}

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
                                 key: pointer; iv: pointer) {.importcFunc.}

type
  SslrecOutChapolClass* {.importc: "br_sslrec_out_chapol_class",
                         header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ptr ptr SslrecOutChapolClass;
                                 ichacha: Chacha20Run; ipoly: Poly1305Run;
                                 key: pointer; iv: pointer) {.importcFunc.}

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
    hsrun* {.importc: "hsrun".}: proc (ctx: pointer) {.importcFunc.}
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
                        suitesNum: int) {.importcFunc,
    importc: "br_ssl_engine_set_suites", header: "bearssl_ssl.h".}

proc sslEngineSetX509*(cc: ptr SslEngineContext; x509ctx: ptr ptr X509Class) {.inline,
    importcFunc.} =
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
    importcFunc.} =
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

proc sslEngineSetDefaultAesCbc*(cc: ptr SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_aes_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetAesCtr*(cc: ptr SslEngineContext; impl: ptr BlockCtrClass) {.inline,
    importcFunc.} =
  cc.iaesCtr = impl

proc sslEngineSetDefaultAesGcm*(cc: ptr SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_aes_gcm", header: "bearssl_ssl.h".}

proc sslEngineSetDesCbc*(cc: ptr SslEngineContext; implEnc: ptr BlockCbcencClass;
                        implDec: ptr BlockCbcdecClass) {.inline.} =
  cc.idesCbcenc = implEnc
  cc.idesCbcdec = implDec

proc sslEngineSetDefaultDesCbc*(cc: ptr SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_des_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetGhash*(cc: ptr SslEngineContext; impl: Ghash) {.inline.} =
  cc.ighash = impl

proc sslEngineSetChacha20*(cc: ptr SslEngineContext; ichacha: Chacha20Run) {.inline,
    importcFunc.} =
  cc.ichacha = ichacha

proc sslEngineSetPoly1305*(cc: ptr SslEngineContext; ipoly: Poly1305Run) {.inline,
    importcFunc.} =
  cc.ipoly = ipoly

proc sslEngineSetDefaultChapol*(cc: ptr SslEngineContext) {.importcFunc,
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

proc sslEngineSetDefaultEc*(cc: ptr SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_ec", header: "bearssl_ssl.h".}

proc sslEngineGetEc*(cc: ptr SslEngineContext): ptr EcImpl {.inline.} =
  return cc.iec

proc sslEngineSetRsavrfy*(cc: ptr SslEngineContext; irsavrfy: RsaPkcs1Vrfy) {.inline,
    importcFunc.} =
  cc.irsavrfy = irsavrfy

proc sslEngineSetDefaultRsavrfy*(cc: ptr SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_rsavrfy", header: "bearssl_ssl.h".}

proc sslEngineGetRsavrfy*(cc: ptr SslEngineContext): RsaPkcs1Vrfy {.inline.} =
  return cc.irsavrfy

proc sslEngineSetEcdsa*(cc: ptr SslEngineContext; iecdsa: EcdsaVrfy) {.inline.} =
  cc.iecdsa = iecdsa

proc sslEngineSetDefaultEcdsa*(cc: ptr SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_ecdsa", header: "bearssl_ssl.h".}

proc sslEngineGetEcdsa*(cc: ptr SslEngineContext): EcdsaVrfy {.inline.} =
  return cc.iecdsa

proc sslEngineSetBuffer*(cc: ptr SslEngineContext, iobuf: ptr byte,
                         iobufLen: uint, bidi: cint) {.
     importcFunc, importc: "br_ssl_engine_set_buffer", header: "bearssl_ssl.h".}

proc sslEngineSetBuffersBidi*(cc: ptr SslEngineContext, ibuf: ptr byte,
                              ibufLen: uint, obuf: ptr byte, obufLen: uint) {.
    importcFunc, importc: "br_ssl_engine_set_buffers_bidi", header: "bearssl_ssl.h".}

proc sslEngineInjectEntropy*(cc: ptr SslEngineContext; data: pointer; len: int) {.
    importcFunc, importc: "br_ssl_engine_inject_entropy", header: "bearssl_ssl.h".}

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

proc sslEngineCurrentState*(cc: ptr SslEngineContext): cuint {.importcFunc,
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
     importcFunc, importc: "br_ssl_engine_sendapp_buf", header: "bearssl_ssl.h".}

proc sslEngineSendappAck*(cc: ptr SslEngineContext,
                          length: uint) {.
     importcFunc, importc: "br_ssl_engine_sendapp_ack", header: "bearssl_ssl.h".}

proc sslEngineRecvappBuf*(cc: ptr SslEngineContext,
                          length: var uint): ptr byte {.
     importcFunc, importc: "br_ssl_engine_recvapp_buf", header: "bearssl_ssl.h".}

proc sslEngineRecvappAck*(cc: ptr SslEngineContext,
                          length: uint) {.
     importcFunc, importc: "br_ssl_engine_recvapp_ack", header: "bearssl_ssl.h".}

proc sslEngineSendrecBuf*(cc: ptr SslEngineContext,
                          length: var uint): ptr byte {.
     importcFunc, importc: "br_ssl_engine_sendrec_buf", header: "bearssl_ssl.h".}

proc sslEngineSendrecAck*(cc: ptr SslEngineContext,
                          length: uint) {.
     importcFunc, importc: "br_ssl_engine_sendrec_ack", header: "bearssl_ssl.h".}

proc sslEngineRecvrecBuf*(cc: ptr SslEngineContext,
                          length: var uint): ptr byte {.
     importcFunc, importc: "br_ssl_engine_recvrec_buf", header: "bearssl_ssl.h".}

proc sslEngineRecvrecAck*(cc: ptr SslEngineContext; length: uint) {.
     importcFunc, importc: "br_ssl_engine_recvrec_ack", header: "bearssl_ssl.h".}

proc sslEngineFlush*(cc: ptr SslEngineContext; force: cint) {.
     importcFunc, importc: "br_ssl_engine_flush", header: "bearssl_ssl.h".}

proc sslEngineClose*(cc: ptr SslEngineContext) {.
     importcFunc, importc: "br_ssl_engine_close", header: "bearssl_ssl.h".}

proc sslEngineRenegotiate*(cc: ptr SslEngineContext): cint {.
    importcFunc, importc: "br_ssl_engine_renegotiate", header: "bearssl_ssl.h".}

proc sslKeyExport*(cc: ptr SslEngineContext; dst: pointer; len: int; label: cstring;
                   context: pointer; contextLen: int): cint {.importcFunc,
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
        pctx: ptr ptr SslClientCertificateClass) {.importcFunc.}
    startName* {.importc: "start_name".}: proc (
        pctx: ptr ptr SslClientCertificateClass; len: int) {.importcFunc.}
    appendName* {.importc: "append_name".}: proc (
        pctx: ptr ptr SslClientCertificateClass; data: ptr cuchar; len: int) {.importcFunc.}
    endName* {.importc: "end_name".}: proc (pctx: ptr ptr SslClientCertificateClass) {.
        importcFunc.}
    endNameList* {.importc: "end_name_list".}: proc (
        pctx: ptr ptr SslClientCertificateClass) {.importcFunc.}
    choose* {.importc: "choose".}: proc (pctx: ptr ptr SslClientCertificateClass;
                                     cc: ptr SslClientContext; authTypes: uint32;
                                     choices: ptr SslClientCertificate) {.importcFunc.}
    doKeyx* {.importc: "do_keyx".}: proc (pctx: ptr ptr SslClientCertificateClass;
                                      data: ptr cuchar; len: ptr int): uint32 {.
        importcFunc.}
    doSign* {.importc: "do_sign".}: proc (pctx: ptr ptr SslClientCertificateClass;
                                      hashId: cint; hvLen: int; data: ptr cuchar;
                                      len: int): int {.importcFunc.}

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
    importcFunc, importc: "br_ssl_client_init_full", header: "bearssl_ssl.h".}

proc sslClientZero*(cc: ptr SslClientContext) {.importcFunc, importc: "br_ssl_client_zero",
    header: "bearssl_ssl.h".}

proc sslClientSetClientCertificate*(cc: ptr SslClientContext;
                                   pctx: ptr ptr SslClientCertificateClass) {.
    inline.} =
  cc.clientAuthVtable = pctx

proc sslClientSetRsapub*(cc: ptr SslClientContext; irsapub: RsaPublic) {.inline.} =
  cc.irsapub = irsapub

proc sslClientSetDefaultRsapub*(cc: ptr SslClientContext) {.importcFunc,
    importc: "br_ssl_client_set_default_rsapub", header: "bearssl_ssl.h".}

proc sslClientSetMinClienthelloLen*(cc: ptr SslClientContext; len: uint16) {.inline,
    importcFunc.} =
  cc.minClienthelloLen = len

proc sslClientReset*(cc: ptr SslClientContext; serverName: cstring;
                    resumeSession: cint): cint {.importcFunc,
    importc: "br_ssl_client_reset", header: "bearssl_ssl.h".}

proc sslClientForgetSession*(cc: ptr SslClientContext) {.inline.} =
  cc.eng.session.sessionIdLen = 0

proc sslClientSetSingleRsa*(cc: ptr SslClientContext; chain: ptr X509Certificate;
                           chainLen: int; sk: ptr RsaPrivateKey;
                           irsasign: RsaPkcs1Sign) {.importcFunc,
    importc: "br_ssl_client_set_single_rsa", header: "bearssl_ssl.h".}

proc sslClientSetSingleEc*(cc: ptr SslClientContext; chain: ptr X509Certificate;
                          chainLen: int; sk: ptr EcPrivateKey;
                          allowedUsages: cuint; certIssuerKeyType: cuint;
                          iec: ptr EcImpl; iecdsa: EcdsaSign) {.importcFunc,
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
                                     choices: ptr SslServerChoices): cint {.importcFunc.}
    doKeyx* {.importc: "do_keyx".}: proc (pctx: ptr ptr SslServerPolicyClass;
                                      data: ptr cuchar; len: ptr int): uint32 {.
        importcFunc.}
    doSign* {.importc: "do_sign".}: proc (pctx: ptr ptr SslServerPolicyClass;
                                      algoId: cuint; data: ptr cuchar; hvLen: int;
                                      len: int): int {.importcFunc.}

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
                                 params: ptr SslSessionParameters) {.importcFunc.}
    load* {.importc: "load".}: proc (ctx: ptr ptr SslSessionCacheClass;
                                 serverCtx: ptr SslServerContext;
                                 params: ptr SslSessionParameters): cint {.importcFunc.}

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
                            storeLen: int) {.importcFunc,
    importc: "br_ssl_session_cache_lru_init", header: "bearssl_ssl.h".}

proc sslSessionCacheLruForget*(cc: ptr SslSessionCacheLru; id: ptr cuchar) {.importcFunc,
    importc: "br_ssl_session_cache_lru_forget", header: "bearssl_ssl.h".}


proc sslServerInitFullRsa*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                          chainLen: int; sk: ptr RsaPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_full_rsa", header: "bearssl_ssl.h".}

proc sslServerInitFullEc*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; certIssuerKeyType: cuint;
                         sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_full_ec", header: "bearssl_ssl.h".}

proc sslServerInitMinr2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr RsaPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minr2g", header: "bearssl_ssl.h".}

proc sslServerInitMine2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr RsaPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_mine2g", header: "bearssl_ssl.h".}

proc sslServerInitMinf2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minf2g", header: "bearssl_ssl.h".}

proc sslServerInitMinu2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minu2g", header: "bearssl_ssl.h".}

proc sslServerInitMinv2g*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minv2g", header: "bearssl_ssl.h".}

proc sslServerInitMine2c*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr RsaPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_mine2c", header: "bearssl_ssl.h".}

proc sslServerInitMinf2c*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                         chainLen: int; sk: ptr EcPrivateKey) {.importcFunc,
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

proc sslServerZero*(cc: ptr SslServerContext) {.importcFunc, importc: "br_ssl_server_zero",
    header: "bearssl_ssl.h".}

proc sslServerSetPolicy*(cc: ptr SslServerContext;
                        pctx: ptr ptr SslServerPolicyClass) {.inline.} =
  cc.policyVtable = pctx

proc sslServerSetSingleRsa*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                           chainLen: int; sk: ptr RsaPrivateKey;
                           allowedUsages: cuint; irsacore: RsaPrivate;
                           irsasign: RsaPkcs1Sign) {.importcFunc,
    importc: "br_ssl_server_set_single_rsa", header: "bearssl_ssl.h".}

proc sslServerSetSingleEc*(cc: ptr SslServerContext; chain: ptr X509Certificate;
                          chainLen: int; sk: ptr EcPrivateKey;
                          allowedUsages: cuint; certIssuerKeyType: cuint;
                          iec: ptr EcImpl; iecdsa: EcdsaSign) {.importcFunc,
    importc: "br_ssl_server_set_single_ec", header: "bearssl_ssl.h".}

proc sslServerSetTrustAnchorNames*(cc: ptr SslServerContext; taNames: ptr X500Name;
                                  num: int) {.inline.} =
  cc.taNames = taNames
  cc.tas = nil
  cc.numTas = num

proc sslServerSetTrustAnchorNamesAlt*(cc: ptr SslServerContext;
                                     tas: ptr X509TrustAnchor; num: int) {.inline,
    importcFunc.} =
  cc.taNames = nil
  cc.tas = tas
  cc.numTas = num

proc sslServerSetCache*(cc: ptr SslServerContext;
                       vtable: ptr ptr SslSessionCacheClass) {.inline.} =
  cc.cacheVtable = vtable

proc sslServerReset*(cc: ptr SslServerContext): cint {.importcFunc,
    importc: "br_ssl_server_reset", header: "bearssl_ssl.h".}

type
  SslioContext* {.importc: "br_sslio_context", header: "bearssl_ssl.h", bycopy.} = object
    engine* {.importc: "engine".}: ptr SslEngineContext
    lowRead* {.importc: "low_read".}: proc (readContext: pointer; data: ptr cuchar;
                                        len: int): cint {.importcFunc.}
    readContext* {.importc: "read_context".}: pointer
    lowWrite* {.importc: "low_write".}: proc (writeContext: pointer; data: ptr cuchar;
        len: int): cint {.importcFunc.}
    writeContext* {.importc: "write_context".}: pointer


proc sslioInit*(ctx: ptr SslioContext; engine: ptr SslEngineContext; lowRead: proc (
    readContext: pointer; data: ptr cuchar; len: int): cint {.importcFunc.};
               readContext: pointer; lowWrite: proc (writeContext: pointer;
    data: ptr cuchar; len: int): cint {.importcFunc.}; writeContext: pointer) {.importcFunc,
    importc: "br_sslio_init", header: "bearssl_ssl.h".}

proc sslioRead*(cc: ptr SslioContext; dst: pointer; len: int): cint {.importcFunc,
    importc: "br_sslio_read", header: "bearssl_ssl.h".}

proc sslioReadAll*(cc: ptr SslioContext; dst: pointer; len: int): cint {.importcFunc,
    importc: "br_sslio_read_all", header: "bearssl_ssl.h".}

proc sslioWrite*(cc: ptr SslioContext; src: pointer; len: int): cint {.importcFunc,
    importc: "br_sslio_write", header: "bearssl_ssl.h".}

proc sslioWriteAll*(cc: ptr SslioContext; src: pointer; len: int): cint {.importcFunc,
    importc: "br_sslio_write_all", header: "bearssl_ssl.h".}

proc sslioFlush*(cc: ptr SslioContext): cint {.importcFunc, importc: "br_sslio_flush",
    header: "bearssl_ssl.h".}

proc sslioClose*(cc: ptr SslioContext): cint {.importcFunc, importc: "br_sslio_close",
    header: "bearssl_ssl.h".}
