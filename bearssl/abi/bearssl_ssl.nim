import
  ./[
    bearssl_aead, bearssl_block, bearssl_ec, bearssl_hash, bearssl_hmac, bearssl_prf,
    bearssl_rand, bearssl_rsa, bearssl_x509, consttypes, csources,
  ]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

{.compile: currentSourceDir() & "/bearssl_ssl.c".}

# Unity conflicts
{.compile: bearSrcPath & "ssl/ssl_ccert_single_rsa.c".}
{.compile: bearSrcPath & "ssl/ssl_hs_server.c".}
{.compile: bearSrcPath & "ssl/ssl_scert_single_rsa.c".}

type
  ConstPtrConstPtrSslrecInClass* {.importc: "const br_sslrec_in_class *const *", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrConstPtrSslrecOutClass* {.importc: "const br_sslrec_out_class *const *", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslClientCertificateClass* {.importc: "const br_ssl_client_certificate_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslServerPolicyClass* {.importc: "const br_ssl_server_policy_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  SslSessionCacheClassPointerConst* {.importc: "const br_ssl_session_cache_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecInCbcClass* {.importc: "const br_sslrec_in_cbc_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecInCcmClass* {.importc: "const br_sslrec_in_ccm_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecInChapolClass* {.importc: "const br_sslrec_in_chapol_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecInClass* {.importc: "const br_sslrec_in_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecInGcmClass* {.importc: "const br_sslrec_in_gcm_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecOutCbcClass* {.importc: "const br_sslrec_out_cbc_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecOutCcmClass* {.importc: "const br_sslrec_out_ccm_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecOutChapolClass* {.importc: "const br_sslrec_out_chapol_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecOutClass* {.importc: "const br_sslrec_out_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrPtrSslrecOutGcmClass* {.importc: "const br_sslrec_out_gcm_class**", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrSslClientContext* {.importc: "const br_ssl_client_context *", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrSslServerContext* {.importc: "const br_ssl_server_context *", header: "bearssl_ssl.h", bycopy.} = pointer
  ConstPtrSslSessionParameters* {.importc: "const br_ssl_session_parameters *", header: "bearssl_ssl.h", bycopy.} = pointer
  ProtocolNamesPointerConst* {.importc: "const char **", header: "bearssl_ssl.h", bycopy.} = pointer

const
  SSL_BUFSIZE_INPUT* = (16384 + 325)


const
  SSL_BUFSIZE_OUTPUT* = (16384 + 85)


const
  SSL_BUFSIZE_MONO* = SSL_BUFSIZE_INPUT


const
  SSL_BUFSIZE_BIDI* = (SSL_BUFSIZE_INPUT + SSL_BUFSIZE_OUTPUT)


const
  SSL30* = 0x0300


const
  TLS10* = 0x0301


const
  TLS11* = 0x0302


const
  TLS12* = 0x0303


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
    contextSize* {.importc: "context_size".}: csize_t
    checkLength* {.importc: "check_length".}: proc (
        ctx: ConstPtrConstPtrSslrecInClass; recordLen: csize_t): cint {.importcFunc.}
    decrypt* {.importc: "decrypt".}: proc (ctx: ConstPtrPtrSslrecInClass;
                                       recordType: cint; version: cuint;
                                       payload: pointer; len: var csize_t): ptr byte {.
        importcFunc.}



type
  SslrecOutClass* {.importc: "br_sslrec_out_class", header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: csize_t
    maxPlaintext* {.importc: "max_plaintext".}: proc (
        ctx: ConstPtrConstPtrSslrecOutClass; start: ptr csize_t; `end`: ptr csize_t) {.
        importcFunc.}
    encrypt* {.importc: "encrypt".}: proc (ctx: ConstPtrPtrSslrecOutClass;
                                       recordType: cint; version: cuint;
                                       plaintext: pointer; len: var csize_t): ptr byte {.
        importcFunc.}



type
  SslrecOutClearContext* {.importc: "br_sslrec_out_clear_context",
                          header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslrecOutClass



var sslrecOutClearVtable* {.importc: "br_sslrec_out_clear_vtable", header: "bearssl_ssl.h".}: SslrecOutClass


type
  SslrecInCbcClass* {.importc: "br_sslrec_in_cbc_class", header: "bearssl_ssl.h",
                     bycopy.} = object
    inner* {.importc: "inner".}: SslrecInClass
    init* {.importc: "init".}: proc (ctx: ConstPtrPtrSslrecInCbcClass;
                                 bcImpl: ConstPtrBlockCbcdecClass;
                                 bcKey: ConstPointer; bcKeyLen: csize_t;
                                 digImpl: ConstPtrHashClass; macKey: ConstPointer;
                                 macKeyLen: csize_t; macOutLen: csize_t;
                                 iv: ConstPointer) {.importcFunc.}



type
  SslrecOutCbcClass* {.importc: "br_sslrec_out_cbc_class",
                      header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ConstPtrPtrSslrecOutCbcClass;
                                 bcImpl: ConstPtrBlockCbcencClass;
                                 bcKey: ConstPointer; bcKeyLen: csize_t;
                                 digImpl: ConstPtrHashClass; macKey: ConstPointer;
                                 macKeyLen: csize_t; macOutLen: csize_t;
                                 iv: ConstPointer) {.importcFunc.}



type
  INNER_C_UNION_bearssl_ssl_1* {.importc: "br_sslrec_in_cbc_context::no_name",
                                  header: "bearssl_ssl.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcdecClass
    aes* {.importc: "aes".}: AesGenCbcdecKeys
    des* {.importc: "des".}: DesGenCbcdecKeys

  SslrecInCbcContext* {.importc: "br_sslrec_in_cbc_context",
                       header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslrecInCbcClass
    seq* {.importc: "seq".}: uint64
    bc* {.importc: "bc".}: INNER_C_UNION_bearssl_ssl_1
    mac* {.importc: "mac".}: HmacKeyContext
    macLen* {.importc: "mac_len".}: csize_t
    iv* {.importc: "iv".}: array[16, byte]
    explicitIV* {.importc: "explicit_IV".}: cint



var sslrecInCbcVtable* {.importc: "br_sslrec_in_cbc_vtable", header: "bearssl_ssl.h".}: SslrecInCbcClass


type
  INNER_C_UNION_bearssl_ssl_2* {.importc: "br_sslrec_out_cbc_context::no_name",
                                  header: "bearssl_ssl.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCbcencClass
    aes* {.importc: "aes".}: AesGenCbcencKeys
    des* {.importc: "des".}: DesGenCbcencKeys

  SslrecOutCbcContext* {.importc: "br_sslrec_out_cbc_context",
                        header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslrecOutCbcClass
    seq* {.importc: "seq".}: uint64
    bc* {.importc: "bc".}: INNER_C_UNION_bearssl_ssl_2
    mac* {.importc: "mac".}: HmacKeyContext
    macLen* {.importc: "mac_len".}: csize_t
    iv* {.importc: "iv".}: array[16, byte]
    explicitIV* {.importc: "explicit_IV".}: cint



var sslrecOutCbcVtable* {.importc: "br_sslrec_out_cbc_vtable", header: "bearssl_ssl.h".}: SslrecOutCbcClass


type
  SslrecInGcmClass* {.importc: "br_sslrec_in_gcm_class", header: "bearssl_ssl.h",
                     bycopy.} = object
    inner* {.importc: "inner".}: SslrecInClass
    init* {.importc: "init".}: proc (ctx: ConstPtrPtrSslrecInGcmClass;
                                 bcImpl: ConstPtrBlockCtrClass; key: ConstPointer;
                                 keyLen: csize_t; ghImpl: Ghash; iv: ConstPointer) {.
        importcFunc.}



type
  SslrecOutGcmClass* {.importc: "br_sslrec_out_gcm_class",
                      header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ConstPtrPtrSslrecOutGcmClass;
                                 bcImpl: ConstPtrBlockCtrClass; key: ConstPointer;
                                 keyLen: csize_t; ghImpl: Ghash; iv: ConstPointer) {.
        importcFunc.}



type
  INNER_C_UNION_bearssl_ssl_3* {.importc: "br_sslrec_gcm_context::no_name",
                                  header: "bearssl_ssl.h", bycopy, union.} = object
    gen* {.importc: "gen".}: ConstPointer
    `in`* {.importc: "in".}: ptr SslrecInGcmClass
    `out`* {.importc: "out".}: ptr SslrecOutGcmClass

  INNER_C_UNION_bearssl_ssl_4* {.importc: "br_sslrec_gcm_context::no_name",
                                  header: "bearssl_ssl.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrClass
    aes* {.importc: "aes".}: AesGenCtrKeys

  SslrecGcmContext* {.importc: "br_sslrec_gcm_context", header: "bearssl_ssl.h",
                     bycopy.} = object
    vtable* {.importc: "vtable".}: INNER_C_UNION_bearssl_ssl_3
    seq* {.importc: "seq".}: uint64
    bc* {.importc: "bc".}: INNER_C_UNION_bearssl_ssl_4
    gh* {.importc: "gh".}: Ghash
    iv* {.importc: "iv".}: array[4, byte]
    h* {.importc: "h".}: array[16, byte]



var sslrecInGcmVtable* {.importc: "br_sslrec_in_gcm_vtable", header: "bearssl_ssl.h".}: SslrecInGcmClass


var sslrecOutGcmVtable* {.importc: "br_sslrec_out_gcm_vtable", header: "bearssl_ssl.h".}: SslrecOutGcmClass


type
  SslrecInChapolClass* {.importc: "br_sslrec_in_chapol_class",
                        header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecInClass
    init* {.importc: "init".}: proc (ctx: ConstPtrPtrSslrecInChapolClass;
                                 ichacha: Chacha20Run; ipoly: Poly1305Run;
                                 key: ConstPointer; iv: ConstPointer) {.importcFunc.}



type
  SslrecOutChapolClass* {.importc: "br_sslrec_out_chapol_class",
                         header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ConstPtrPtrSslrecOutChapolClass;
                                 ichacha: Chacha20Run; ipoly: Poly1305Run;
                                 key: ConstPointer; iv: ConstPointer) {.importcFunc.}



type
  INNER_C_UNION_bearssl_ssl_5* {.importc: "br_sslrec_chapol_context::no_name",
                                  header: "bearssl_ssl.h", bycopy, union.} = object
    gen* {.importc: "gen".}: ConstPointer
    `in`* {.importc: "in".}: ptr SslrecInChapolClass
    `out`* {.importc: "out".}: ptr SslrecOutChapolClass

  SslrecChapolContext* {.importc: "br_sslrec_chapol_context",
                        header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: INNER_C_UNION_bearssl_ssl_5
    seq* {.importc: "seq".}: uint64
    key* {.importc: "key".}: array[32, byte]
    iv* {.importc: "iv".}: array[12, byte]
    ichacha* {.importc: "ichacha".}: Chacha20Run
    ipoly* {.importc: "ipoly".}: Poly1305Run



var sslrecInChapolVtable* {.importc: "br_sslrec_in_chapol_vtable", header: "bearssl_ssl.h".}: SslrecInChapolClass


var sslrecOutChapolVtable* {.importc: "br_sslrec_out_chapol_vtable", header: "bearssl_ssl.h".}: SslrecOutChapolClass


type
  SslrecInCcmClass* {.importc: "br_sslrec_in_ccm_class", header: "bearssl_ssl.h",
                     bycopy.} = object
    inner* {.importc: "inner".}: SslrecInClass
    init* {.importc: "init".}: proc (ctx: ConstPtrPtrSslrecInCcmClass;
                                 bcImpl: ConstPtrBlockCtrcbcClass;
                                 key: ConstPointer; keyLen: csize_t;
                                 iv: ConstPointer; tagLen: csize_t) {.importcFunc.}



type
  SslrecOutCcmClass* {.importc: "br_sslrec_out_ccm_class",
                      header: "bearssl_ssl.h", bycopy.} = object
    inner* {.importc: "inner".}: SslrecOutClass
    init* {.importc: "init".}: proc (ctx: ConstPtrPtrSslrecOutCcmClass;
                                 bcImpl: ConstPtrBlockCtrcbcClass;
                                 key: ConstPointer; keyLen: csize_t;
                                 iv: ConstPointer; tagLen: csize_t) {.importcFunc.}



type
  INNER_C_UNION_bearssl_ssl_6* {.importc: "br_sslrec_ccm_context::no_name",
                                  header: "bearssl_ssl.h", bycopy, union.} = object
    gen* {.importc: "gen".}: ConstPointer
    `in`* {.importc: "in".}: ptr SslrecInCcmClass
    `out`* {.importc: "out".}: ptr SslrecOutCcmClass

  INNER_C_UNION_bearssl_ssl_7* {.importc: "br_sslrec_ccm_context::no_name",
                                  header: "bearssl_ssl.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr BlockCtrcbcClass
    aes* {.importc: "aes".}: AesGenCtrcbcKeys

  SslrecCcmContext* {.importc: "br_sslrec_ccm_context", header: "bearssl_ssl.h",
                     bycopy.} = object
    vtable* {.importc: "vtable".}: INNER_C_UNION_bearssl_ssl_6
    seq* {.importc: "seq".}: uint64
    bc* {.importc: "bc".}: INNER_C_UNION_bearssl_ssl_7
    iv* {.importc: "iv".}: array[4, byte]
    tagLen* {.importc: "tag_len".}: csize_t



var sslrecInCcmVtable* {.importc: "br_sslrec_in_ccm_vtable", header: "bearssl_ssl.h".}: SslrecInCcmClass


var sslrecOutCcmVtable* {.importc: "br_sslrec_out_ccm_vtable", header: "bearssl_ssl.h".}: SslrecOutCcmClass


type
  SslSessionParameters* {.importc: "br_ssl_session_parameters",
                         header: "bearssl_ssl.h", bycopy.} = object
    sessionId* {.importc: "session_id".}: array[32, byte]
    sessionIdLen* {.importc: "session_id_len".}: byte
    version* {.importc: "version".}: uint16
    cipherSuite* {.importc: "cipher_suite".}: uint16
    masterSecret* {.importc: "master_secret".}: array[48, byte]



const
  MAX_CIPHER_SUITES* = 48


type
  INNER_C_UNION_bearssl_ssl_8* {.importc: "br_ssl_engine_context::no_name",
                                   header: "bearssl_ssl.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr SslrecInClass
    cbc* {.importc: "cbc".}: SslrecInCbcContext
    gcm* {.importc: "gcm".}: SslrecGcmContext
    chapol* {.importc: "chapol".}: SslrecChapolContext
    ccm* {.importc: "ccm".}: SslrecCcmContext

  INNER_C_UNION_bearssl_ssl_9* {.importc: "br_ssl_engine_context::no_name",
                                   header: "bearssl_ssl.h", bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr SslrecOutClass
    clear* {.importc: "clear".}: SslrecOutClearContext
    cbc* {.importc: "cbc".}: SslrecOutCbcContext
    gcm* {.importc: "gcm".}: SslrecGcmContext
    chapol* {.importc: "chapol".}: SslrecChapolContext
    ccm* {.importc: "ccm".}: SslrecCcmContext

  INNER_C_STRUCT_bearssl_ssl_10* {.importc: "br_ssl_engine_context::no_name",
                                    header: "bearssl_ssl.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ConstPtrByte

  SslEngineContext* {.importc: "br_ssl_engine_context", header: "bearssl_ssl.h",
                     bycopy.} = object
    err* {.importc: "err".}: cint
    ibuf* {.importc: "ibuf".}: ptr byte
    obuf* {.importc: "obuf".}: ptr byte
    ibufLen* {.importc: "ibuf_len".}: csize_t
    obufLen* {.importc: "obuf_len".}: csize_t
    maxFragLen* {.importc: "max_frag_len".}: uint16
    logMaxFragLen* {.importc: "log_max_frag_len".}: byte
    peerLogMaxFragLen* {.importc: "peer_log_max_frag_len".}: byte
    ixa* {.importc: "ixa".}: csize_t
    ixb* {.importc: "ixb".}: csize_t
    ixc* {.importc: "ixc".}: csize_t
    oxa* {.importc: "oxa".}: csize_t
    oxb* {.importc: "oxb".}: csize_t
    oxc* {.importc: "oxc".}: csize_t
    iomode* {.importc: "iomode".}: byte
    incrypt* {.importc: "incrypt".}: byte
    shutdownRecv* {.importc: "shutdown_recv".}: byte
    recordTypeIn* {.importc: "record_type_in".}: byte
    recordTypeOut* {.importc: "record_type_out".}: byte
    versionIn* {.importc: "version_in".}: uint16
    versionOut* {.importc: "version_out".}: uint16
    `in`* {.importc: "in".}: INNER_C_UNION_bearssl_ssl_8
    `out`* {.importc: "out".}: INNER_C_UNION_bearssl_ssl_9
    applicationData* {.importc: "application_data".}: byte
    rng* {.importc: "rng".}: HmacDrbgContext
    rngInitDone* {.importc: "rng_init_done".}: cint
    rngOsRandDone* {.importc: "rng_os_rand_done".}: cint
    versionMin* {.importc: "version_min".}: uint16
    versionMax* {.importc: "version_max".}: uint16
    suitesBuf* {.importc: "suites_buf".}: array[MAX_CIPHER_SUITES, uint16]
    suitesNum* {.importc: "suites_num".}: byte
    serverName* {.importc: "server_name".}: array[256, char]
    clientRandom* {.importc: "client_random".}: array[32, byte]
    serverRandom* {.importc: "server_random".}: array[32, byte]
    session* {.importc: "session".}: SslSessionParameters
    ecdheCurve* {.importc: "ecdhe_curve".}: byte
    ecdhePoint* {.importc: "ecdhe_point".}: array[133, byte]
    ecdhePointLen* {.importc: "ecdhe_point_len".}: byte
    reneg* {.importc: "reneg".}: byte
    savedFinished* {.importc: "saved_finished".}: array[24, byte]
    flags* {.importc: "flags".}: uint32
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_bearssl_ssl_10
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    pad* {.importc: "pad".}: array[512, byte]
    hbufIn* {.importc: "hbuf_in".}: ptr byte
    hbufOut* {.importc: "hbuf_out".}: ptr byte
    savedHbufOut* {.importc: "saved_hbuf_out".}: ptr byte
    hlenIn* {.importc: "hlen_in".}: csize_t
    hlenOut* {.importc: "hlen_out".}: csize_t
    hsrun* {.importc: "hsrun".}: proc (ctx: pointer) {.importcFunc.}
    action* {.importc: "action".}: byte
    alert* {.importc: "alert".}: byte
    closeReceived* {.importc: "close_received".}: byte
    mhash* {.importc: "mhash".}: MultihashContext
    x509ctx* {.importc: "x509ctx".}: X509ClassPointerConst
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: csize_t
    certCur* {.importc: "cert_cur".}: ConstPtrByte
    certLen* {.importc: "cert_len".}: csize_t
    protocolNames* {.importc: "protocol_names".}: ProtocolNamesPointerConst
    protocolNamesNum* {.importc: "protocol_names_num".}: uint16
    selectedProtocol* {.importc: "selected_protocol".}: uint16
    prf10* {.importc: "prf10".}: TlsPrfImpl
    prfSha256* {.importc: "prf_sha256".}: TlsPrfImpl
    prfSha384* {.importc: "prf_sha384".}: TlsPrfImpl
    iaesCbcenc* {.importc: "iaes_cbcenc".}: ptr BlockCbcencClass
    iaesCbcdec* {.importc: "iaes_cbcdec".}: ptr BlockCbcdecClass
    iaesCtr* {.importc: "iaes_ctr".}: ptr BlockCtrClass
    iaesCtrcbc* {.importc: "iaes_ctrcbc".}: ptr BlockCtrcbcClass
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
    iccmIn* {.importc: "iccm_in".}: ptr SslrecInCcmClass
    iccmOut* {.importc: "iccm_out".}: ptr SslrecOutCcmClass
    iec* {.importc: "iec".}: ptr EcImpl
    irsavrfy* {.importc: "irsavrfy".}: RsaPkcs1Vrfy
    iecdsa* {.importc: "iecdsa".}: EcdsaVrfy



proc sslEngineGetFlags*(cc: var SslEngineContext): uint32 {.importcFunc,
    importc: "br_ssl_engine_get_flags", header: "bearssl_ssl.h".}

proc sslEngineSetAllFlags*(cc: var SslEngineContext; flags: uint32) {.importcFunc,
    importc: "br_ssl_engine_set_all_flags", header: "bearssl_ssl.h".}

proc sslEngineAddFlags*(cc: var SslEngineContext; flags: uint32) {.importcFunc,
    importc: "br_ssl_engine_add_flags", header: "bearssl_ssl.h".}

proc sslEngineRemoveFlags*(cc: var SslEngineContext; flags: uint32) {.importcFunc,
    importc: "br_ssl_engine_remove_flags", header: "bearssl_ssl.h".}

const
  OPT_ENFORCE_SERVER_PREFERENCES* = (cast[uint32](1) shl 0)


const
  OPT_NO_RENEGOTIATION* = (cast[uint32](1) shl 1)


const
  OPT_TOLERATE_NO_CLIENT_AUTH* = (cast[uint32](1) shl 2)


const
  OPT_FAIL_ON_ALPN_MISMATCH* = (cast[uint32](1) shl 3)


proc sslEngineSetVersions*(cc: var SslEngineContext; versionMin: cuint;
                          versionMax: cuint) {.importcFunc,
    importc: "br_ssl_engine_set_versions", header: "bearssl_ssl.h".}

proc sslEngineSetSuites*(cc: var SslEngineContext; suites: ptr uint16;
                        suitesNum: csize_t) {.importcFunc,
    importc: "br_ssl_engine_set_suites", header: "bearssl_ssl.h".}

proc sslEngineSetX509*(cc: var SslEngineContext; x509ctx: X509ClassPointerConst) {.
    importcFunc, importc: "br_ssl_engine_set_x509", header: "bearssl_ssl.h".}

proc sslEngineSetProtocolNames*(ctx: var SslEngineContext; names: ProtocolNamesPointerConst;
                               num: csize_t) {.importcFunc,
    importc: "br_ssl_engine_set_protocol_names", header: "bearssl_ssl.h".}

proc sslEngineGetSelectedProtocol*(ctx: var SslEngineContext): ConstCstring {.importcFunc,
    importc: "br_ssl_engine_get_selected_protocol", header: "bearssl_ssl.h".}

proc sslEngineSetHash*(ctx: var SslEngineContext; id: cint; impl: ptr HashClass) {.importcFunc,
    importc: "br_ssl_engine_set_hash", header: "bearssl_ssl.h".}

proc sslEngineGetHash*(ctx: var SslEngineContext; id: cint): ptr HashClass {.importcFunc,
    importc: "br_ssl_engine_get_hash", header: "bearssl_ssl.h".}

proc sslEngineSetPrf10*(cc: var SslEngineContext; impl: TlsPrfImpl) {.importcFunc,
    importc: "br_ssl_engine_set_prf10", header: "bearssl_ssl.h".}

proc sslEngineSetPrfSha256*(cc: var SslEngineContext; impl: TlsPrfImpl) {.importcFunc,
    importc: "br_ssl_engine_set_prf_sha256", header: "bearssl_ssl.h".}

proc sslEngineSetPrfSha384*(cc: var SslEngineContext; impl: TlsPrfImpl) {.importcFunc,
    importc: "br_ssl_engine_set_prf_sha384", header: "bearssl_ssl.h".}

proc sslEngineSetAesCbc*(cc: var SslEngineContext; implEnc: ptr BlockCbcencClass;
                        implDec: ptr BlockCbcdecClass) {.importcFunc,
    importc: "br_ssl_engine_set_aes_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetDefaultAesCbc*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_aes_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetAesCtr*(cc: var SslEngineContext; impl: ptr BlockCtrClass) {.importcFunc,
    importc: "br_ssl_engine_set_aes_ctr", header: "bearssl_ssl.h".}

proc sslEngineSetDefaultAesGcm*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_aes_gcm", header: "bearssl_ssl.h".}

proc sslEngineSetDesCbc*(cc: var SslEngineContext; implEnc: ptr BlockCbcencClass;
                        implDec: ptr BlockCbcdecClass) {.importcFunc,
    importc: "br_ssl_engine_set_des_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetDefaultDesCbc*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_des_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetGhash*(cc: var SslEngineContext; impl: Ghash) {.importcFunc,
    importc: "br_ssl_engine_set_ghash", header: "bearssl_ssl.h".}

proc sslEngineSetChacha20*(cc: var SslEngineContext; ichacha: Chacha20Run) {.importcFunc,
    importc: "br_ssl_engine_set_chacha20", header: "bearssl_ssl.h".}

proc sslEngineSetPoly1305*(cc: var SslEngineContext; ipoly: Poly1305Run) {.importcFunc,
    importc: "br_ssl_engine_set_poly1305", header: "bearssl_ssl.h".}

proc sslEngineSetDefaultChapol*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_chapol", header: "bearssl_ssl.h".}

proc sslEngineSetAesCtrcbc*(cc: var SslEngineContext; impl: ptr BlockCtrcbcClass) {.
    importcFunc, importc: "br_ssl_engine_set_aes_ctrcbc", header: "bearssl_ssl.h".}

proc sslEngineSetDefaultAesCcm*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_aes_ccm", header: "bearssl_ssl.h".}

proc sslEngineSetCbc*(cc: var SslEngineContext; implIn: ptr SslrecInCbcClass;
                     implOut: ptr SslrecOutCbcClass) {.importcFunc,
    importc: "br_ssl_engine_set_cbc", header: "bearssl_ssl.h".}

proc sslEngineSetGcm*(cc: var SslEngineContext; implIn: ptr SslrecInGcmClass;
                     implOut: ptr SslrecOutGcmClass) {.importcFunc,
    importc: "br_ssl_engine_set_gcm", header: "bearssl_ssl.h".}

proc sslEngineSetCcm*(cc: var SslEngineContext; implIn: ptr SslrecInCcmClass;
                     implOut: ptr SslrecOutCcmClass) {.importcFunc,
    importc: "br_ssl_engine_set_ccm", header: "bearssl_ssl.h".}

proc sslEngineSetChapol*(cc: var SslEngineContext; implIn: ptr SslrecInChapolClass;
                        implOut: ptr SslrecOutChapolClass) {.importcFunc,
    importc: "br_ssl_engine_set_chapol", header: "bearssl_ssl.h".}

proc sslEngineSetEc*(cc: var SslEngineContext; iec: ptr EcImpl) {.importcFunc,
    importc: "br_ssl_engine_set_ec", header: "bearssl_ssl.h".}

proc sslEngineSetDefaultEc*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_ec", header: "bearssl_ssl.h".}

proc sslEngineGetEc*(cc: var SslEngineContext): ptr EcImpl {.importcFunc,
    importc: "br_ssl_engine_get_ec", header: "bearssl_ssl.h".}

proc sslEngineSetRsavrfy*(cc: var SslEngineContext; irsavrfy: RsaPkcs1Vrfy) {.importcFunc,
    importc: "br_ssl_engine_set_rsavrfy", header: "bearssl_ssl.h".}

proc sslEngineSetDefaultRsavrfy*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_rsavrfy", header: "bearssl_ssl.h".}

proc sslEngineGetRsavrfy*(cc: var SslEngineContext): RsaPkcs1Vrfy {.importcFunc,
    importc: "br_ssl_engine_get_rsavrfy", header: "bearssl_ssl.h".}

proc sslEngineSetEcdsa*(cc: var SslEngineContext; iecdsa: EcdsaVrfy) {.importcFunc,
    importc: "br_ssl_engine_set_ecdsa", header: "bearssl_ssl.h".}

proc sslEngineSetDefaultEcdsa*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_set_default_ecdsa", header: "bearssl_ssl.h".}

proc sslEngineGetEcdsa*(cc: var SslEngineContext): EcdsaVrfy {.importcFunc,
    importc: "br_ssl_engine_get_ecdsa", header: "bearssl_ssl.h".}

proc sslEngineSetBuffer*(cc: var SslEngineContext; iobuf: pointer; iobufLen: csize_t;
                        bidi: cint) {.importcFunc, importc: "br_ssl_engine_set_buffer",
                                    header: "bearssl_ssl.h".}

proc sslEngineSetBuffersBidi*(cc: var SslEngineContext; ibuf: pointer;
                             ibufLen: csize_t; obuf: pointer; obufLen: csize_t) {.
    importcFunc, importc: "br_ssl_engine_set_buffers_bidi", header: "bearssl_ssl.h".}

proc sslEngineInjectEntropy*(cc: var SslEngineContext; data: ConstPointer;
                            len: csize_t) {.importcFunc,
    importc: "br_ssl_engine_inject_entropy", header: "bearssl_ssl.h".}

proc sslEngineGetServerName*(cc: var SslEngineContext): ConstCstring {.importcFunc,
    importc: "br_ssl_engine_get_server_name", header: "bearssl_ssl.h".}

proc sslEngineGetVersion*(cc: var SslEngineContext): cuint {.importcFunc,
    importc: "br_ssl_engine_get_version", header: "bearssl_ssl.h".}

proc sslEngineGetSessionParameters*(cc: var SslEngineContext;
                                   pp: ptr SslSessionParameters) {.importcFunc,
    importc: "br_ssl_engine_get_session_parameters", header: "bearssl_ssl.h".}

proc sslEngineSetSessionParameters*(cc: var SslEngineContext;
                                   pp: ptr SslSessionParameters) {.importcFunc,
    importc: "br_ssl_engine_set_session_parameters", header: "bearssl_ssl.h".}

proc sslEngineGetEcdheCurve*(cc: var SslEngineContext): cint {.importcFunc,
    importc: "br_ssl_engine_get_ecdhe_curve", header: "bearssl_ssl.h".}

proc sslEngineCurrentState*(cc: var SslEngineContext): cuint {.importcFunc,
    importc: "br_ssl_engine_current_state", header: "bearssl_ssl.h".}

const
  SSL_CLOSED* = 0x0001


const
  SSL_SENDREC* = 0x0002


const
  SSL_RECVREC* = 0x0004


const
  SSL_SENDAPP* = 0x0008


const
  SSL_RECVAPP* = 0x0010


proc sslEngineLastError*(cc: var SslEngineContext): cint {.importcFunc,
    importc: "br_ssl_engine_last_error", header: "bearssl_ssl.h".}

proc sslEngineSendappBuf*(cc: var SslEngineContext; len: var csize_t): ptr byte {.
    importcFunc, importc: "br_ssl_engine_sendapp_buf", header: "bearssl_ssl.h".}

proc sslEngineSendappAck*(cc: var SslEngineContext; len: csize_t) {.importcFunc,
    importc: "br_ssl_engine_sendapp_ack", header: "bearssl_ssl.h".}

proc sslEngineRecvappBuf*(cc: var SslEngineContext; len: var csize_t): ptr byte {.
    importcFunc, importc: "br_ssl_engine_recvapp_buf", header: "bearssl_ssl.h".}

proc sslEngineRecvappAck*(cc: var SslEngineContext; len: csize_t) {.importcFunc,
    importc: "br_ssl_engine_recvapp_ack", header: "bearssl_ssl.h".}

proc sslEngineSendrecBuf*(cc: var SslEngineContext; len: var csize_t): ptr byte {.
    importcFunc, importc: "br_ssl_engine_sendrec_buf", header: "bearssl_ssl.h".}

proc sslEngineSendrecAck*(cc: var SslEngineContext; len: csize_t) {.importcFunc,
    importc: "br_ssl_engine_sendrec_ack", header: "bearssl_ssl.h".}

proc sslEngineRecvrecBuf*(cc: var SslEngineContext; len: var csize_t): ptr byte {.
    importcFunc, importc: "br_ssl_engine_recvrec_buf", header: "bearssl_ssl.h".}

proc sslEngineRecvrecAck*(cc: var SslEngineContext; len: csize_t) {.importcFunc,
    importc: "br_ssl_engine_recvrec_ack", header: "bearssl_ssl.h".}

proc sslEngineFlush*(cc: var SslEngineContext; force: cint) {.importcFunc,
    importc: "br_ssl_engine_flush", header: "bearssl_ssl.h".}

proc sslEngineClose*(cc: var SslEngineContext) {.importcFunc,
    importc: "br_ssl_engine_close", header: "bearssl_ssl.h".}

proc sslEngineRenegotiate*(cc: var SslEngineContext): cint {.importcFunc,
    importc: "br_ssl_engine_renegotiate", header: "bearssl_ssl.h".}

proc sslKeyExport*(cc: var SslEngineContext; dst: pointer; len: csize_t;
                  label: ConstCstring; context: ConstPointer; contextLen: csize_t): cint {.
    importcFunc, importc: "br_ssl_key_export", header: "bearssl_ssl.h".}

const
  AUTH_ECDH* = 0

const
  AUTH_RSA* = 1

const
  AUTH_ECDSA* = 3

type
  SslClientCertificate* {.importc: "br_ssl_client_certificate",
                         header: "bearssl_ssl.h", bycopy.} = object
    authType* {.importc: "auth_type".}: cint
    hashId* {.importc: "hash_id".}: cint
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: csize_t






  SslClientCertificateClass* {.importc: "br_ssl_client_certificate_class",
                              header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: csize_t
    startNameList* {.importc: "start_name_list".}: proc (
        pctx: ConstPtrPtrSslClientCertificateClass) {.importcFunc.}
    startName* {.importc: "start_name".}: proc (
        pctx: ConstPtrPtrSslClientCertificateClass; len: csize_t) {.importcFunc.}
    appendName* {.importc: "append_name".}: proc (
        pctx: ConstPtrPtrSslClientCertificateClass; data: ConstPtrByte; len: csize_t) {.
        importcFunc.}
    endName* {.importc: "end_name".}: proc (pctx: ConstPtrPtrSslClientCertificateClass) {.
        importcFunc.}
    endNameList* {.importc: "end_name_list".}: proc (
        pctx: ConstPtrPtrSslClientCertificateClass) {.importcFunc.}
    choose* {.importc: "choose".}: proc (pctx: ConstPtrPtrSslClientCertificateClass;
                                     cc: ConstPtrSslClientContext;
                                     authTypes: uint32;
                                     choices: ptr SslClientCertificate) {.importcFunc.}
    doKeyx* {.importc: "do_keyx".}: proc (pctx: ConstPtrPtrSslClientCertificateClass;
                                      data: ptr byte; len: var csize_t): uint32 {.
        importcFunc.}
    doSign* {.importc: "do_sign".}: proc (pctx: ConstPtrPtrSslClientCertificateClass;
                                      hashId: cint; hvLen: csize_t;
                                      data: ptr byte; len: csize_t): csize_t {.importcFunc.}



  SslClientCertificateRsaContext* {.importc: "br_ssl_client_certificate_rsa_context",
                                   header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslClientCertificateClass
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: csize_t
    sk* {.importc: "sk".}: ptr RsaPrivateKey
    irsasign* {.importc: "irsasign".}: RsaPkcs1Sign



  SslClientCertificateEcContext* {.importc: "br_ssl_client_certificate_ec_context",
                                  header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslClientCertificateClass
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: csize_t
    sk* {.importc: "sk".}: ptr EcPrivateKey
    allowedUsages* {.importc: "allowed_usages".}: cuint
    issuerKeyType* {.importc: "issuer_key_type".}: cuint
    mhash* {.importc: "mhash".}: ptr MultihashContext
    iec* {.importc: "iec".}: ptr EcImpl
    iecdsa* {.importc: "iecdsa".}: EcdsaSign



  INNER_C_UNION_bearssl_ssl_11* {.importc: "no_name", header: "bearssl_ssl.h",
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
    clientAuthVtable* {.importc: "client_auth_vtable".}: ConstPtrPtrSslClientCertificateClass
    authType* {.importc: "auth_type".}: byte
    hashId* {.importc: "hash_id".}: byte
    clientAuth* {.importc: "client_auth".}: INNER_C_UNION_bearssl_ssl_11
    irsapub* {.importc: "irsapub".}: RsaPublic



proc sslClientGetServerHashes*(cc: var SslClientContext): uint32 {.importcFunc,
    importc: "br_ssl_client_get_server_hashes", header: "bearssl_ssl.h".}

proc sslClientGetServerCurve*(cc: var SslClientContext): cint {.importcFunc,
    importc: "br_ssl_client_get_server_curve", header: "bearssl_ssl.h".}

proc sslClientInitFull*(cc: var SslClientContext; xc: ptr X509MinimalContext;
                       trustAnchors: ptr X509TrustAnchor; trustAnchorsNum: csize_t) {.
    importcFunc, importc: "br_ssl_client_init_full", header: "bearssl_ssl.h".}

proc sslClientZero*(cc: var SslClientContext) {.importcFunc, importc: "br_ssl_client_zero",
    header: "bearssl_ssl.h".}

proc sslClientSetClientCertificate*(cc: var SslClientContext;
                                   pctx: ConstPtrPtrSslClientCertificateClass) {.
    importcFunc, importc: "br_ssl_client_set_client_certificate", header: "bearssl_ssl.h".}

proc sslClientSetRsapub*(cc: var SslClientContext; irsapub: RsaPublic) {.importcFunc,
    importc: "br_ssl_client_set_rsapub", header: "bearssl_ssl.h".}

proc sslClientSetDefaultRsapub*(cc: var SslClientContext) {.importcFunc,
    importc: "br_ssl_client_set_default_rsapub", header: "bearssl_ssl.h".}

proc sslClientSetMinClienthelloLen*(cc: var SslClientContext; len: uint16) {.importcFunc,
    importc: "br_ssl_client_set_min_clienthello_len", header: "bearssl_ssl.h".}

proc sslClientReset*(cc: var SslClientContext; serverName: ConstCstring;
                    resumeSession: cint): cint {.importcFunc,
    importc: "br_ssl_client_reset", header: "bearssl_ssl.h".}

proc sslClientForgetSession*(cc: var SslClientContext) {.importcFunc,
    importc: "br_ssl_client_forget_session", header: "bearssl_ssl.h".}

proc sslClientSetSingleRsa*(cc: var SslClientContext; chain: ptr X509Certificate;
                           chainLen: csize_t; sk: ptr RsaPrivateKey;
                           irsasign: RsaPkcs1Sign) {.importcFunc,
    importc: "br_ssl_client_set_single_rsa", header: "bearssl_ssl.h".}

proc sslClientSetSingleEc*(cc: var SslClientContext; chain: ptr X509Certificate;
                          chainLen: csize_t; sk: ptr EcPrivateKey;
                          allowedUsages: cuint; certIssuerKeyType: cuint;
                          iec: ptr EcImpl; iecdsa: EcdsaSign) {.importcFunc,
    importc: "br_ssl_client_set_single_ec", header: "bearssl_ssl.h".}

type
  SuiteTranslated* = array[2, uint16]


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
    chainLen* {.importc: "chain_len".}: csize_t



  SslServerPolicyClass* {.importc: "br_ssl_server_policy_class",
                         header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: csize_t
    choose* {.importc: "choose".}: proc (pctx: ConstPtrPtrSslServerPolicyClass;
                                     cc: ConstPtrSslServerContext;
                                     choices: ptr SslServerChoices): cint {.importcFunc.}
    doKeyx* {.importc: "do_keyx".}: proc (pctx: ConstPtrPtrSslServerPolicyClass;
                                      data: ptr byte; len: var csize_t): uint32 {.
        importcFunc.}
    doSign* {.importc: "do_sign".}: proc (pctx: ConstPtrPtrSslServerPolicyClass;
                                      algoId: cuint; data: ptr byte;
                                      hvLen: csize_t; len: csize_t): csize_t {.importcFunc.}



  SslServerPolicyRsaContext* {.importc: "br_ssl_server_policy_rsa_context",
                              header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslServerPolicyClass
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: csize_t
    sk* {.importc: "sk".}: ptr RsaPrivateKey
    allowedUsages* {.importc: "allowed_usages".}: cuint
    irsacore* {.importc: "irsacore".}: RsaPrivate
    irsasign* {.importc: "irsasign".}: RsaPkcs1Sign



  SslServerPolicyEcContext* {.importc: "br_ssl_server_policy_ec_context",
                             header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslServerPolicyClass
    chain* {.importc: "chain".}: ptr X509Certificate
    chainLen* {.importc: "chain_len".}: csize_t
    sk* {.importc: "sk".}: ptr EcPrivateKey
    allowedUsages* {.importc: "allowed_usages".}: cuint
    certIssuerKeyType* {.importc: "cert_issuer_key_type".}: cuint
    mhash* {.importc: "mhash".}: ptr MultihashContext
    iec* {.importc: "iec".}: ptr EcImpl
    iecdsa* {.importc: "iecdsa".}: EcdsaSign



  SslSessionCacheClass* {.importc: "br_ssl_session_cache_class",
                         header: "bearssl_ssl.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: csize_t
    save* {.importc: "save".}: proc (ctx: SslSessionCacheClassPointerConst;
                                 serverCtx: ptr SslServerContext;
                                 params: ConstPtrSslSessionParameters) {.importcFunc.}
    load* {.importc: "load".}: proc (ctx: SslSessionCacheClassPointerConst;
                                 serverCtx: ptr SslServerContext;
                                 params: ptr SslSessionParameters): cint {.importcFunc.}



  SslSessionCacheLru* {.importc: "br_ssl_session_cache_lru",
                       header: "bearssl_ssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr SslSessionCacheClass
    store* {.importc: "store".}: ptr byte
    storeLen* {.importc: "store_len".}: csize_t
    storePtr* {.importc: "store_ptr".}: csize_t
    indexKey* {.importc: "index_key".}: array[32, byte]
    hash* {.importc: "hash".}: ptr HashClass
    initDone* {.importc: "init_done".}: cint
    head* {.importc: "head".}: uint32
    tail* {.importc: "tail".}: uint32
    root* {.importc: "root".}: uint32



  INNER_C_UNION_bearssl_ssl_12* {.importc: "no_name", header: "bearssl_ssl.h",
                                   bycopy, union.} = object
    vtable* {.importc: "vtable".}: ptr SslServerPolicyClass
    singleRsa* {.importc: "single_rsa".}: SslServerPolicyRsaContext
    singleEc* {.importc: "single_ec".}: SslServerPolicyEcContext

  SslServerContext* {.importc: "br_ssl_server_context", header: "bearssl_ssl.h",
                     bycopy.} = object
    eng* {.importc: "eng".}: SslEngineContext
    clientMaxVersion* {.importc: "client_max_version".}: uint16
    cacheVtable* {.importc: "cache_vtable".}: SslSessionCacheClassPointerConst
    clientSuites* {.importc: "client_suites".}: array[MAX_CIPHER_SUITES,
        SuiteTranslated]
    clientSuitesNum* {.importc: "client_suites_num".}: byte
    hashes* {.importc: "hashes".}: uint32
    curves* {.importc: "curves".}: uint32
    policyVtable* {.importc: "policy_vtable".}: ConstPtrPtrSslServerPolicyClass
    signHashId* {.importc: "sign_hash_id".}: uint16
    chainHandler* {.importc: "chain_handler".}: INNER_C_UNION_bearssl_ssl_12
    ecdheKey* {.importc: "ecdhe_key".}: array[70, byte]
    ecdheKeyLen* {.importc: "ecdhe_key_len".}: csize_t
    taNames* {.importc: "ta_names".}: ptr X500Name
    tas* {.importc: "tas".}: ptr X509TrustAnchor
    numTas* {.importc: "num_tas".}: csize_t
    curDnIndex* {.importc: "cur_dn_index".}: csize_t
    curDn* {.importc: "cur_dn".}: ConstPtrByte
    curDnLen* {.importc: "cur_dn_len".}: csize_t
    hashCV* {.importc: "hash_CV".}: array[64, byte]
    hashCV_len* {.importc: "hash_CV_len".}: csize_t
    hashCV_id* {.importc: "hash_CV_id".}: cint

proc sslSessionCacheLruInit*(cc: var SslSessionCacheLru; store: ptr byte;
                            storeLen: csize_t) {.importcFunc,
    importc: "br_ssl_session_cache_lru_init", header: "bearssl_ssl.h".}

proc sslSessionCacheLruForget*(cc: var SslSessionCacheLru; id: ConstPtrByte) {.importcFunc,
    importc: "br_ssl_session_cache_lru_forget", header: "bearssl_ssl.h".}



proc sslServerInitFullRsa*(cc: var SslServerContext; chain: ptr X509Certificate;
                          chainLen: csize_t; sk: ptr RsaPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_full_rsa", header: "bearssl_ssl.h".}

proc sslServerInitFullEc*(cc: var SslServerContext; chain: ptr X509Certificate;
                         chainLen: csize_t; certIssuerKeyType: cuint;
                         sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_full_ec", header: "bearssl_ssl.h".}

proc sslServerInitMinr2g*(cc: var SslServerContext; chain: ptr X509Certificate;
                         chainLen: csize_t; sk: ptr RsaPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minr2g", header: "bearssl_ssl.h".}

proc sslServerInitMine2g*(cc: var SslServerContext; chain: ptr X509Certificate;
                         chainLen: csize_t; sk: ptr RsaPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_mine2g", header: "bearssl_ssl.h".}

proc sslServerInitMinf2g*(cc: var SslServerContext; chain: ptr X509Certificate;
                         chainLen: csize_t; sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minf2g", header: "bearssl_ssl.h".}

proc sslServerInitMinu2g*(cc: var SslServerContext; chain: ptr X509Certificate;
                         chainLen: csize_t; sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minu2g", header: "bearssl_ssl.h".}

proc sslServerInitMinv2g*(cc: var SslServerContext; chain: ptr X509Certificate;
                         chainLen: csize_t; sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minv2g", header: "bearssl_ssl.h".}

proc sslServerInitMine2c*(cc: var SslServerContext; chain: ptr X509Certificate;
                         chainLen: csize_t; sk: ptr RsaPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_mine2c", header: "bearssl_ssl.h".}

proc sslServerInitMinf2c*(cc: var SslServerContext; chain: ptr X509Certificate;
                         chainLen: csize_t; sk: ptr EcPrivateKey) {.importcFunc,
    importc: "br_ssl_server_init_minf2c", header: "bearssl_ssl.h".}

proc sslServerGetClientSuites*(cc: var SslServerContext; num: ptr csize_t): ptr array[MAX_CIPHER_SUITES, SuiteTranslated] {.
    importcFunc, importc: "br_ssl_server_get_client_suites", header: "bearssl_ssl.h".}

proc sslServerGetClientHashes*(cc: var SslServerContext): uint32 {.importcFunc,
    importc: "br_ssl_server_get_client_hashes", header: "bearssl_ssl.h".}

proc sslServerGetClientCurves*(cc: var SslServerContext): uint32 {.importcFunc,
    importc: "br_ssl_server_get_client_curves", header: "bearssl_ssl.h".}

proc sslServerZero*(cc: var SslServerContext) {.importcFunc, importc: "br_ssl_server_zero",
    header: "bearssl_ssl.h".}

proc sslServerSetPolicy*(cc: var SslServerContext;
                        pctx: ConstPtrPtrSslServerPolicyClass) {.importcFunc,
    importc: "br_ssl_server_set_policy", header: "bearssl_ssl.h".}

proc sslServerSetSingleRsa*(cc: var SslServerContext; chain: ptr X509Certificate;
                           chainLen: csize_t; sk: ptr RsaPrivateKey;
                           allowedUsages: cuint; irsacore: RsaPrivate;
                           irsasign: RsaPkcs1Sign) {.importcFunc,
    importc: "br_ssl_server_set_single_rsa", header: "bearssl_ssl.h".}

proc sslServerSetSingleEc*(cc: var SslServerContext; chain: ptr X509Certificate;
                          chainLen: csize_t; sk: ptr EcPrivateKey;
                          allowedUsages: cuint; certIssuerKeyType: cuint;
                          iec: ptr EcImpl; iecdsa: EcdsaSign) {.importcFunc,
    importc: "br_ssl_server_set_single_ec", header: "bearssl_ssl.h".}

proc sslServerSetTrustAnchorNames*(cc: var SslServerContext; taNames: ptr X500Name;
                                  num: csize_t) {.importcFunc,
    importc: "br_ssl_server_set_trust_anchor_names", header: "bearssl_ssl.h".}

proc sslServerSetTrustAnchorNamesAlt*(cc: var SslServerContext;
                                     tas: ptr X509TrustAnchor; num: csize_t) {.importcFunc,
    importc: "br_ssl_server_set_trust_anchor_names_alt", header: "bearssl_ssl.h".}

proc sslServerSetCache*(cc: var SslServerContext;
                       vtable: SslSessionCacheClassPointerConst) {.importcFunc,
    importc: "br_ssl_server_set_cache", header: "bearssl_ssl.h".}

proc sslServerReset*(cc: var SslServerContext): cint {.importcFunc,
    importc: "br_ssl_server_reset", header: "bearssl_ssl.h".}

type
  SslioContext* {.importc: "br_sslio_context", header: "bearssl_ssl.h", bycopy.} = object
    engine* {.importc: "engine".}: ptr SslEngineContext
    lowRead* {.importc: "low_read".}: proc (readContext: pointer; data: ptr byte;
                                        len: csize_t): cint {.importcFunc.}
    readContext* {.importc: "read_context".}: pointer
    lowWrite* {.importc: "low_write".}: proc (writeContext: pointer;
        data: ConstPtrByte; len: csize_t): cint {.importcFunc.}
    writeContext* {.importc: "write_context".}: pointer



proc sslioInit*(ctx: var SslioContext; engine: ptr SslEngineContext; lowRead: proc (
    readContext: pointer; data: ptr byte; len: csize_t): cint {.importcFunc.};
               readContext: pointer; lowWrite: proc (writeContext: pointer;
    data: ConstPtrByte; len: csize_t): cint {.importcFunc.}; writeContext: pointer) {.importcFunc,
    importc: "br_sslio_init", header: "bearssl_ssl.h".}

proc sslioRead*(cc: var SslioContext; dst: pointer; len: csize_t): cint {.importcFunc,
    importc: "br_sslio_read", header: "bearssl_ssl.h".}

proc sslioReadAll*(cc: var SslioContext; dst: pointer; len: csize_t): cint {.importcFunc,
    importc: "br_sslio_read_all", header: "bearssl_ssl.h".}

proc sslioWrite*(cc: var SslioContext; src: ConstPointer; len: csize_t): cint {.importcFunc,
    importc: "br_sslio_write", header: "bearssl_ssl.h".}

proc sslioWriteAll*(cc: var SslioContext; src: ConstPointer; len: csize_t): cint {.importcFunc,
    importc: "br_sslio_write_all", header: "bearssl_ssl.h".}

proc sslioFlush*(cc: var SslioContext): cint {.importcFunc, importc: "br_sslio_flush",
    header: "bearssl_ssl.h".}

proc sslioClose*(cc: var SslioContext): cint {.importcFunc, importc: "br_sslio_close",
    header: "bearssl_ssl.h".}

const
  TLS_NULL_WITH_NULL_NULL* = 0x0000
  TLS_RSA_WITH_NULL_MD5* = 0x0001
  TLS_RSA_WITH_NULL_SHA* = 0x0002
  TLS_RSA_WITH_NULL_SHA256* = 0x003B
  TLS_RSA_WITH_RC4_128_MD5* = 0x0004
  TLS_RSA_WITH_RC4_128_SHA* = 0x0005
  TLS_RSA_WITH_3DES_EDE_CBC_SHA* = 0x000A
  TLS_RSA_WITH_AES_128_CBC_SHA* = 0x002F
  TLS_RSA_WITH_AES_256_CBC_SHA* = 0x0035
  TLS_RSA_WITH_AES_128_CBC_SHA256* = 0x003C
  TLS_RSA_WITH_AES_256_CBC_SHA256* = 0x003D
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA* = 0x000D
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA* = 0x0010
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA* = 0x0013
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA* = 0x0016
  TLS_DH_DSS_WITH_AES_128_CBC_SHA* = 0x0030
  TLS_DH_RSA_WITH_AES_128_CBC_SHA* = 0x0031
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA* = 0x0032
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA* = 0x0033
  TLS_DH_DSS_WITH_AES_256_CBC_SHA* = 0x0036
  TLS_DH_RSA_WITH_AES_256_CBC_SHA* = 0x0037
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA* = 0x0038
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA* = 0x0039
  TLS_DH_DSS_WITH_AES_128_CBC_SHA256* = 0x003E
  TLS_DH_RSA_WITH_AES_128_CBC_SHA256* = 0x003F
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256* = 0x0040
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256* = 0x0067
  TLS_DH_DSS_WITH_AES_256_CBC_SHA256* = 0x0068
  TLS_DH_RSA_WITH_AES_256_CBC_SHA256* = 0x0069
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256* = 0x006A
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256* = 0x006B
  TLS_DH_anonWITH_RC4128MD5* = 0x0018
  TLS_DH_anonWITH_3DES_EDE_CBC_SHA* = 0x001B
  TLS_DH_anonWITH_AES_128CBC_SHA* = 0x0034
  TLS_DH_anonWITH_AES_256CBC_SHA* = 0x003A
  TLS_DH_anonWITH_AES_128CBC_SHA256* = 0x006C
  TLS_DH_anonWITH_AES_256CBC_SHA256* = 0x006D


const
  TLS_ECDH_ECDSA_WITH_NULL_SHA* = 0xC001
  TLS_ECDH_ECDSA_WITH_RC4_128_SHA* = 0xC002
  TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA* = 0xC003
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA* = 0xC004
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA* = 0xC005
  TLS_ECDHE_ECDSA_WITH_NULL_SHA* = 0xC006
  TLS_ECDHE_ECDSA_WITH_RC4_128_SHA* = 0xC007
  TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA* = 0xC008
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA* = 0xC009
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA* = 0xC00A
  TLS_ECDH_RSA_WITH_NULL_SHA* = 0xC00B
  TLS_ECDH_RSA_WITH_RC4_128_SHA* = 0xC00C
  TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA* = 0xC00D
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA* = 0xC00E
  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA* = 0xC00F
  TLS_ECDHE_RSA_WITH_NULL_SHA* = 0xC010
  TLS_ECDHE_RSA_WITH_RC4_128_SHA* = 0xC011
  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA* = 0xC012
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA* = 0xC013
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA* = 0xC014
  TLS_ECDH_anonWITH_NULL_SHA* = 0xC015
  TLS_ECDH_anonWITH_RC4128SHA* = 0xC016
  TLS_ECDH_anonWITH_3DES_EDE_CBC_SHA* = 0xC017
  TLS_ECDH_anonWITH_AES_128CBC_SHA* = 0xC018
  TLS_ECDH_anonWITH_AES_256CBC_SHA* = 0xC019


const
  TLS_RSA_WITH_AES_128_GCM_SHA256* = 0x009C
  TLS_RSA_WITH_AES_256_GCM_SHA384* = 0x009D
  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256* = 0x009E
  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384* = 0x009F
  TLS_DH_RSA_WITH_AES_128_GCM_SHA256* = 0x00A0
  TLS_DH_RSA_WITH_AES_256_GCM_SHA384* = 0x00A1
  TLS_DHE_DSS_WITH_AES_128_GCM_SHA256* = 0x00A2
  TLS_DHE_DSS_WITH_AES_256_GCM_SHA384* = 0x00A3
  TLS_DH_DSS_WITH_AES_128_GCM_SHA256* = 0x00A4
  TLS_DH_DSS_WITH_AES_256_GCM_SHA384* = 0x00A5
  TLS_DH_anonWITH_AES_128GCM_SHA256* = 0x00A6
  TLS_DH_anonWITH_AES_256GCM_SHA384* = 0x00A7


const
  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256* = 0xC023
  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384* = 0xC024
  TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256* = 0xC025
  TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384* = 0xC026
  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256* = 0xC027
  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384* = 0xC028
  TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256* = 0xC029
  TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384* = 0xC02A
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256* = 0xC02B
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384* = 0xC02C
  TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256* = 0xC02D
  TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384* = 0xC02E
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256* = 0xC02F
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384* = 0xC030
  TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256* = 0xC031
  TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384* = 0xC032


const
  TLS_RSA_WITH_AES_128_CCM* = 0xC09C
  TLS_RSA_WITH_AES_256_CCM* = 0xC09D
  TLS_RSA_WITH_AES_128_CCM_8* = 0xC0A0
  TLS_RSA_WITH_AES_256_CCM_8* = 0xC0A1
  TLS_ECDHE_ECDSA_WITH_AES_128_CCM* = 0xC0AC
  TLS_ECDHE_ECDSA_WITH_AES_256_CCM* = 0xC0AD
  TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8* = 0xC0AE
  TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8* = 0xC0AF


const
  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256* = 0xCCA8
  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256* = 0xCCA9
  TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256* = 0xCCAA
  TLS_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0xCCAB
  TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0xCCAC
  TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0xCCAD
  TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256* = 0xCCAE


const
  TLS_FALLBACK_SCSV* = 0x5600


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

func toSizeT(len: int): csize_t =
  doAssert len >= 0 and uint64(len) <= uint64(high(csize_t))
  csize_t(len)

template sslClientSetSingleRsa*(cc: var SslClientContext; chain: ptr X509Certificate;
                               chainLen: int; sk: ptr RsaPrivateKey;
                               irsasign: RsaPkcs1Sign) =
  sslClientSetSingleRsa(cc, chain, toSizeT(chainLen), sk, irsasign)

template sslClientSetSingleEc*(cc: var SslClientContext; chain: ptr X509Certificate;
                              chainLen: int; sk: ptr EcPrivateKey;
                              allowedUsages: cuint; certIssuerKeyType: cuint;
                              iec: ptr EcImpl; iecdsa: EcdsaSign) =
  sslClientSetSingleEc(cc, chain, toSizeT(chainLen), sk, allowedUsages,
                       certIssuerKeyType, iec, iecdsa)

template sslSessionCacheLruInit*(cc: var SslSessionCacheLru; store: ptr byte;
                                storeLen: int) =
  sslSessionCacheLruInit(cc, store, toSizeT(storeLen))
