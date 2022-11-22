import
  "."/[bearssl_ec, bearssl_hash, bearssl_rsa, csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearX509Path = bearSrcPath & "x509/"

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
  INNER_C_UNION_bearssl_x509_1* {.importc: "br_x509_pkey::no_name",
                                 header: "bearssl_x509.h", bycopy, union.} = object
    rsa* {.importc: "rsa".}: RsaPublicKey
    ec* {.importc: "ec".}: EcPublicKey

  X509Pkey* {.importc: "br_x509_pkey", header: "bearssl_x509.h", bycopy.} = object
    keyType* {.importc: "key_type".}: byte
    key* {.importc: "key".}: INNER_C_UNION_bearssl_x509_1



type
  X500Name* {.importc: "br_x500_name", header: "bearssl_x509.h", bycopy.} = object
    data* {.importc: "data".}: ptr byte
    len* {.importc: "len".}: uint



type
  X509TrustAnchor* {.importc: "br_x509_trust_anchor", header: "bearssl_x509.h",
                    bycopy.} = object
    dn* {.importc: "dn".}: X500Name
    flags* {.importc: "flags".}: cuint
    pkey* {.importc: "pkey".}: X509Pkey



const
  X509_TA_CA* = 0x0001


const
  KEYTYPE_RSA* = 1


const
  KEYTYPE_EC* = 2


const
  KEYTYPE_KEYX* = 0x10


const
  KEYTYPE_SIGN* = 0x20


type
  X509Class* {.importc: "br_x509_class", header: "bearssl_x509.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: uint
    startChain* {.importc: "start_chain".}: proc (ctx: ptr ptr X509Class;
        serverName: cstring) {.importcFunc.}
    startCert* {.importc: "start_cert".}: proc (ctx: ptr ptr X509Class; length: uint32) {.
        importcFunc.}
    append* {.importc: "append".}: proc (ctx: ptr ptr X509Class; buf: ptr byte;
                                     len: uint) {.importcFunc.}
    endCert* {.importc: "end_cert".}: proc (ctx: ptr ptr X509Class) {.importcFunc.}
    endChain* {.importc: "end_chain".}: proc (ctx: ptr ptr X509Class): cuint {.importcFunc.}
    getPkey* {.importc: "get_pkey".}: proc (ctx: ptr ptr X509Class; usages: ptr cuint): ptr X509Pkey {.
        importcFunc.}



type
  X509KnownkeyContext* {.importc: "br_x509_knownkey_context",
                        header: "bearssl_x509.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class
    pkey* {.importc: "pkey".}: X509Pkey
    usages* {.importc: "usages".}: cuint


var x509KnownkeyVtable* {.importc: "br_x509_knownkey_vtable",
                        header: "bearssl_x509.h".}: X509Class

proc x509KnownkeyInitRsa*(ctx: var X509KnownkeyContext; pk: ptr RsaPublicKey;
                         usages: cuint) {.importcFunc,
                                        importc: "br_x509_knownkey_init_rsa",
                                        header: "bearssl_x509.h".}

proc x509KnownkeyInitEc*(ctx: var X509KnownkeyContext; pk: ptr EcPublicKey;
                        usages: cuint) {.importcFunc,
                                       importc: "br_x509_knownkey_init_ec",
                                       header: "bearssl_x509.h".}

const
  X509_BUFSIZE_KEY* = 520
  X509_BUFSIZE_SIG* = 512


type
  NameElement* {.importc: "br_name_element", header: "bearssl_x509.h", bycopy.} = object
    oid* {.importc: "oid".}: ptr byte
    buf* {.importc: "buf".}: cstring
    len* {.importc: "len".}: uint
    status* {.importc: "status".}: cint



type
  X509TimeCheck* {.importc: "br_x509_time_check", header: "bearssl_x509.h".} =
    proc (tctx: pointer; notBeforeDays: uint32;
      notBeforeSeconds: uint32; notAfterDays: uint32;
      notAfterSeconds: uint32): cint {.importcFunc.}


type
  INNER_C_STRUCT_bearssl_x509_3* {.importc: "br_x509_minimal_context::no_name",
                                  header: "bearssl_x509.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr byte

  X509MinimalContext* {.importc: "br_x509_minimal_context",
                       header: "bearssl_x509.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class
    pkey* {.importc: "pkey".}: X509Pkey
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_bearssl_x509_3
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    serverName* {.importc: "server_name".}: cstring
    keyUsages* {.importc: "key_usages".}: byte
    days* {.importc: "days".}: uint32
    seconds* {.importc: "seconds".}: uint32
    certLength* {.importc: "cert_length".}: uint32
    numCerts* {.importc: "num_certs".}: uint32
    hbuf* {.importc: "hbuf".}: ptr byte
    hlen* {.importc: "hlen".}: uint
    pad* {.importc: "pad".}: array[256, byte]
    eePkeyData* {.importc: "ee_pkey_data".}: array[X509_BUFSIZE_KEY, byte]
    pkeyData* {.importc: "pkey_data".}: array[X509_BUFSIZE_KEY, byte]
    certSignerKeyType* {.importc: "cert_signer_key_type".}: byte
    certSigHashOid* {.importc: "cert_sig_hash_oid".}: uint16
    certSigHashLen* {.importc: "cert_sig_hash_len".}: byte
    certSig* {.importc: "cert_sig".}: array[X509_BUFSIZE_SIG, byte]
    certSigLen* {.importc: "cert_sig_len".}: uint16
    minRsaSize* {.importc: "min_rsa_size".}: int16
    trustAnchors* {.importc: "trust_anchors".}: ptr X509TrustAnchor
    trustAnchorsNum* {.importc: "trust_anchors_num".}: uint
    doMhash* {.importc: "do_mhash".}: byte
    mhash* {.importc: "mhash".}: MultihashContext
    tbsHash* {.importc: "tbs_hash".}: array[64, byte]
    doDnHash* {.importc: "do_dn_hash".}: byte
    dnHashImpl* {.importc: "dn_hash_impl".}: ptr HashClass
    dnHash* {.importc: "dn_hash".}: HashCompatContext
    currentDnHash* {.importc: "current_dn_hash".}: array[64, byte]
    nextDnHash* {.importc: "next_dn_hash".}: array[64, byte]
    savedDnHash* {.importc: "saved_dn_hash".}: array[64, byte]
    nameElts* {.importc: "name_elts".}: ptr NameElement
    numNameElts* {.importc: "num_name_elts".}: uint
    itimeCtx* {.importc: "itime_ctx".}: pointer
    itime* {.importc: "itime".}: X509TimeCheck
    irsa* {.importc: "irsa".}: RsaPkcs1Vrfy
    iecdsa* {.importc: "iecdsa".}: EcdsaVrfy
    iec* {.importc: "iec".}: ptr EcImpl


var x509MinimalVtable* {.importc: "br_x509_minimal_vtable", header: "bearssl_x509.h".}: X509Class

proc x509MinimalInit*(ctx: var X509MinimalContext; dnHashImpl: ptr HashClass;
                     trustAnchors: ptr X509TrustAnchor; trustAnchorsNum: uint) {.
    importcFunc, importc: "br_x509_minimal_init", header: "bearssl_x509.h".}

proc x509MinimalSetHash*(ctx: var X509MinimalContext; id: cint; impl: ptr HashClass) {.
    inline.} =
  multihashSetimpl(ctx.mhash, id, impl)


proc x509MinimalSetRsa*(ctx: var X509MinimalContext; irsa: RsaPkcs1Vrfy) {.inline.} =
  ctx.irsa = irsa


proc x509MinimalSetEcdsa*(ctx: var X509MinimalContext; iec: ptr EcImpl;
                         iecdsa: EcdsaVrfy) {.inline.} =
  ctx.iecdsa = iecdsa
  ctx.iec = iec


proc x509MinimalInitFull*(ctx: var X509MinimalContext;
                         trustAnchors: ptr X509TrustAnchor;
                         trustAnchorsNum: uint) {.importcFunc,
    importc: "br_x509_minimal_init_full", header: "bearssl_x509.h".}

proc x509MinimalSetTime*(ctx: var X509MinimalContext; days: uint32; seconds: uint32) {.
    inline.} =
  ctx.days = days
  ctx.seconds = seconds
  ctx.itime = nil


proc x509MinimalSetTimeCallback*(ctx: var X509MinimalContext; itimeCtx: pointer;
                                itime: X509TimeCheck) {.inline, importcFunc,
    importc: "br_x509_minimal_set_time_callback".} =
  ctx.itimeCtx = itimeCtx
  ctx.itime = itime


proc x509MinimalSetMinrsa*(ctx: var X509MinimalContext; byteLength: cint) {.inline.} =
  ctx.minRsaSize = (int16)(byteLength - 128)


proc x509MinimalSetNameElements*(ctx: var X509MinimalContext; elts: ptr NameElement;
                                numElts: uint) {.inline.} =
  ctx.nameElts = elts
  ctx.numNameElts = numElts


type
  INNER_C_STRUCT_bearssl_x509_5* {.importc: "br_x509_decoder_context::no_name",
                                  header: "bearssl_x509.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr byte

  X509DecoderContext* {.importc: "br_x509_decoder_context",
                       header: "bearssl_x509.h", bycopy.} = object
    pkey* {.importc: "pkey".}: X509Pkey
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_bearssl_x509_5
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    pad* {.importc: "pad".}: array[256, byte]
    decoded* {.importc: "decoded".}: bool
    notbeforeDays* {.importc: "notbefore_days".}: uint32
    notbeforeSeconds* {.importc: "notbefore_seconds".}: uint32
    notafterDays* {.importc: "notafter_days".}: uint32
    notafterSeconds* {.importc: "notafter_seconds".}: uint32
    isCA* {.importc: "isCA".}: bool
    copyDn* {.importc: "copy_dn".}: byte
    appendDnCtx* {.importc: "append_dn_ctx".}: pointer
    appendDn* {.importc: "append_dn".}: proc (ctx: pointer; buf: pointer; len: uint) {.
        importcFunc.}
    hbuf* {.importc: "hbuf".}: ptr byte
    hlen* {.importc: "hlen".}: uint
    pkeyData* {.importc: "pkey_data".}: array[X509_BUFSIZE_KEY, byte]
    signerKeyType* {.importc: "signer_key_type".}: byte
    signerHashId* {.importc: "signer_hash_id".}: byte



proc x509DecoderInit*(ctx: var X509DecoderContext; appendDn: proc (ctx: pointer;
    buf: pointer; len: uint) {.importcFunc.}; appendDnCtx: pointer) {.importcFunc,
    importc: "br_x509_decoder_init", header: "bearssl_x509.h".}

proc x509DecoderPush*(ctx: var X509DecoderContext; data: pointer; len: uint) {.importcFunc,
    importc: "br_x509_decoder_push", header: "bearssl_x509.h".}

proc x509DecoderGetPkey*(ctx: var X509DecoderContext): ptr X509Pkey {.inline.} =
  if ctx.decoded and ctx.err == 0:
    return addr(ctx.pkey)
  else:
    return nil


proc x509DecoderLastError*(ctx: var X509DecoderContext): cint {.inline.} =
  if ctx.err != 0:
    return ctx.err
  if not ctx.decoded:
    return ERR_X509_TRUNCATED
  return 0

proc x509DecoderIsCA*(ctx: var X509DecoderContext): cint {.inline.} =
  return cint ctx.isCA

proc x509DecoderGetSignerKeyType*(ctx: var X509DecoderContext): cint {.inline.} =
  return cint ctx.signerKeyType

proc x509DecoderGetSignerHashId*(ctx: var X509DecoderContext): cint {.inline.} =
  return cint ctx.signerHashId

type
  X509Certificate* {.importc: "br_x509_certificate", header: "bearssl_x509.h", bycopy.} = object
    data* {.importc: "data".}: ptr byte
    dataLen* {.importc: "data_len".}: uint



type
  INNER_C_UNION_bearssl_x509_8* {.importc: "br_skey_decoder_context::no_name",
                                 header: "bearssl_x509.h", bycopy, union.} = object
    rsa* {.importc: "rsa".}: RsaPrivateKey
    ec* {.importc: "ec".}: EcPrivateKey

  INNER_C_STRUCT_bearssl_x509_9* {.importc: "br_skey_decoder_context::no_name",
                                  header: "bearssl_x509.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr byte

  SkeyDecoderContext* {.importc: "br_skey_decoder_context",
                       header: "bearssl_x509.h", bycopy.} = object
    key* {.importc: "key".}: INNER_C_UNION_bearssl_x509_8
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_bearssl_x509_9
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    hbuf* {.importc: "hbuf".}: ptr byte
    hlen* {.importc: "hlen".}: uint
    pad* {.importc: "pad".}: array[256, byte]
    keyType* {.importc: "key_type".}: byte
    keyData* {.importc: "key_data".}: array[3 * X509_BUFSIZE_SIG, byte]



proc skeyDecoderInit*(ctx: var SkeyDecoderContext) {.importcFunc,
    importc: "br_skey_decoder_init", header: "bearssl_x509.h".}

proc skeyDecoderPush*(ctx: var SkeyDecoderContext; data: pointer; len: uint) {.importcFunc,
    importc: "br_skey_decoder_push", header: "bearssl_x509.h".}

proc skeyDecoderLastError*(ctx: var SkeyDecoderContext): cint {.inline.} =
  if ctx.err != 0:
    return ctx.err
  if ctx.keyType == '\0'.byte:
    return ERR_X509_TRUNCATED
  return 0


proc skeyDecoderKeyType*(ctx: var SkeyDecoderContext): cint {.inline.} =
  if ctx.err == 0:
    return cint ctx.keyType
  else:
    return 0


proc skeyDecoderGetRsa*(ctx: var SkeyDecoderContext): ptr RsaPrivateKey {.inline.} =
  if ctx.err == 0 and ctx.keyType == KEYTYPE_RSA:
    return addr(ctx.key.rsa)
  else:
    return nil


proc skeyDecoderGetEc*(ctx: var SkeyDecoderContext): ptr EcPrivateKey {.inline.} =
  if ctx.err == 0 and ctx.keyType == KEYTYPE_EC:
    return addr(ctx.key.ec)
  else:
    return nil


proc encodeRsaRawDer*(dest: pointer; sk: ptr RsaPrivateKey; pk: ptr RsaPublicKey;
                     d: pointer; dlen: uint): uint {.importcFunc,
    importc: "br_encode_rsa_raw_der", header: "bearssl_x509.h".}

proc encodeRsaPkcs8Der*(dest: pointer; sk: ptr RsaPrivateKey; pk: ptr RsaPublicKey;
                       d: pointer; dlen: uint): uint {.importcFunc,
    importc: "br_encode_rsa_pkcs8_der", header: "bearssl_x509.h".}

proc encodeEcRawDer*(dest: pointer; sk: ptr EcPrivateKey; pk: ptr EcPublicKey): uint {.
    importcFunc, importc: "br_encode_ec_raw_der", header: "bearssl_x509.h".}

proc encodeEcPkcs8Der*(dest: pointer; sk: ptr EcPrivateKey; pk: ptr EcPublicKey): uint {.
    importcFunc, importc: "br_encode_ec_pkcs8_der", header: "bearssl_x509.h".}

const
  ENCODE_PEM_RSA_RAW* = "RSA PRIVATE KEY"


const
  ENCODE_PEM_EC_RAW* = "EC PRIVATE KEY"


const
  ENCODE_PEM_PKCS8* = "PRIVATE KEY"
