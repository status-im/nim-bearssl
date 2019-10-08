## Nim-BearSSL
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module provides error messages for BearSSL's error codes.

type
  SSLError* {.pure.} = enum
    NoError = 0,
    BadParam = 1,
    BadState = 2,
    UnsupportedVersion = 3,
    BadVersion = 4,
    BadLength = 5,
    TooLarge = 6,
    BadMac = 7,
    NoRandom = 8,
    UnknownType = 9,
    UnexpectedError = 10,
    BadCcs = 12,
    BadAlert = 13,
    BadHandshake = 14,
    OversizedIdError = 15,
    BadCipherSuite = 16,
    BadCompression = 17,
    BadFraglen = 18,
    BadSecReneg = 19,
    ExtraExtensionError = 20,
    BadSni = 21,
    BadHelloDone = 22,
    LimitExceeded = 23,
    BadFinished = 24,
    ResumeMismatch = 25,
    InvalidAlgorithm = 26,
    BadSignature = 27,
    WrongKeyUsage = 28,
    NoClientAuth = 29,
    SslIoError = 31,
    X509NoError = 32,
    X509InvalidValue = 33,
    X509TruncatedError = 34,
    X509EmptyChain = 35,
    X509InnerTrunc = 36,
    X509BadTagClass = 37,
    X509BadTagValue = 38,
    X509IndefiniteLength = 39,
    X509ExtraElement = 40,
    X509UnexpectedError = 41,
    X509NotConstructed = 42,
    X509NotPrimitive = 43,
    X509PartialByte = 44,
    X509BadBoolean = 45,
    X509Overflow = 46,
    X509BadDn = 47,
    X509BadTime = 48,
    X509Unsupported = 49,
    X509LimitExceeded = 50,
    X509WrongKeyType = 51,
    X509BadSignature = 52,
    X509TimeUnknown = 53,
    X509Expired = 54,
    X509DnMismatch = 55,
    X509BadServerName = 56,
    X509CriticalExtension = 57,
    X509NotCa = 58,
    X509ForbiddenKeyUsage = 59,
    X509WeakPublicKey = 60,
    X509NotTrusted = 62,
    RecvFatalAlert = 256,
    SendFatalAlert = 512

const
  SSLErrors = [
    (NoError, "No error"),
    (BadParam, "Caller-provided parameter is incorrect"),
    (BadState, "Operation requested by the caller cannot be applied with " &
               "the current context state (e.g. reading data while " &
               "outgoing data is waiting to be sent)"),
    (UnsupportedVersion, "Incoming protocol or record version is unsupported"),
    (BadVersion, "Incoming record version does not match the expected version"),
    (BadLength, "Incoming record length is invalid"),
    (TooLarge, "Incoming record is too large to be processed, or buffer is " &
               "too small for the handshake message to send"),
    (BadMac, "Decryption found an invalid padding, or the record MAC is " &
             "not correct"),
    (NoRandom, "No initial entropy was provided, and none can be obtained " &
               "from the OS"),
    (UnknownType, "Incoming record type is unknown"),
    (UnexpectedError, "Incoming record or message has wrong type with " &
                      "regards to the current engine state"),
    (BadCcs, "ChangeCipherSpec message from the peer has invalid contents"),
    (BadAlert, "Alert message from the peer has invalid contents (odd length)"),
    (BadHandshake, "Incoming handshake message decoding failed."),
    (OversizedIdError, "ServerHello contains a session ID which is larger " &
                       "than 32 bytes"),
    (BadCipherSuite, "Server wants to use a cipher suite that we did not " &
                     "claim to support. This is also reported if we tried " &
                     "to advertise a cipher suite that we do not support"),
    (BadCompression, "Server wants to use a compression that we did not " &
                     "claim to support"),
    (BadFraglen, "Server's max fragment length does not match client's"),
    (BadSecReneg, "Secure renegotiation failed"),
    (ExtraExtensionError, "Server sent an extension type that we did not " &
                          "announce, or used the same extension type several " &
                          "times in a single ServerHello"),
    (BadSni, "Invalid Server Name Indication contents (when used by the " &
             "server, this extension shall be empty)"),
    (BadHelloDone, "Invalid ServerHelloDone from the server (length is not 0)"),
    (LimitExceeded, "Internal limit exceeded (e.g. server's public key is " &
                    "too large)"),
    (BadFinished, "Finished message from peer does not match the expected " &
                  "value"),
    (ResumeMismatch, "Session resumption attempt with distinct version or " &
                     "cipher suite"),
    (InvalidAlgorithm, "Unsupported or invalid algorithm (ECDHE curve, " &
                       "signature algorithm, hash function"),
    (BadSignature, "Invalid signature (on ServerKeyExchange from server, " &
                   "or in CertificateVerify from client)"),
    (WrongKeyUsage, "Peer's public key does not have the proper type or is " &
                    "not allowed for requested operation"),
    (NoClientAuth, "Client did not send a certificate upon request, or the " &
                   "client certificate could not be validated"),
    (SslIoError, "I/O error or premature close on underlying transport stream"),
    (X509NoError, "Validation was successful"),
    (X509InvalidValue, "Invalid value in an ASN.1 structure"),
    (X509TruncatedError, "Truncated certificate"),
    (X509EmptyChain, "Empty certificate chain (no certificate at all)"),
    (X509InnerTrunc, "Decoding error: inner element extends beyond"),
    (X509BadTagClass, "Decoding error: unsupported tag class (application " &
                      "or private)"),
    (X509BadTagValue, "Decoding error: unsupported tag value"),
    (X509IndefiniteLength, "Decoding error: indefinite length"),
    (X509ExtraElement, "Decoding error: extraneous element"),
    (X509UnexpectedError, "Decoding error: unexpected element"),
    (X509NotConstructed, "Decoding error: expected constructed element, but " &
                         "is primitive"),
    (X509NotPrimitive, "Decoding error: expected primitive element, but is " &
                       "constructed"),
    (X509PartialByte, "Decoding error: BIT STRING length is not multiple of 8"),
    (X509BadBoolean, "Decoding error: BOOLEAN value has invalid length"),
    (X509Overflow, "Decoding error: value is off-limits"),
    (X509BadDn, "Invalid distinguished name"),
    (X509BadTime, "Invalid date/time representation"),
    (X509Unsupported, "Certificate contains unsupported features that " &
                      "cannot be ignored"),
    (X509LimitExceeded, "Key or signature size exceeds internal limits"),
    (X509WrongKeyType, "Key type does not match that which was expected."),
    (X509BadSignature, "Signature is invalid"),
    (X509TimeUnknown, "Validation time is unknown"),
    (X509Expired, "Certificate is expired or not yet valid"),
    (X509DnMismatch, "Issuer/subject DN mismatch in the chain"),
    (X509BadServerName, "Expected server name was not found in the chain"),
    (X509CriticalExtension, "Unknown critical extension in certificate"),
    (X509NotCa, "Not a CA, or path length constraint violation"),
    (X509ForbiddenKeyUsage, "Key Usage extension prohibits intended usage"),
    (X509WeakPublicKey, "Public key found in certificate is too small"),
    (X509NotTrusted, "Chain could not be linked to a trust anchor")
  ]

proc sslErrorMsg*(code: cint): string =
  ## Converts BearSSL integer error code to string representation.
  if int(code) > int(SendFatalAlert):
    let err = int(code) - int(SendFatalAlert)
    result = "(SendFatalAlert) Fatal alert (" & $err & ") sent to the peer"
  elif int(code) > int(RecvFatalAlert):
    let err = int(code) - int(RecvFatalAlert)
    result = "(RecvFatalAlert) Fatal alert (" & $err &
             ") received from the peer"
  else:
    for item in SSLErrors:
      if int(item[0]) == int(code):
        result = "(" & $cast[SSLError](code) & ") " & item[1]
        break
    if len(result) == 0:
      result = "(" & $code & ") Unknown error"

proc errorMsg*(code: SSLError): string =
  ## Converts enum error to string representation.
  for item in SSLErrors:
    if item[0] == code:
      result = "(" & $code & ") " & item[1]
      break
