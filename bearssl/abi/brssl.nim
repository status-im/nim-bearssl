import ./[csources, bearssl_block, bearssl_pem, bearssl_x509]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

{.compile: currentSourceDir & "/brssl.c".}

type
  X509NoanchorContext* {.importc: "x509_noanchor_context", header: "brssl_cpp.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class
    inner* {.importc: "inner".}: X509ClassPointerConst

proc x509NoanchorInit*(xwc: var X509NoanchorContext; inner: X509ClassPointerConst) {.
    importcFunc, importc: "x509_noanchor_init", header: "brssl_cpp.h".}

proc initNoAnchor*(xwc: var X509NoanchorContext, inner: X509ClassPointerConst) {.
     importcFunc, importc: "x509_noanchor_init", header: "brssl_cpp.h", deprecated: "x509NoanchorInit".}
