import
  "."/[csources, bearssl_block, bearssl_pem, bearssl_x509]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearToolsPath = bearPath & "tools/"

{.compile: bearToolsPath & "vector.c".}
{.compile: bearToolsPath & "xmem.c".}
{.compile: bearToolsPath & "names.c".}
{.compile: bearToolsPath & "certs.c".}
{.compile: bearToolsPath & "files.c".}

type
  X509NoanchorContext* {.importc: "x509_noanchor_context", header: "brssl_cpp.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class
    inner* {.importc: "inner".}: ptr ptr X509Class

proc x509NoanchorInit*(xwc: var X509NoanchorContext; inner: ptr ptr X509Class) {.importcFunc,
    importc: "x509_noanchor_init", header: "brssl_cpp.h".}

proc initNoAnchor*(xwc: var X509NoanchorContext, inner: ptr ptr X509Class) {.
     importcFunc, importc: "x509_noanchor_init", header: "brssl_cpp.h", deprecated: "x509NoanchorInit".}
