import
  "."/[csources, bearssl_x509]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "brssl.h".}
{.used.}

const
  bearToolsPath = bearPath / "tools"


{.compile: bearToolsPath / "vector.c".}
{.compile: bearToolsPath / "xmem.c".}
{.compile: bearToolsPath / "names.c".}
{.compile: bearToolsPath / "certs.c".}
{.compile: bearToolsPath / "files.c".}

type
  X509NoAnchorContext* {.importc: "x509_noanchor_context",
                         header: "brssl.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class

proc initNoAnchor*(xwc: var X509NoAnchorContext, inner: ptr ptr X509Class) {.
     importcFunc, importc: "x509_noanchor_init", header: "brssl.h".}
