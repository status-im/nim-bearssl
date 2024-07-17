import
  unittest2,
  ../bearssl/x509,
  ../bearssl/abi/brssl

{.used.}

type
  TLSAsyncStream* = ref object of RootRef
    xwc*: X509NoanchorContext
    x509*: X509MinimalContext

suite "x509":
  test "test x509NoanchorInit interface":

    let res = TLSAsyncStream()
    x509NoanchorInit(res.xwc, addr res.x509.vtable)
