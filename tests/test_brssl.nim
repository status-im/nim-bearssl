import unittest2,
  ../bearssl/[x509, brssl]

{.used.}

suite "x509":
  test "init":
    var xwc: X509NoanchorContext
    var x509: X509MinimalContext

    x509MinimalInit(x509, nil, nil, 0)
    x509NoanchorInit(xwc, addr x509.vtable)
