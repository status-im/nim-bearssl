## Nim-BearSSL
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module provides access to Mozilla's CA certificate store in PEM format.
## This certificate store was downloaded from
## https://curl.haxx.se/ca/cacert-2020-06-24.pem
## And converted to C header using ``brssl ta cacert-2020-06-24.pem > cacert``.
from decls import X509TrustAnchor
from strutils import rsplit
from os import DirSep

const CurrentPath = currentSourcePath.rsplit(DirSep, 1)[0]

{.passC: "-I" & CurrentPath & DirSep & "certs".}

var MozillaTrustAnchors* {.
    importc: "TAs", header: "cacert20200624.h".}: array[138, X509TrustAnchor]
var MozillaTrustAnchorsCount* {.
    importc: "TAs_NUM", header: "cacert20200624.h".}: cint
