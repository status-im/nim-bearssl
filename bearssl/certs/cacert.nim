## Nim-BearSSL
## Copyright (c) 2018-2021 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

## This module provides access to Mozilla's CA certificate store in PEM format.
## This certificate store was downloaded from
## https://curl.haxx.se/ca/cacert.pem
## And converted to C header using:
##
## echo '#include <brssl.h> > cacert.c'
## brssl ta cacert.pem | sed "s/static //" >> cacert.c.
## MozillaTrustAnchorsCount below needs to be updated manually to the same
## value as TAs_NUM

import ../abi/csources
from ../abi/bearssl_x509 import X509TrustAnchor

{.compile: bearPath & "/../certs/cacert20221116.c".}

const MozillaTrustAnchorsCount* = 142 # TAs_NUM

var MozillaTrustAnchors* {.importc: "TAs".}: array[
  MozillaTrustAnchorsCount, X509TrustAnchor]
