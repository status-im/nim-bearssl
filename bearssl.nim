## Nim-BearSSL
## Copyright (c) 2018-2022 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

when defined(bearsslNewAbi):
  # This will become default in the future - we cannot use it now because there
  # are duplicate symbols in `decls.nim` - the new ABI can already be accessed
  # using the more specific imports (`import bearssl/ssl`)
  import
    ./bearssl/[
      aead, blockx, ec, errors, hash, hmac, kdf, pem, prf, rand, rsa, ssl, x509],
    ./bearssl/abi/[brssl, config]

  export
    aead, blockx, ec, errors, hash, hmac, kdf, pem, prf, rand, rsa, ssl, x509,
    brssl, config,
    errors

else:
  import
    ./bearssl/[errors, decls] # Deprecated, will be removed in the future

  export errors, decls


when defined(nimHasUsed): {.used.}
