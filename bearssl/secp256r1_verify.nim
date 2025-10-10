import
  std/[os, strutils]

import
  ./abi/bearssl_ec

export
  bearssl_ec

const
  bearPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]

{.compile: bearPath & "/secp256r1_verify/ecdsa_i31_vrfy_raw.c".}
{.compile: bearPath & "/secp256r1_verify/ec_p256_m64.c".}

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}

# A special patch for secp256r1 verify raw due to
# original muladd function cannot handle h == 0 or h == N.
# Also return 0 if r == 0;
proc secp256r1_i31_vrfy_raw*(hash: pointer; hashLen: uint;
                     pk: ptr EcPublicKey; sig: pointer; sigLen: uint): uint32 {.
      importcFunc, importc, header: bearPath & "/secp256r1_verify/secp256r1_verify.h".}
