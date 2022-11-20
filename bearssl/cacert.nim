# TODO it should really be easier to use a pem file instead
{.deprecated: "use bearssl/abi/cacert".}
import
  ./abi/cacert

export cacert.MozillaTrustAnchorsCount, cacert.MozillaTrustAnchors
