import ./[consttypes, csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

{.compile: bearSrcPath & "settings.c".}

type
  ConfigOption* {.importc: "br_config_option", header: "bearssl.h", bycopy.} = object
    name* {.importc: "name".}: ConstCstring
    value* {.importc: "value".}: clong



proc getConfig*(): ptr ConfigOption {.importcFunc, importc: "br_get_config",
                                  header: "bearssl.h".}

const
  FEATURE_X509_TIME_CALLBACK* = 1
