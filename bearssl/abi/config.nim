import
  "."/[csources]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl.h".}
{.used.}

const
  bearRootPath = bearSrcPath

{.compile: bearRootPath / "settings.c".}

type
  ConfigOption* {.importc: "br_config_option", header: "bearssl.h", bycopy.} = object
    name* {.importc: "name".}: cstring
    value* {.importc: "value".}: clong

proc getConfig*(): ptr ConfigOption {.importcFunc, importc: "br_get_config",
  headerFunc.}
