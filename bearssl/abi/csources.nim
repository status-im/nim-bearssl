## Nim-BearSSL
## Copyright (c) 2018-2022 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

import
  std/[os, strutils]

export os

# For each bearssl header file, we create one nim module that compilers the
# C file related to that module. Some C "modules" have dependencies - the Nim
# modules make sure to import these dependencies so that the correct C source
# files get compiled transitively.
#
# Most of the header-like content was generated with c2nim, then hand-edited.
#
# For historical reasons, some functions and types are exposed with a "Br"
# prefix - these have been marked deprecated.
#
# Some functions take a length as input - in bearssl, `csize_t` is used for this
# purpose - wrappers do the same

static: doAssert sizeof(csize_t) == sizeof(int)
const
  bearPath* = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "/../" &
             "csources" & "/"
  bearIncPath* = bearPath & "inc/"
  bearSrcPath* = bearPath & "src/"
  bearToolsPath* = bearPath & "tools/"

# TODO https://github.com/nim-lang/Nim/issues/19864

{.passc: "-I" & quoteShell(bearSrcPath)}
{.passc: "-I" & quoteShell(bearIncPath)}
{.passc: "-I" & quoteShell(bearToolsPath)}

when defined(windows):
  {.passc: "-DBR_USE_WIN32_TIME=1".}
  {.passc: "-DBR_USE_WIN32_RAND=1".}
else:
  {.passc: "-DBR_USE_UNIX_TIME=1".}
  {.passc: "-DBR_USE_URANDOM=1".}

when defined(i386) or defined(amd64) or defined(arm64):
  {.passc: "-DBR_LE_UNALIGNED=1".}
elif defined(powerpc) or defined(powerpc64):
  {.passc: "-DBR_BE_UNALIGNED=1".}
elif defined(powerpc64el):
  {.passc: "-DBR_LE_UNALIGNED=1".}

when sizeof(int) == 8:
  {.passc: "-DBR_64=1".}
  when hostCPU == "amd64":
    {.passc:" -DBR_amd64=1".}
  when defined(vcc):
    {.passc: "-DBR_UMUL128=1".}
  else:
    {.passc: "-DBR_INT128=1".}
