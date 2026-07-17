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

# Include folders need to be avalable to all consumers of bearssl

# quoteShell is not defined when compiling to bare metal
when not defined(`any`) and not defined(standalone):
  {.passc: "-I" & quoteShell(currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]).}
  {.passc: "-I" & quoteShell(bearSrcPath)}
  {.passc: "-I" & quoteShell(bearIncPath)}
  {.passc: "-I" & quoteShell(bearToolsPath)}
else:
  {.passc: "-I\"" & currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "\"".}
  {.passc: "-I\"" & bearSrcPath & "\""}
  {.passc: "-I\"" & bearIncPath & "\""}
  {.passc: "-I\"" & bearToolsPath & "\""}

template currentSourceDir*(): string =
  # TODO https://github.com/nim-lang/Nim/issues/19558
  # parentDir breaks cross compilation  e.g. from linux to windows
  currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]
