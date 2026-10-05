## Nim-BearSSL
## Copyright (c) 2018-2026 Status Research & Development GmbH
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
# The header-like content is generated with c2nim by `regenerate.sh`.
#
# For historical reasons, some functions and types are exposed with a "Br"
# prefix - these have been marked deprecated.
#
# Some functions take a length as input - in bearssl, `csize_t` is used for this
# purpose - wrappers do the same

static: doAssert sizeof(csize_t) == sizeof(int)

const bearssl = currentSourcePath.rsplit({DirSep, AltSep}, 2)[0] & "/"
when defined(`any`) or defined(standalone):
  const patched = bearssl
else:
  import std/[compilesettings, hashes, macros]

  const patched = block:
    var nimcache = querySetting(nimcacheDir)
    if not nimcache.isAbsolute:  # e.g., `--nimcache:build/$projectName`
      # https://github.com/nim-lang/Nim/issues/26296
      let probe = nimcache & "/bearssl_probe"
      createDir(nimcache)
      writeFile(probe, "")
      if fileExists(probe):  # `nim check`, `nimsuggest` etc don't write
        let n = newEmptyNode()
        n.setLineInfo(probe, 1, 1)  # Resolved against the compiler's cwd
        nimcache = n.lineInfoObj.filename.parentDir
    if not nimcache.isAbsolute:  # Unknown cwd
      bearssl
    else:
      var h = hash(staticRead(bearssl & "csources.patch"))
      for dir in ["abi", "certs"]:
        for kind, path in walkDir(bearssl & dir):
          if path.endsWith(".c"):
            h = h !& hash(staticRead(path))
      let dest = nimcache & "/bearssl_" & toHex(!$h)
      if dirExists(dest):
        dest & "/"
      else:
        let (output, exitCode) = gorgeEx(
          quoteShell(getCurrentCompilerExe()) &
          " e --hints:off --warnings:off" &
          " --skipUserCfg --skipParentCfg --skipProjCfg " &
          quoteShell(bearssl & "abi/csources_patch.nims") & " " &
          quoteShell(bearssl) & " " & quoteShell(dest))
        doAssert exitCode == 0, output
        if output.len == 0:  # `nim check`, `nimsuggest` etc don't run tools
          bearssl
        else:
          dest & "/"

const
  bearPath* = patched & "csources/"
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
  (patched & "abi/").rsplit({DirSep, AltSep}, 1)[0]
