## Nim-BearSSL
## Copyright (c) 2026 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

# Usage: nim e csources_patch.nims <bearssl> <dest>

import std/[os, strutils]

let
  n = paramCount() # arguments come last, after `e`, flags and the script
  (bearssl, dest) = (paramStr(n - 1), paramStr(n))
  tmp = dest & ".tmp"

if not dirExists(dest):
  # Copy csources to tmp
  rmDir(tmp)
  for dir in ["abi", "certs"]:
    mkDir(tmp / dir)
    for path in listFiles(bearssl / dir):
      if path.endsWith(".c"):
        cpFile(path, tmp / dir / path.extractFilename)
  for dir in ["inc", "src", "tools"]:
    cpDir(bearssl / "csources" / dir, tmp / "csources" / dir)

  # Apply patch
  putEnv("GIT_DIR", "/dev/null")  # Ignore outside repositories
  let cmd = "git -C " & quoteShell(tmp / "csources") & " apply " &
    quoteShell(bearssl / "csources.patch")
  echo cmd
  exec cmd

  # Move to dest (or cancel if someone else was faster)
  try:
    mvDir(tmp, dest)
  except OSError:
    if not dirExists(dest):
      raise
    rmDir(tmp)

echo dest
