# Package
mode          = ScriptMode.Verbose
version       = "0.1.5"
author        = "Status Research & Development GmbH"
description   = "BearSSL wrapper"
license       = "MIT or Apache License 2.0"

# Dependencies
requires "nim >= 1.2.0"

import strutils

proc compileStaticLibrary() =
  when defined(macosx):
    var numCPUs = gorge("sysctl -n hw.ncpu").strip()
  else:
    var numCPUs = gorge("nproc").strip()
  if numCPUs == "":
    numCPUs = "1"

  # add custom defines to `cdefs` (stuff like "-DBR_SLOW_MUL=1", not the ones already defined in "bearssl/csources/src/inner.h")
  var
    cdefs: seq[string] = @[]
    envCflags = "-O3 -pipe"
  if existsEnv("CFLAGS"):
    envCflags = getEnv("CFLAGS")
  let cflags = "CFLAGS=\"" & envCflags & " " & cdefs.join(" ") & "\""

  withDir "bearssl/csources":
    when defined(windows):
      when defined(vcc):
        # unclear how "vcc" can be defined in a *.nimble file: https://github.com/nim-lang/nimble/issues/726
        exec("nmake lib")
      else:
        exec("mingw32-make CC=gcc -j" & numCPUs & " " & cflags & " lib")
    else:
      exec("make -j" & numCPUs & " " & cflags & " lib")

task buildBundledLib, "build bundled library":
  compileStaticLibrary()

