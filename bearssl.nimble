import os, strutils

# Package
version       = "0.1.5"
author        = "Status Research & Development GmbH"
description   = "BearSSL wrapper"
license       = "MIT or Apache License 2.0"
mode          = ScriptMode.Verbose

# Dependencies
requires "nim >= 1.2.0",
          "unittest2"

### Helper functions
proc test(env, path: string) =
  # Compilation language is controlled by TEST_LANG
  exec "nim " & getEnv("TEST_LANG", "c") & " " & getEnv("NIMFLAGS") & " " & env &
    " -d:bearsslSplitAbi -rf --hints:off --skipParentCfg --styleCheck:usages --styleCheck:error " & path

task test, "Run tests":
  for path in listFiles(thisDir() / "tests"):
    if path.split(".")[^1] != "nim":
      continue
    test "-d:debug", path
    test "-d:release", path
    test "--gc:arc -d:release", path
    rmFile(path[0..^5].toExe())
