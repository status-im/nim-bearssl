# Package
version       = "0.1.5"
author        = "Status Research & Development GmbH"
description   = "BearSSL wrapper"
license       = "MIT or Apache License 2.0"

# Dependencies
requires "nim >= 1.2.0"

### Helper functions
proc test(env, path: string) =
  # Compilation language is controlled by TEST_LANG
  var lang = "c"
  if existsEnv"TEST_LANG":
    lang = getEnv"TEST_LANG"

  exec "nim " & lang & " " & env &
    " -r --hints:off --warnings:off " & path

task test, "Run tests":
  exec "nim -v"
  test "-d:debug", "tests/test1"
  test "-d:release", "tests/test1"
  test "--gc:arc -d:release", "tests/test1"
