# bearssl

[![Build Status (Travis)](https://img.shields.io/travis/status-im/nim-bearssl/master.svg?label=Linux%20/%20macOS "Linux/macOS build status (Travis)")](https://travis-ci.org/status-im/nim-bearssl)
[![Windows build status (Appveyor)](https://img.shields.io/appveyor/ci/nimbus/nim-bearssl/master.svg?label=Windows "Windows build status (Appveyor)")](https://ci.appveyor.com/project/nimbus/nim-bearssl)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Github action](https://github.com/status-im/nim-bearssl/workflows/CI/badge.svg)

Simple [BearSSL](https://bearssl.org/) wrapper for Nim, fully integrated with the Nim build system.

Applications using `nim-bearssl` are fully stand-alone, needing no additional DLL or shared library.

## Usage

The library is organised into two parts:

* `bearssl/` (except for `abi`) exposes thin wrappers around the raw ABI making the functions more convenient to use in Nim
* `bearssl/abi` exposes the raw C functions of bearssl

For each `bearssl` header file, a corresponding Nim file exists - `bearssl_rand.h` ~ `bearssl/rand.nim`.

```nim
# You can import the whole library
import bearssl

# ... or simply parts thereof, which can save compilation time
import bearssl/rand
```

In general, the mappings follow the conventions of the original BearSSL library closely. The following conventions exist:

* the `br_` prefix has been dropped throughout
* functions taking a `XxxContext*` use `var` and not `ptr`
* `byte` replaces `unsigned char*` - this type is predominantly used for byte buffers
* `uint` used instead of `csize_t` - these are the same type in Nim, but spelled more conveniently
  * Canonical nim code will have to be careful when converting existing `int` lengths, looking out for out-of-range values

In addition to the raw `C`-like api, convenience functions are added where applicable - these follow a similar set of conventions:

* named after the function they simplify, but take advantage of types and overload support in Nim
* help turn pointers and bytes into Nim types

## Installation

You can install the developement version of the library through nimble with the following command:

```
nimble install bearssl
```

`BearSSL` itself is compiled as part of your project - there is no need to install any third-party libraries.

## Developer notes

When updating the library, `c2nim` is used via `regenerate.sh` to update the RAW ABI files. Manual editing is then needed to make a few adjustments to the mapping, after which the files can be generated.

When adding new convenience functions, these should be added to `bearssl/` instead of the generated files.

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
