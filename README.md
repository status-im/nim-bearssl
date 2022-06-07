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

* `bearssl/abi` exposes the raw C functions of bearssl
* `bearssl/` (except for `abi`) exposes thin wrappers around the raw ABI making the functions more convenient to use in Nim

```nim
# You can import the whole library
import bearssl

# ... or simply parts thereof, which can save compilation time
import bearssl/random
```

## Installation

You can install the developement version of the library through nimble with the following command:

```
nimble install bearssl
```

`BearSSL` itself is compiled as part of your project - there is no need to install any third-party libraries.

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. This file may not be copied, modified, or distributed except according to those terms.
