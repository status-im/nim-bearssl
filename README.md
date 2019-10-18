# bearssl

[![Build Status (Travis)](https://img.shields.io/travis/status-im/nim-bearssl/master.svg?label=Linux%20/%20macOS "Linux/macOS build status (Travis)")](https://travis-ci.org/status-im/nim-bearssl)
[![Windows build status (Appveyor)](https://img.shields.io/appveyor/ci/nimbus/nim-bearssl/master.svg?label=Windows "Windows build status (Appveyor)")](https://ci.appveyor.com/project/nimbus/nim-bearssl)
![Stability: experimental](https://img.shields.io/badge/stability-experimental-orange.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[BearSSL](https://bearssl.org/) wrapper.

## Installation

You can install the development version of the library through nimble with the following command
```
nimble install bearssl
```

### Using a static BearSSL library

By default, the bundled BearSSL source files will all be compiled and linked into your Nim project using `{.compile: ... .}` pragmas.
To build and use a BearSSL static library instead (so only the used objects are linked), install it like this:

```sh
nimble buildBundledLib
nimble install
```

Then add `-d:BearSSLBundledStaticLib` to your project's top-level "nim.cfg" or "config.nims".

#### MSVC

There's also experimental support for the MSVC compiler suite, if you can't use MingGW-w64.
From a Visual Studio Development Command Prompt (the "Native Tools" one matching your architecture), run:

```cmd
cd bearssl\csources
nmake lib
cd ..\..
nimble install
```

Don't forget to add `-d:BearSSLBundledStaticLib` to your project's top-level "nim.cfg" or "config.nims".

## License

Licensed and distributed under either of

* MIT license: [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT

or

* Apache License, Version 2.0, ([LICENSE-APACHEv2](LICENSE-APACHEv2) or http://www.apache.org/licenses/LICENSE-2.0)

at your option. These files may not be copied, modified, or distributed except according to those terms.

