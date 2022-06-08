import
  "."/[csources, inner]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.pragma: headerFunc, importcFunc, header: "bearssl_hash.h".}
{.used.}

const
  bearHashPath = bearSrcPath / "hash"

{.compile: bearHashPath / "dig_oid.c".}
{.compile: bearHashPath / "dig_size.c".}
{.compile: bearHashPath / "ghash_ctmul.c".}
{.compile: bearHashPath / "ghash_ctmul32.c".}
{.compile: bearHashPath / "ghash_ctmul64.c".}
{.compile: bearHashPath / "ghash_pclmul.c".}
{.compile: bearHashPath / "ghash_pwr8.c".}
{.compile: bearHashPath / "md5.c".}
{.compile: bearHashPath / "md5sha1.c".}
{.compile: bearHashPath / "mgf1.c".}
{.compile: bearHashPath / "multihash.c".}
{.compile: bearHashPath / "sha1.c".}
{.compile: bearHashPath / "sha2big.c".}
{.compile: bearHashPath / "sha2small.c".}

type
  HashClass* {.importc: "br_hash_class", header: "bearssl_hash.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: int
    desc* {.importc: "desc".}: uint32
    init* {.importc: "init".}: proc (ctx: ptr ptr HashClass) {.importcFunc.}
    update* {.importc: "update".}: proc (ctx: ptr ptr HashClass; data: pointer; len: int) {.
        importcFunc.}
    output* {.importc: "out".}: proc (ctx: ptr ptr HashClass; dst: pointer) {.importcFunc.}
    state* {.importc: "state".}: proc (ctx: ptr ptr HashClass; dst: pointer): uint64 {.
        importcFunc.}
    setState* {.importc: "set_state".}: proc (ctx: ptr ptr HashClass; stb: pointer;
        count: uint64) {.importcFunc.}

template hashdesc_Id*(id: untyped): untyped =
  ((uint32)(id) shl hashdesc_Id_Off)

const
  HASHDESC_ID_OFF* = 0
  HASHDESC_ID_MASK* = 0x000000FF

template hashdesc_Out*(size: untyped): untyped =
  ((uint32)(size) shl hashdesc_Out_Off)

const
  HASHDESC_OUT_OFF* = 8
  HASHDESC_OUT_MASK* = 0x0000007F

template hashdesc_State*(size: untyped): untyped =
  ((uint32)(size) shl hashdesc_State_Off)

const
  HASHDESC_STATE_OFF* = 15
  HASHDESC_STATE_MASK* = 0x000000FF

template hashdesc_Lblen*(ls: untyped): untyped =
  ((uint32)(ls) shl hashdesc_Lblen_Off)

const
  HASHDESC_LBLEN_OFF* = 23
  HASHDESC_LBLEN_MASK* = 0x0000000F
  HASHDESC_MD_PADDING* = (1'u32 shl 28)
  HASHDESC_MD_PADDING_128* = (1'u32 shl 29)
  HASHDESC_MD_PADDING_BE* = (1'u32 shl 30)

const
  md5ID* = 1

const
  md5SIZE* = 16

var md5Vtable* {.importc: "br_md5_vtable", header: "bearssl_hash.h".}: HashClass

type
  Md5Context* {.importc: "br_md5_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, cuchar]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[4, uint32]


proc md5Init*(ctx: ptr Md5Context) {.importc: "br_md5_init", headerFunc.}

proc md5Update*(ctx: ptr Md5Context; data: pointer; len: int) {.
    importc: "br_md5_update", headerFunc.}

proc md5Out*(ctx: ptr Md5Context; `out`: pointer) {.importc: "br_md5_out",
    headerFunc.}

proc md5State*(ctx: ptr Md5Context; `out`: pointer): uint64 {.importc: "br_md5_state",
    headerFunc.}

proc md5SetState*(ctx: ptr Md5Context; stb: pointer; count: uint64) {.
    importc: "br_md5_set_state", headerFunc.}

const
  sha1ID* = 2

const
  sha1SIZE* = 20

var sha1Vtable* {.importc: "br_sha1_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha1Context* {.importc: "br_sha1_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, cuchar]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[5, uint32]


proc sha1Init*(ctx: ptr Sha1Context) {.importc: "br_sha1_init",
                                   headerFunc.}

proc sha1Update*(ctx: ptr Sha1Context; data: pointer; len: int) {.
    importc: "br_sha1_update", headerFunc.}

proc sha1Out*(ctx: ptr Sha1Context; `out`: pointer) {.importc: "br_sha1_out",
    headerFunc.}

proc sha1State*(ctx: ptr Sha1Context; `out`: pointer): uint64 {.
    importc: "br_sha1_state", headerFunc.}

proc sha1SetState*(ctx: ptr Sha1Context; stb: pointer; count: uint64) {.
    importc: "br_sha1_set_state", headerFunc.}

const
  sha224ID* = 3

const
  sha224SIZE* = 28

var sha224Vtable* {.importc: "br_sha224_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha256Context* = Sha224Context
  Sha224Context* {.importc: "br_sha224_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, cuchar]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[8, uint32]


proc sha224Init*(ctx: ptr Sha224Context) {.importc: "br_sha224_init",
                                       headerFunc.}

proc sha224Update*(ctx: ptr Sha224Context; data: pointer; len: int) {.
    importc: "br_sha224_update", headerFunc.}

proc sha224Out*(ctx: ptr Sha224Context; `out`: pointer) {.
    importc: "br_sha224_out", headerFunc.}

proc sha224State*(ctx: ptr Sha224Context; `out`: pointer): uint64 {.
    importc: "br_sha224_state", headerFunc.}

proc sha224SetState*(ctx: ptr Sha224Context; stb: pointer; count: uint64) {.
    importc: "br_sha224_set_state", headerFunc.}

const
  sha256ID* = 4

const
  sha256SIZE* = 32

var sha256Vtable* {.importc: "br_sha256_vtable", header: "bearssl_hash.h".}: HashClass

proc sha256Init*(ctx: ptr Sha256Context) {.
    importc: "br_sha256_init", headerFunc.}

proc sha256Out*(ctx: ptr Sha256Context; `out`: pointer) {.
    importc: "br_sha256_out", headerFunc.}

when false:
  proc sha256State*(ctx: ptr Sha256Context; `out`: pointer): uint64 {.
      importc: "br_sha256_state", headerFunc.}
else:
  const
    sha256State* = sha224State

when false:
  proc sha256SetState*(ctx: ptr Sha256Context; stb: pointer; count: uint64) {.
      importc: "br_sha256_set_state", headerFunc.}
else:
  const
    sha256SetState* = sha224SetState

const
  sha384ID* = 5

const
  sha384SIZE* = 48

var sha384Vtable* {.importc: "br_sha384_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha384Context* {.importc: "br_sha384_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[128, cuchar]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[8, uint64]


proc sha384Init*(ctx: ptr Sha384Context) {.importc: "br_sha384_init",
                                       headerFunc.}

proc sha384Update*(ctx: ptr Sha384Context; data: pointer; len: int) {.
    importc: "br_sha384_update", headerFunc.}

proc sha384Out*(ctx: ptr Sha384Context; `out`: pointer) {.
    importc: "br_sha384_out", headerFunc.}

proc sha384State*(ctx: ptr Sha384Context; `out`: pointer): uint64 {.
    importc: "br_sha384_state", headerFunc.}

proc sha384SetState*(ctx: ptr Sha384Context; stb: pointer; count: uint64) {.
    importc: "br_sha384_set_state", headerFunc.}

const
  sha512ID* = 6

const
  sha512SIZE* = 64

var sha512Vtable* {.importc: "br_sha512_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha512Context* = Sha384Context

proc sha512Init*(ctx: ptr Sha512Context) {.
    importc: "br_sha512_init", headerFunc.}

const
  sha512Update* = sha384Update

proc sha512Out*(ctx: ptr Sha512Context; `out`: pointer) {.
    importc: "br_sha512_out", headerFunc.}

const
  md5sha1ID* = 0

const
  md5sha1SIZE* = 36

var md5sha1Vtable* {.importc: "br_md5sha1_vtable", header: "bearssl_hash.h".}: HashClass

type
  Md5sha1Context* {.importc: "br_md5sha1_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, cuchar]
    count* {.importc: "count".}: uint64
    valMd5* {.importc: "val_md5".}: array[4, uint32]
    valSha1* {.importc: "val_sha1".}: array[5, uint32]


proc md5sha1Init*(ctx: ptr Md5sha1Context) {.importc: "br_md5sha1_init",
    headerFunc.}

proc md5sha1Update*(ctx: ptr Md5sha1Context; data: pointer; len: int) {.
    importc: "br_md5sha1_update", headerFunc.}

proc md5sha1Out*(ctx: ptr Md5sha1Context; `out`: pointer) {.
    importc: "br_md5sha1_out", headerFunc.}

proc md5sha1State*(ctx: ptr Md5sha1Context; `out`: pointer): uint64 {.
    importc: "br_md5sha1_state", headerFunc.}

proc md5sha1SetState*(ctx: ptr Md5sha1Context; stb: pointer; count: uint64) {.
    importc: "br_md5sha1_set_state", headerFunc.}

type
  HashCompatContext* {.importc: "br_hash_compat_context", header: "bearssl_hash.h",
                      union, bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    md5* {.importc: "md5".}: Md5Context
    sha1* {.importc: "sha1".}: Sha1Context
    sha224* {.importc: "sha224".}: Sha224Context
    sha256* {.importc: "sha256".}: Sha256Context
    sha384* {.importc: "sha384".}: Sha384Context
    sha512* {.importc: "sha512".}: Sha512Context
    md5sha1* {.importc: "md5sha1".}: Md5sha1Context


type
  MultihashContext* {.importc: "br_multihash_context", header: "bearssl_hash.h",
                     bycopy.} = object
    buf* {.importc: "buf".}: array[128, cuchar]
    count* {.importc: "count".}: uint64
    val32* {.importc: "val_32".}: array[25, uint32]
    val64* {.importc: "val_64".}: array[16, uint64]
    impl* {.importc: "impl".}: array[6, ptr HashClass]


proc multihashZero*(ctx: ptr MultihashContext) {.importc: "br_multihash_zero",
    headerFunc.}

proc multihashSetimpl*(ctx: ptr MultihashContext; id: cint; impl: ptr HashClass) {.
    inline.} =
  ctx.impl[id - 1] = impl

proc multihashGetimpl*(ctx: ptr MultihashContext; id: cint): ptr HashClass {.inline.} =
  return ctx.impl[id - 1]

proc multihashInit*(ctx: ptr MultihashContext) {.importc: "br_multihash_init",
    headerFunc.}

proc multihashUpdate*(ctx: ptr MultihashContext; data: pointer; len: int) {.
    importc: "br_multihash_update", headerFunc.}

proc multihashOut*(ctx: ptr MultihashContext; id: cint; dst: pointer): int {.
    importc: "br_multihash_out", headerFunc.}

type
  Ghash* {.importc: "br_ghash".} = proc (y: pointer; h: pointer; data: pointer; len: int) {.importcFunc.}

proc ghashCtmul*(y: pointer; h: pointer; data: pointer; len: int) {.
    importc: "br_ghash_ctmul", headerFunc.}

proc ghashCtmul32*(y: pointer; h: pointer; data: pointer; len: int) {.
    importc: "br_ghash_ctmul32", headerFunc.}

proc ghashCtmul64*(y: pointer; h: pointer; data: pointer; len: int) {.
    importc: "br_ghash_ctmul64", headerFunc.}

proc ghashPclmul*(y: pointer; h: pointer; data: pointer; len: int) {.
    importc: "br_ghash_pclmul", headerFunc.}

proc ghashPclmulGet*(): Ghash {.importc: "br_ghash_pclmul_get",
    headerFunc.}

proc ghashPwr8*(y: pointer; h: pointer; data: pointer; len: int) {.
    importc: "br_ghash_pwr8", headerFunc.}

proc ghashPwr8Get*(): Ghash {.importc: "br_ghash_pwr8_get", headerFunc.}

