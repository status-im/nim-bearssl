import
  "."/[csources, inner]

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}

const
  bearHashPath = bearSrcPath & "hash/"

{.compile: bearHashPath & "dig_oid.c".}
{.compile: bearHashPath & "dig_size.c".}
{.compile: bearHashPath & "ghash_ctmul.c".}
{.compile: bearHashPath & "ghash_ctmul32.c".}
{.compile: bearHashPath & "ghash_ctmul64.c".}
{.compile: bearHashPath & "ghash_pclmul.c".}
{.compile: bearHashPath & "ghash_pwr8.c".}
{.compile: bearHashPath & "md5.c".}
{.compile: bearHashPath & "md5sha1.c".}
{.compile: bearHashPath & "mgf1.c".}
{.compile: bearHashPath & "multihash.c".}
{.compile: bearHashPath & "sha1.c".}
{.compile: bearHashPath & "sha2big.c".}
{.compile: bearHashPath & "sha2small.c".}

type
  HashClass* {.importc: "br_hash_class", header: "bearssl_hash.h", bycopy.} = object
    contextSize* {.importc: "context_size".}: uint
    desc* {.importc: "desc".}: uint32
    init* {.importc: "init".}: proc (ctx: ptr ptr HashClass) {.importcFunc.}
    update* {.importc: "update".}: proc (ctx: ptr ptr HashClass; data: pointer;
                                     len: uint) {.importcFunc.}
    `out`* {.importc: "out".}: proc (ctx: ptr ptr HashClass; dst: pointer) {.importcFunc.}
    state* {.importc: "state".}: proc (ctx: ptr ptr HashClass; dst: pointer): uint64 {.
        importcFunc.}
    setState* {.importc: "set_state".}: proc (ctx: ptr ptr HashClass; stb: pointer;
        count: uint64) {.importcFunc.}


template hashdesc_Id*(id: untyped): untyped =
  ((uint32)(id) shl hashdesc_Id_Off)

const
  HASHDESC_ID_OFF* = 0
  HASHDESC_ID_MASK* = 0xFF

template hashdesc_Out*(size: untyped): untyped =
  ((uint32)(size) shl hashdesc_Out_Off)

const
  HASHDESC_OUT_OFF* = 8
  HASHDESC_OUT_MASK* = 0x7F

template hashdesc_State*(size: untyped): untyped =
  ((uint32)(size) shl hashdesc_State_Off)

const
  HASHDESC_STATE_OFF* = 15
  HASHDESC_STATE_MASK* = 0xFF

template hashdesc_Lblen*(ls: untyped): untyped =
  ((uint32)(ls) shl hashdesc_Lblen_Off)

const
  HASHDESC_LBLEN_OFF* = 23
  HASHDESC_LBLEN_MASK* = 0x0F
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
    buf* {.importc: "buf".}: array[64, byte]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[4, uint32]



proc md5Init*(ctx: var Md5Context) {.importcFunc, importc: "br_md5_init",
                                 header: "bearssl_hash.h".}

proc md5Update*(ctx: var Md5Context; data: pointer; len: uint) {.importcFunc,
    importc: "br_md5_update", header: "bearssl_hash.h".}

proc md5Out*(ctx: var Md5Context; `out`: pointer) {.importcFunc, importc: "br_md5_out",
    header: "bearssl_hash.h".}

proc md5State*(ctx: var Md5Context; `out`: pointer): uint64 {.importcFunc,
    importc: "br_md5_state", header: "bearssl_hash.h".}

proc md5SetState*(ctx: var Md5Context; stb: pointer; count: uint64) {.importcFunc,
    importc: "br_md5_set_state", header: "bearssl_hash.h".}

const
  sha1ID* = 2


const
  sha1SIZE* = 20


var sha1Vtable* {.importc: "br_sha1_vtable", header: "bearssl_hash.h".}: HashClass


type
  Sha1Context* {.importc: "br_sha1_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, byte]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[5, uint32]



proc sha1Init*(ctx: var Sha1Context) {.importcFunc, importc: "br_sha1_init",
                                   header: "bearssl_hash.h".}

proc sha1Update*(ctx: var Sha1Context; data: pointer; len: uint) {.importcFunc,
    importc: "br_sha1_update", header: "bearssl_hash.h".}

proc sha1Out*(ctx: var Sha1Context; `out`: pointer) {.importcFunc, importc: "br_sha1_out",
    header: "bearssl_hash.h".}

proc sha1State*(ctx: var Sha1Context; `out`: pointer): uint64 {.importcFunc,
    importc: "br_sha1_state", header: "bearssl_hash.h".}

proc sha1SetState*(ctx: var Sha1Context; stb: pointer; count: uint64) {.importcFunc,
    importc: "br_sha1_set_state", header: "bearssl_hash.h".}

const
  sha224ID* = 3


const
  sha224SIZE* = 28


var sha224Vtable* {.importc: "br_sha224_vtable", header: "bearssl_hash.h".}: HashClass


type
  Sha224Context* {.importc: "br_sha224_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, byte]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[8, uint32]



proc sha224Init*(ctx: var Sha224Context) {.importcFunc, importc: "br_sha224_init",
                                       header: "bearssl_hash.h".}

proc sha224Update*(ctx: var Sha224Context; data: pointer; len: uint) {.importcFunc,
    importc: "br_sha224_update", header: "bearssl_hash.h".}

proc sha224Out*(ctx: var Sha224Context; `out`: pointer) {.importcFunc,
    importc: "br_sha224_out", header: "bearssl_hash.h".}

proc sha224State*(ctx: var Sha224Context; `out`: pointer): uint64 {.importcFunc,
    importc: "br_sha224_state", header: "bearssl_hash.h".}

proc sha224SetState*(ctx: var Sha224Context; stb: pointer; count: uint64) {.importcFunc,
    importc: "br_sha224_set_state", header: "bearssl_hash.h".}

const
  sha256ID* = 4


const
  sha256SIZE* = 32


var sha256Vtable* {.importc: "br_sha256_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha256Context* = Sha224Context


proc sha256Init*(ctx: var Sha256Context) {.importcFunc, importc: "br_sha256_init",
                                       header: "bearssl_hash.h".}

template sha256Update*(ctx: var Sha256Context; data: pointer; len: int) =
  sha224Update(ctx, data, len)

proc sha256Out*(ctx: var Sha256Context; `out`: pointer) {.importcFunc,
    importc: "br_sha256_out", header: "bearssl_hash.h".}

template sha256State*(ctx: var Sha256Context; `out`: pointer): uint64 =
  sha224State(ctx, `out`)

template sha256SetState*(ctx: var Sha256Context; stb: pointer; count: uint64) =
  sha224SetState(ctx, stb, count)

const
  sha384ID* = 5


const
  sha384SIZE* = 48


var sha384Vtable* {.importc: "br_sha384_vtable", header: "bearssl_hash.h".}: HashClass


type
  Sha384Context* {.importc: "br_sha384_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[128, byte]
    count* {.importc: "count".}: uint64
    val* {.importc: "val".}: array[8, uint64]



proc sha384Init*(ctx: var Sha384Context) {.importcFunc, importc: "br_sha384_init",
                                       header: "bearssl_hash.h".}

proc sha384Update*(ctx: var Sha384Context; data: pointer; len: uint) {.importcFunc,
    importc: "br_sha384_update", header: "bearssl_hash.h".}

proc sha384Out*(ctx: var Sha384Context; `out`: pointer) {.importcFunc,
    importc: "br_sha384_out", header: "bearssl_hash.h".}

proc sha384State*(ctx: var Sha384Context; `out`: pointer): uint64 {.importcFunc,
    importc: "br_sha384_state", header: "bearssl_hash.h".}

proc sha384SetState*(ctx: var Sha384Context; stb: pointer; count: uint64) {.importcFunc,
    importc: "br_sha384_set_state", header: "bearssl_hash.h".}

const
  sha512ID* = 6


const
  sha512SIZE* = 64


var sha512Vtable* {.importc: "br_sha512_vtable", header: "bearssl_hash.h".}: HashClass

type
  Sha512Context* = Sha384Context


proc sha512Init*(ctx: var Sha512Context) {.importcFunc, importc: "br_sha512_init",
                                       header: "bearssl_hash.h".}
const
  sha512Update* = sha384Update


proc sha512Out*(ctx: var Sha512Context; `out`: pointer) {.importcFunc,
    importc: "br_sha512_out", header: "bearssl_hash.h".}

const
  md5sha1ID* = 0


const
  md5sha1SIZE* = 36


var md5sha1Vtable* {.importc: "br_md5sha1_vtable", header: "bearssl_hash.h".}: HashClass


type
  Md5sha1Context* {.importc: "br_md5sha1_context", header: "bearssl_hash.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr HashClass
    buf* {.importc: "buf".}: array[64, byte]
    count* {.importc: "count".}: uint64
    valMd5* {.importc: "val_md5".}: array[4, uint32]
    valSha1* {.importc: "val_sha1".}: array[5, uint32]



proc md5sha1Init*(ctx: var Md5sha1Context) {.importcFunc, importc: "br_md5sha1_init",
    header: "bearssl_hash.h".}

proc md5sha1Update*(ctx: var Md5sha1Context; data: pointer; len: uint) {.importcFunc,
    importc: "br_md5sha1_update", header: "bearssl_hash.h".}

proc md5sha1Out*(ctx: var Md5sha1Context; `out`: pointer) {.importcFunc,
    importc: "br_md5sha1_out", header: "bearssl_hash.h".}

proc md5sha1State*(ctx: var Md5sha1Context; `out`: pointer): uint64 {.importcFunc,
    importc: "br_md5sha1_state", header: "bearssl_hash.h".}

proc md5sha1SetState*(ctx: var Md5sha1Context; stb: pointer; count: uint64) {.importcFunc,
    importc: "br_md5sha1_set_state", header: "bearssl_hash.h".}

type
  HashCompatContext* {.importc: "br_hash_compat_context", header: "bearssl_hash.h",
                      bycopy, union.} = object
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
    buf* {.importc: "buf".}: array[128, byte]
    count* {.importc: "count".}: uint64
    val32* {.importc: "val_32".}: array[25, uint32]
    val64* {.importc: "val_64".}: array[16, uint64]
    impl* {.importc: "impl".}: array[6, ptr HashClass]



proc multihashZero*(ctx: var MultihashContext) {.importcFunc, importc: "br_multihash_zero",
    header: "bearssl_hash.h".}

proc multihashSetimpl*(ctx: var MultihashContext; id: cint; impl: ptr HashClass) {.
    inline.} =
  ctx.impl[id - 1] = impl


proc multihashGetimpl*(ctx: var MultihashContext; id: cint): ptr HashClass {.inline.} =
  return ctx.impl[id - 1]


proc multihashInit*(ctx: var MultihashContext) {.importcFunc, importc: "br_multihash_init",
    header: "bearssl_hash.h".}

proc multihashUpdate*(ctx: var MultihashContext; data: pointer; len: uint) {.importcFunc,
    importc: "br_multihash_update", header: "bearssl_hash.h".}

proc multihashOut*(ctx: var MultihashContext; id: cint; dst: pointer): uint {.importcFunc,
    importc: "br_multihash_out", header: "bearssl_hash.h".}

type
  Ghash* {.importc: "br_ghash".} = proc (y: pointer; h: pointer; data: pointer; len: uint) {.importcFunc.}


proc ghashCtmul*(y: pointer; h: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_ghash_ctmul", header: "bearssl_hash.h".}

proc ghashCtmul32*(y: pointer; h: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_ghash_ctmul32", header: "bearssl_hash.h".}

proc ghashCtmul64*(y: pointer; h: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_ghash_ctmul64", header: "bearssl_hash.h".}

proc ghashPclmul*(y: pointer; h: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_ghash_pclmul", header: "bearssl_hash.h".}

proc ghashPclmulGet*(): Ghash {.importcFunc, importc: "br_ghash_pclmul_get",
                             header: "bearssl_hash.h".}

proc ghashPwr8*(y: pointer; h: pointer; data: pointer; len: uint) {.importcFunc,
    importc: "br_ghash_pwr8", header: "bearssl_hash.h".}

proc ghashPwr8Get*(): Ghash {.importcFunc, importc: "br_ghash_pwr8_get",
                           header: "bearssl_hash.h".}
