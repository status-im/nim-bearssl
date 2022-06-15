import
  typetraits,
  ./abi/[bearssl_hash, bearssl_rand]

export bearssl_rand

# About types used in helpers:
# `bool` types are problematic because because they only use one bit of the
# entire byte - a similar problem occurs with `object` types with alignment
# gaps - `supportsCopyMem` is wrong here, we should be using `supportsMemCmp` or
# something similar that takes into account these issues, but alas, there's no
# such trait as of now

proc init*[S](T: type HmacDrbgContext, seed: openArray[S]): HmacDrbgContext =
  ## Create a new randomness context with the given seed - typically, a single
  ## instance per thread should be created.
  ##
  ## The seed can later be topped up with `update`.
  static: doAssert supportsCopyMem(S) and sizeof(S) > 0 and S isnot bool

  if seed.len == 0:
    hmacDrbgInit(result, addr bearssl_hash.sha256Vtable, nil, 0)
  else:
    # In theory the multiplication can overflow, but practically we can't
    # allocate that much memory, so it won't
    hmacDrbgInit(
      result, addr sha256Vtable, unsafeAddr seed[0], uint seed.len * sizeof(S))

proc new*(T: type HmacDrbgContext): ref HmacDrbgContext =
  ## Create a new randomness context intended to be shared between randomness
  ## consumers - typically, a single instance per thread should be created.
  ##
  ## The context is seeded with randomness from the OS / system.
  ## Returns `nil` if the OS / system has no randomness API.
  let seeder = prngSeederSystem(nil)
  if seeder == nil:
    return nil

  let rng = (ref HmacDrbgContext)()
  hmacDrbgInit(rng[], addr sha256Vtable, nil, 0)

  if seeder(addr rng.vtable) == 0:
    return nil

  rng

func generate*(ctx: var HmacDrbgContext, v: var auto) =
  ## Fill `v` with random data - `v` must be a simple type
  static: doAssert supportsCopyMem(type v)

  when sizeof(v) > 0:
    when v is bool:
      # `bool` would result in a heavily biased value because >0 == true
      var tmp: byte
      hmacDrbgGenerate(ctx, addr tmp, uint sizeof(tmp))
      v = (tmp and 1'u8) == 1
    else:
      hmacDrbgGenerate(ctx, addr v, uint sizeof(v))

func generate*[V](ctx: var HmacDrbgContext, v: var openArray[V]) =
  ## Fill `v` with random data - `T` must be a simple type
  static: doAssert supportsCopyMem(V) and sizeof(V) > 0

  when V is bool:
    for b in v.mitems:
      ctx.generate(b)
  else:
    if v.len > 0:
      # In theory the multiplication can overflow, but practically we can't
      # allocate that much memory, so it won't
      hmacDrbgGenerate(ctx, addr v[0], uint v.len * sizeof(V))

template generate*[V](ctx: var HmacDrbgContext, v: var seq[V]) =
  generate(ctx, v.toOpenArray(0, v.high()))

func generateBytes*(ctx: var HmacDrbgContext, n: int): seq[byte] =
  # https://github.com/nim-lang/Nim/issues/19357
  if n > 0:
    result = newSeqUninitialized[byte](n)
    ctx.generate(result)

func generate*(ctx: var HmacDrbgContext, T: type): T {.noinit.} =
  ## Create a new instance of `T` filled with random data - `T` must be
  ## a simple type
  ctx.generate(result)

func update*[S](ctx: var HmacDrbgContext, seed: openArray[S]) =
  ## Update context with additional seed data
  static: doAssert supportsCopyMem(S) and sizeof(S) > 0 and S isnot bool

  if seed.len > 0:
    # In theory the multiplication can overflow, but practically we can't
    # allocate that much memory, so it won't
    hmacDrbgUpdate(ctx, unsafeAddr seed[0], uint seed.len * sizeof(S))

# Convenience helpers using bearssl naming

template hmacDrbgGenerate*(
    ctx: var HmacDrbgContext, output: var openArray[byte]) =
  generate(ctx, output)
