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
    hmacDrbgInit(result, addr sha256Vtable, nil, 0)
  else:
    hmacDrbgInit(
      result, addr sha256Vtable, unsafeAddr seed[0], uint seed.len * sizeof(S))

proc init*(T: type HmacDrbgContext, seeder: PrngSeeder): HmacDrbgContext =
  ## Create a new randomness context with the given seed - typically, a single
  ## instance per thread should be created.
  ##
  ## The context is seeded with the given non-empty `seed`.
  hmacDrbgInit(result, addr sha256Vtable, nil, 0)

proc new*(T: type HmacDrbgContext): ref HmacDrbgContext =
  ## Create a new randomness context intended to be shared between randomness
  ## consumers - typically, a single instance per thread should be created.
  ##
  ## The context is seeded with randomness from the OS / system.
  let seeder = prngSeederSystem(nil)
  if seeder == nil:
    return nil

  let rng = (ref T)()
  rng[] = HmacDrbgContext.init(seeder)
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
      hmacDrbgGenerate(ctx, addr v[0], uint v.len * sizeof(V))

template generate*[V](ctx: var HmacDrbgContext, v: var seq[V]) =
  generate(ctx, v.toOpenArray(0, v.high()))

func generate*(ctx: var HmacDrbgContext, T: type): T {.noinit.} =
  ## Create a new instance of `T` filled with random data - `T` must be
  ## a simple type
  generate(ctx, result)

func update*[S](ctx: var HmacDrbgContext, seed: openArray[S]) =
  ## Update context with additional seed data
  static: doAssert supportsCopyMem(S) and sizeof(S) > 0 and S isnot bool

  if seed.len > 0:
    hmacDrbgUpdate(ctx, unsafeAddr seed[0], uint seed.len * sizeof(S))

# Convenience helpers using bearssl naming

template hmacDrbgGenerate*(
    ctx: var HmacDrbgContext, output: var openArray[byte]) =
  generate(ctx, output)
