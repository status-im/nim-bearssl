import
  typetraits,
  ./abi/[bearssl_hash, bearssl_rand]

export bearssl_rand

proc init*[A](T: type HmacDrbgContext, seed: openArray[A]): HmacDrbgContext =
  ## Create a new randomness context with the given seed - typically, a single
  ## instance per thread should be created.
  ##
  ## The context is seeded with the given non-empty `seed`.
  static: doAssert supportsCopyMem(A)

  doAssert seed.len > 0, "Seed must not be empty"
  hmacDrbgInit(
    result, addr sha256Vtable, unsafeAddr seed[0],
    uint seed.len * sizeof(seed[0]))

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

func generate*(ctx: var HmacDrbgContext, output: var openArray[byte]) =
  ## Generate a sequence of random bytes, storing them in `output`
  if output.len > 0:
    hmacDrbgGenerate(ctx, addr output[0], uint output.len)

func update*[T](ctx: var HmacDrbgContext, seed: openArray[T]) =
  ## Update context with additional seed data
  static: doAssert supportsCopyMem(T) and sizeof(T) > 0

  if seed.len > 0:
    hmacDrbgUpdate(ctx, unsafeAddr seed[0], uint sizeof(T) * seed.len)

# Additional helpers that are not part of the bearssl API but maintain its
# constant-time properties

func fill*[T](ctx: var HmacDrbgContext, v: openArray[T]) =
  ## Fill `v` with random data - `v` must be a simple type
  static: doAssert supportsCopyMem(T) and sizeof(T) > 0 and T isnot bool

  if v.len > 0:
    hmacDrbgGenerate(ctx, addr v[0], uint sizeof(T) * v.len)

func fill*(ctx: var HmacDrbgContext, v: var auto) =
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

func fill*(ctx: var HmacDrbgContext, T: type): T {.noinit.} =
  ## Create a new instance of `T` filled with random data - `T` must be
  ## a simple type
  fill(ctx, result)
