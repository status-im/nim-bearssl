## Adapters for working with primitive Nim types similar to std/random.
##
## This module contains thin wrappers but does not cover advanced randomness
## concepts like distributions.

import
  std/typetraits,
  ./abi/[hash, rand]

export rand

proc new*(T: type HmacDrbgContext): ref HmacDrbgContext =
  ## Create a new randomness context intended to be shared between randomness
  ## consumers - typically, a single instance per thread should be created.
  ##
  ## The context is seeded with randomness from the OS / system.
  let seeder = prngSeederSystem(nil)
  if seeder == nil:
    return nil

  let rng = (ref T)()
  hmacDrbgInit(addr rng[], addr sha256Vtable, nil, 0)
  if seeder(addr rng.vtable) == 0:
    return nil

  rng

proc new*[A](T: type HmacDrbgContext, seed: openArray[A]): ref HmacDrbgContext =
  ## Create a new randomness context with the given seed - typically, a single
  ## instance per thread should be created.
  ##
  ## The context is seeded with the given non-empty `seed`.
  static: doAssert supportsCopyMem(A)

  doAssert seed.len > 0, "Seed must not be empty"
  let rng = (ref T)()
  hmacDrbgInit(addr rng[], addr sha256Vtable, unsafeAddr seed[0], seed.len * sizeof(seed[0]))
  rng

const randMax = uint64.high

proc rand*(rng: var HmacDrbgContext, max: uint64): uint64 =
  ## Return a random number in the range [0, max] (inclusive)
  var x: uint64
  hmacDrbgGenerate(addr rng, addr x, csize_t(sizeof(x)))

  if max == randMax:
    return x

  while true:
    if x <= randMax - (randMax mod max): # against modulo bias
      return x mod (max + 1) # inclusive of max

    hmacDrbgGenerate(addr rng, addr x, csize_t(sizeof(x)))

proc rand*(rng: var HmacDrbgContext, max: Natural): int =
  ## Return a random number in the range [0, max] (inclusive)
  int(rand(rng, uint64(max)))

proc sample*[T](rng: var HmacDrbgContext, a: openArray[T]): T =
  ## Return a random item from `a` - `a` must not be empty
  doAssert a.len > 0, "Cannot sample from empty array"
  a[rng.rand(a.high)]

proc shuffle*[T](rng: var HmacDrbgContext, a: var openArray[T]) =
  ## Shuffle contents of a using the Durstenfeld method of the Fisher-Yates
  ## shuffle
  ## https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm
  if a.len <= 1: return

  for i in countdown(a.high, 1):
    let j = rng.rand(i)
    if i != j:
      swap(a[i], a[j])

proc fill*[T](rng: var HmacDrbgContext, a: var openArray[T]) =
  ## Fill each item of `a` with random data
  static: doAssert supportsCopyMem(T)
  if a.len > 0:
    hmacDrbgGenerate(addr rng, addr a[0], csize_t(sizeof(a[0]) * a.len))

proc fill*[T](rng: var HmacDrbgContext, v: var T) =
  ## Fill v with random data
  static: doAssert supportsCopyMem(T)
  when sizeof(T) > 0:
    hmacDrbgGenerate(addr rng, addr v, csize_t(sizeof(T)) )

proc fill*(rng: var HmacDrbgContext, T: type): T {.noinit.} =
  ## Return an instance of T filled with random data
  fill(rng, result)
