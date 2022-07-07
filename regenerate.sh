#!/bin/sh

[[ $(c2nim -v) == "0.9.18" ]] || echo "Different c2nim used, check the code"

mkdir -p gen
cp bearssl/csources/inc/*.h gen
cp bearssl/csources/tools/brssl.h gen

# c2nim gets confused by #ifdef inside struct's
unifdef -m -UBR_DOXYGEN_IGNORE gen/*.h

# TODO: several things broken in  c2nim 0.9.18
# https://github.com/nim-lang/c2nim/issues/239
# https://github.com/nim-lang/c2nim/issues/240
# https://github.com/nim-lang/c2nim/issues/241
# https://github.com/nim-lang/c2nim/issues/242

c2nim --header --importc --nep1 --prefix:br_ --prefix:BR_ --skipinclude --cdecl --skipcomments gen/*.h

rm gen/*.h

# Fix cosmetic and ease-of-use issues
sed -i \
  -e "s/int16T/int16/g" \
  -e "s/int32T/int32/g" \
  -e "s/int64T/int64/g" \
  -e "s/cuchar/byte/g" \
  -e "s/cdecl/importcFunc/g" \
  -e "s/csize_t/uint/g" \
  gen/*.nim

# The functions taking a "Context" don't allow `nil` being passed to them - use
# `var` instead - ditto for "output" parameters like length
sed -i \
  -e 's/ctx: ptr \(.*\)Context/ctx: var \1Context/g' \
  -e 's/ctx: ptr \(.*\)Keys/ctx: var \1Keys/g' \
  -e 's/hc: ptr \(.*\)Context/hc: var \1Context/g' \
  -e 's/sc: ptr \(.*\)Context/sc: var \1Context/g' \
  -e 's/cc: ptr \(.*\)Context/cc: var \1Context/g' \
  -e 's/kc: ptr \(.*\)Context/kc: var \1Context/g' \
  -e 's/xwc: ptr \(.*\)Context/xwc: var \1Context/g' \
  -e 's/len: ptr uint/len: var uint/g' \
  gen/*.nim
