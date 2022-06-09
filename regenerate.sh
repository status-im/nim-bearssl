#!/bin/sh
mkdir -p gen
cp bearssl/csources/inc/*.h gen

# c2nim gets confused by #ifdef inside struct's
unifdef -m -UBR_DOXYGEN_IGNORE gen/*.h

c2nim --header --importc --nep1 --prefix:br_ --prefix:BR_ --skipinclude --cdecl --skipcomments gen/*.h

rename bearssl_ '' gen/*.nim
mv gen/block.nim gen/blockx.nim

rm gen/*.h

# Fix cosmetic and ease-of-use issues
sed -i -e "s/int16T/int16/g" -e "s/int32T/int32/g" -e "s/int64T/int64/g" -e "s/cuchar/byte/g" -e "s/cdecl/importcFunc/g" -e "s/csize_t/uint/g" gen/*.nim

