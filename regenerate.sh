#!/bin/sh
mkdir -p gen
cp bearssl/csources/inc/*.h gen
unifdef -m -UBR_DOXYGEN_IGNORE gen/*.h
c2nim --header --importc --nep1 --prefix:br_ --prefix:BR_ --skipinclude --cdecl --skipcomments gen/*.h
sed -i -e "s/uint16T/uint16/g" -e "s/uint32T/uint32/g" -e "s/uint64T/uint64/g" -e "s/cdecl/importcFunc/g" -e "s/csize_t/int/g" gen/*.nim
