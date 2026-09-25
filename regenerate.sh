#!/bin/sh

[[ $(c2nim -v) == "0.9.18" ]] || echo "Different c2nim used, check the code"

# Synthesize csources.patch (applied by bearssl/abi/csources.nim)
if ! git -C bearssl/csources diff --quiet; then
  echo "Clean bearssl/csources changes before re-generating!"
  exit 1
fi
perl -0777 -pi -e '
  # undefined-behavior: call to function through pointer to incorrect function type
  s{^(const br_\w+_class \w+ = \{.*?^\};)}{
    my ($vtable, $wrappers) = ($1, "");
    $vtable =~ s{\(([^()]+?)\s*\(\*\)\(([^()]*)\)\)\s*&(\w+)}{
      my ($ret, $fn, @types) = ($1, $3, split /,/, $2);
      my @args = map { "a$_" } 0 .. $#types;
      my $decl = join ",", map { "$types[$_] $args[$_]" } 0 .. $#types;
      my $call = "$fn((void *)" . join(", ", @args) . ")";
      $wrappers .= "static $ret\n${fn}_wrapper($decl)\n{\n\t"
        . ($ret eq "void" ? "" : "return ") . "$call;\n}\n\n";
      "&${fn}_wrapper";
    }ge;
    $vtable =~ /\(\*\)/ and die "$ARGV: unhandled cast\n";
    $wrappers . $vtable;
  }gmse;

  # undefined-behavior: member access within misaligned address
  s/\(\(br_union_u(\d+) \*\)dst\)->u = x;/uint$1_t v = x;\n\tmemcpy(dst, &v, sizeof v);/g;
  s/return \(\(const br_union_u(\d+) \*\)src\)->u;/uint$1_t v;\n\tmemcpy(&v, src, sizeof v);\n\treturn v;/g;
' bearssl/csources/src/inner.h bearssl/csources/src/*/*.c
echo "/* nim-bearssl patches applied - 2026-09-24 */" >> bearssl/csources/src/inner.h
git -C bearssl/csources diff > bearssl/csources.patch
git -C bearssl/csources checkout -- .

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
