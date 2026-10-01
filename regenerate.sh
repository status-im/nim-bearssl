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
echo "/* nim-bearssl patches applied - 2026-09-24 - $(git -C bearssl/csources rev-parse HEAD) */" >> bearssl/csources/src/inner.h
git -C bearssl/csources diff > bearssl/csources.patch
git -C bearssl/csources checkout -- .

mkdir -p gen
cp bearssl/csources/inc/*.h gen
cp bearssl/csources/tools/brssl.h gen

# c2nim gets confused by #ifdef inside struct's
unifdef -m -UBR_DOXYGEN_IGNORE gen/*.h

# c2nim drops `const` - replace const pointers with const-qualified aliases
# (`ConstPointer`, `ConstPtrPtrXxx`, ..., defined further below).
# `const br_xxx *` only in function pointer types, not in struct fields
perl -0777 -pi -e '
  sub camel { join "", map { ucfirst } split /_/, $_[0] }
  s/\bconst void \*\s*/ConstPointer /g;
  s/\bconst unsigned char \*\s*/ConstPtrByte /g;
  s/\bconst char \*\s*/ConstCstring /g;
  s/\bconst br_(\w+) \*const \*\s*/"ConstPtrConstPtr" . camel($1) . " "/ge;
  s/\bconst br_(\w+) \*\*\s*/"ConstPtrPtr" . camel($1) . " "/ge;
  s/\bconst br_(\w+) \*\s*(\(\s*\*\s*\w+\s*\)\s*\()/"ConstPtr" . camel($1) . " $2"/ge;
  s{(\(\s*\*\s*\w+\s*\)\s*\()((?:[^()]|\((?2)\))*)(\))}{
    my ($pre, $params, $post) = ($1, $2, $3);
    $params =~ s/\bconst br_(\w+) \*\s*/"ConstPtr" . camel($1) . " "/ge;
    "$pre$params$post";
  }ge;

  # Sync pointer aliases from function typedefs to their concrete instantiations
  sub names { join ",", map { /(\w+)\s*$/ ? $1 : "" } split /,/, $_[0] }
  my %typedef;
  $typedef{names($2)} = 1
    while /typedef[^;(]*\(\s*\*\s*(\w+)\s*\)\s*\(((?:[^()]|\((?2)\))*)\)/g;
  s{(\bbr_\w+\s*\()((?:[^()]|\((?2)\))*)(\)\s*;)}{
    my ($pre, $params, $post) = ($1, $2, $3);
    $params =~ s/\bconst br_(\w+) \*\s*/"ConstPtr" . camel($1) . " "/ge
      if $typedef{names($params)};
    "$pre$params$post";
  }ge;
' gen/*.h

# TODO: several things broken in c2nim 0.9.18
# https://github.com/nim-lang/c2nim/issues/239
# https://github.com/nim-lang/c2nim/issues/240
# https://github.com/nim-lang/c2nim/issues/241
# https://github.com/nim-lang/c2nim/issues/242

c2nim --header --importc --nep1 --prefix:br_ --prefix:BR_ --skipinclude --cdecl --skipcomments gen/*.h

rm gen/*.h

# Fix cosmetic and ease-of-use issues
sed -i.bak \
  -e "s/int16T/int16/g" \
  -e "s/int32T/int32/g" \
  -e "s/int64T/int64/g" \
  -e "s/cuchar/byte/g" \
  -e "s/cdecl/importcFunc/g" \
  gen/*.nim
rm -f gen/*.nim.bak  # Portable GNU/macOS `sed` needs backup

# The functions taking a "Context" don't allow `nil` being passed to them - use
# `var` instead - ditto for "output" parameters like length
sed -i.bak \
  -e 's/ctx: ptr \(.*\)Context/ctx: var \1Context/g' \
  -e 's/ctx: ptr \(.*\)Keys/ctx: var \1Keys/g' \
  -e 's/hc: ptr \(.*\)Context/hc: var \1Context/g' \
  -e 's/sc: ptr \(.*\)Context/sc: var \1Context/g' \
  -e 's/cc: ptr \(.*\)Context/cc: var \1Context/g' \
  -e 's/kc: ptr \(.*\)Context/kc: var \1Context/g' \
  -e 's/xwc: ptr \(.*\)Context/xwc: var \1Context/g' \
  -e 's/len: ptr csize_t/len: var csize_t/g' \
  gen/*.nim
rm -f gen/*.nim.bak  # Portable GNU/macOS `sed` needs backup

# c2nim drops the C name of function pointer typedefs - restore it
perl -pi -e '
  sub snake { my $s = shift; $s =~ s/([a-z0-9])([A-Z])/$1_$2/g; lc $s }
  s/^(  (\w+)\*) = proc\b/"$1 {.importc: \"br_" . snake($2) . "\".} = proc"/e;
' gen/*.nim

# `setdest` in `bearssl/pem.nim` replaces `br_pem_decoder_setdest`
sed -i.bak '/^proc pemDecoderSetdest\*/,/^$/d' gen/bearssl_pem.nim
rm -f gen/bearssl_pem.nim.bak  # Portable GNU/macOS `sed` needs backup

# `const char **` keeps the names it already had
sed -i.bak 's/ptr ConstCstring/ProtocolNamesPointerConst/g' gen/bearssl_ssl.nim
sed -i.bak 's/ptr ConstCstring/constCstringArray/g' gen/bearssl_rand.nim
rm -f gen/bearssl_ssl.nim.bak gen/bearssl_rand.nim.bak  # Portable GNU/macOS `sed` needs backup

# Define the `const` pointer types used above, at the top of the module that
# defines the type they point to - aliased to `pointer` (not `ptr Xxx`)
perl -e '
  sub snake { my $s = shift; $s =~ s/([a-z0-9])([A-Z])/$1_$2/g; lc $s }
  my %src = map { local $/; open my $h, "<", $_ or die; ($_ => <$h>) } @ARGV;
  my (%used, %defs);
  $used{$_} = 1
    for map { /\b(ConstPtr\w+|ProtocolNamesPointerConst|constCstringArray)\b/g } values %src;
  for my $name (sort keys %used) {
    my ($f, $c);
    if (my ($kind, $type) = $name =~ /^ConstPtr(ConstPtr|Ptr|)(\w+)$/) {
      next if $type eq "Byte";
      ($f) = grep { $src{$_} =~ /^  \Q$type\E\* \{\.importc: /m } sort keys %src or next;
      $c = "const br_" . snake($type) . ($kind eq "ConstPtr" ? " *const *" : $kind eq "Ptr" ? "**" : " *");
    } else {
      ($f) = grep { $src{$_} =~ /\b$name\b/ } sort keys %src;
      $c = "const char **";
    }
    my ($h) = $f =~ /(\w+)\.nim$/;
    $defs{$f} .= "  $name* {.importc: \"$c\", header: \"$h.h\", bycopy.} = pointer\n";
  }
  for my $f (keys %defs) { open my $h, ">", $f or die; print $h "type\n$defs{$f}\n", $src{$f} =~ s/\A\n+//r }
' gen/*.nim

# Keep legacy names of `const` pointer types that were already public
sed -i.bak \
  -e 's/ConstPtrPtrPrngClass/PrngClassPointerConst/g' \
  -e 's/ConstPtrConstPtrX509Class/X509ClassPointerConstConst/g' \
  -e 's/ConstPtrPtrX509Class/X509ClassPointerConst/g' \
  -e 's/ConstPtrPtrSslSessionCacheClass/SslSessionCacheClassPointerConst/g' \
  gen/*.nim
rm -f gen/*.nim.bak  # Portable GNU/macOS `sed` needs backup

# `(const unsigned char *)"..."` constants are plain string literals
perl -pi -e '
  s{\(cast\[ConstPtrByte\]\(("[^"]*")\)\)}{
    (my $s = $1) =~ s/([\x80-\xff])/sprintf("\\x%02X", ord $1)/ge; "(($s))"
  }ge;
' gen/*.nim
