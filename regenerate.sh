#!/usr/bin/env bash
set -eu -o pipefail
cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")"

[[ $(c2nim -v) == "0.9.18" ]] || { echo "c2nim 0.9.18 required"; exit 1; }

# Byte-wise text processing and file name order
export LC_ALL=C

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

# c2nim gets confused by #ifdef inside struct's
unifdef -m -UBR_DOXYGEN_IGNORE gen/*.h || [ $? -eq 1 ]  # Exit status 1: files changed

# Declare the `#define` function aliases, so they bind as procs
perl -pi -e '
  s/^#define br_sha256_update\s.*/void br_sha256_update(br_sha256_context *ctx, const void *data, size_t len);/;
  s/^#define br_sha256_state\s.*/uint64_t br_sha256_state(const br_sha256_context *ctx, void *out);/;
  s/^#define br_sha256_set_state\s.*/void br_sha256_set_state(br_sha256_context *ctx, const void *stb, uint64_t count);/;
  s/^#define br_sha512_update\s.*/void br_sha512_update(br_sha512_context *ctx, const void *data, size_t len);/;
  s/^#define br_sha512_state\s.*/uint64_t br_sha512_state(const br_sha512_context *ctx, void *out);/;
  s/^#define br_sha512_set_state\s.*/void br_sha512_set_state(br_sha512_context *ctx, const void *stb, uint64_t count);/;
' gen/bearssl_hash.h

# Define the offsets before the macros shifting by them, so the templates bind them
perl -0pi -e 's/^(#define BR_HASHDESC_(ID|OUT|STATE|LBLEN)\(.*\n)(.*\n)(.*\n)/$3$4$1/gm' gen/bearssl_hash.h

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

# `static inline` functions are defined in the header - bind them like other functions
perl -0777 -pi -e 's/^static inline (.*?\))\n\{\n.*?^\}\n/$1;\n/gms' gen/*.h

# TODO: several things broken in c2nim 0.9.18
# https://github.com/nim-lang/c2nim/issues/239
# https://github.com/nim-lang/c2nim/issues/240
# https://github.com/nim-lang/c2nim/issues/241
# https://github.com/nim-lang/c2nim/issues/242

c2nim --header --importc --nep1 --prefix:br_ --prefix:BR_ --skipinclude --cdecl --skipcomments gen/*.h

rm gen/*.h

# Fix cosmetic and ease-of-use issues
sed -i.bak \
  -e "s/int\([0-9]*\)T/int\1/g" \
  -e "s/cuchar/byte/g" \
  -e "s/cdecl/importcFunc/g" \
  gen/*.nim
rm -f gen/*.nim.bak  # Portable GNU/macOS `sed` needs backup

# The functions taking a "Context" don't allow `nil` being passed to them - use
# `var` instead - ditto for "output" parameters like length
sed -i.bak -E \
  -e 's/(ctx|hc|sc|cc|kc): ptr ([A-Za-z0-9]*(Context|Keys)|SslSessionCacheLru)/\1: var \2/g' \
  -e 's/len: ptr csize_t/len: var csize_t/g' \
  gen/*.nim
rm -f gen/*.nim.bak  # Portable GNU/macOS `sed` needs backup

# Keep legacy names of `const char **` types
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

# Fix c2nim 0.9.18 output
perl -0777 -pi -e '
  sub snake { my $s = shift; $s =~ s/([a-z0-9])([A-Z])/$1_$2/g; lc $s }
  BEGIN {
    for my $f (@ARGV) {
      open my $h, "<", $f or die;
      local $/;
      $const{lc s/_//gr} = $_ for <$h> =~ /^\s+([A-Z][A-Z0-9_]*)\* =/mg;
    }
  }

  # `typedef struct br_xxx_ br_xxx;` becomes a type section of its own - merge
  # the type sections from there up to the struct, as they refer to each other
  my @names;
  push @names, $1 while /^type\n  (([A-Z])(\w*))\* = (?i:\2)\3\n/mg;
  for my $name (reverse @names) {
    s{^type\n  \Q$name\E\* = \w+\n(.*?)^(  \Q$name\E\* \{\.importc: "br_\w+)_"(.*?\n)\n}{
      my ($between, $def, $rest, $consts, $procs) = ($1, $2, $3, "", "");
      $between =~ s/^(const\n.*?\n)\n/$consts .= "$1\n"; ""/gmse;
      $between =~ s/^(proc .*?\n)\n/$procs .= "\n$1"; ""/gmse;
      $between =~ s/^type\n//gm;
      $between =~ s/\A\n+//;
      "${consts}type\n$between$def\"$rest$procs\n";
    }mse;
  }

  # Variables and function pointer types lack their C name
  my ($h) = $ARGV =~ /(\w+)\.nim$/;
  s/^var (\w+)\* \{\.header:/"var $1* {.importc: \"br_" . snake($1) . "\", header:"/gme;
  s/^(  (\w+)\*) = proc\b/"$1 {.importc: \"br_" . snake($2) . "\", header: \"$h.h\".} = proc"/gme;

  # References to macros come out mangled, e.g. `ssl_Bufsize_Input`
  s{("[^"\n]*")|\b([a-z]\w*_\w*)\b}{
    my ($str, $id) = ($1, $2);
    $str // $const{lc $id =~ s/_//gr} // $id;
  }ge;

  # Anonymous structs and unions are named by line, which is not unique - number
  # them in order, matching each field to the next one with its name
  my (%inner, $n);
  s{\b((INNER_C_(?:STRUCT|UNION)_\w+?)_\d+)\b(\*?)}{
    my ($name, $prefix, $def) = ($1, $2, $3);
    $def ? (push @{$inner{$name}}, "${prefix}_" . ++$n) && "$inner{$name}[-1]*"
         : shift @{$inner{$name}};
  }ge;
' gen/*.nim

delete_section() {  # $1: anchor regex, $2: file - every match, and blank lines before
  ANCHOR="$1" awk '
    function flush() {
      if (buf != "") { if (!hit) printf "%s%s", gap, buf ; gap = buf = "" ; hit = 0 }
    }
    /^$/ { flush() ; gap = gap "\n" ; next }
    /^[^ ]/ { flush() }
    { buf = buf $0 "\n" ; if ($0 ~ ENVIRON["ANCHOR"]) hit = 1 }
    END { flush() ; printf "%s", gap }' "$2" > "$2.bak"
  mv "$2.bak" "$2"
}

# Add imports and the C sources to compile, and move to `bearssl/abi`
PRAGMAS='{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}
{.used.}'

compile_all() {  # `bearssl/csources/src` directory
  for f in bearssl/csources/src/$1/*.c; do
    echo "{.compile: bearSrcPath & \"$1/${f##*/}\".}"
  done
}

generate_module() {  # `gen` module, `bearssl/abi` module - header from stdin
  { cat; perl -0777 -pe 's/\A\n+//; s/\n*\z/\n/' "gen/$1.nim"; } > "bearssl/abi/$2.nim"
  rm "gen/$1.nim"
}

# ------------------------------------------------------------------------------
# bearssl.h

generate_module bearssl config <<EOF
import ./[consttypes, csources]

$PRAGMAS

{.compile: bearSrcPath & "settings.c".}

EOF

# ------------------------------------------------------------------------------
# bearssl_aead.h

generate_module bearssl_aead bearssl_aead <<EOF
import ./[bearssl_block, bearssl_hash, consttypes, csources]

$PRAGMAS

$(compile_all aead)

EOF

# ------------------------------------------------------------------------------
# bearssl_block.h

generate_module bearssl_block bearssl_block <<EOF
import ./[consttypes, csources, intx]

$PRAGMAS

$(compile_all symcipher)

EOF

# ------------------------------------------------------------------------------
# bearssl_ec.h

generate_module bearssl_ec bearssl_ec <<EOF
import ./[bearssl_hash, bearssl_rand, consttypes, csources, intx]

$PRAGMAS

$(compile_all ec)

EOF

# ------------------------------------------------------------------------------
# bearssl_hash.h

generate_module bearssl_hash bearssl_hash <<EOF
import ./[consttypes, csources, inner]

$PRAGMAS

$(compile_all hash)

EOF

# ------------------------------------------------------------------------------
# bearssl_hmac.h

generate_module bearssl_hmac bearssl_hmac <<EOF
import ./[bearssl_hash, consttypes, csources, inner]

$PRAGMAS

$(compile_all mac)

EOF

# ------------------------------------------------------------------------------
# bearssl_kdf.h

# `BR_HKDF_NO_SALT` is the address of a variable
delete_section '^  HKDF_NO_SALT\* = ' gen/bearssl_kdf.nim

generate_module bearssl_kdf bearssl_kdf <<EOF
import ./[bearssl_hash, bearssl_hmac, consttypes, csources]

$PRAGMAS

$(compile_all kdf)

EOF

# ------------------------------------------------------------------------------
# bearssl_pem.h

# `bearssl/pem.nim` wraps the decoder context, and `setdest` replaces
# `br_pem_decoder_setdest`
sed -i.bak 's/PemDecoderContext/RawPemDecoderContext/g' gen/bearssl_pem.nim
rm -f gen/bearssl_pem.nim.bak  # Portable GNU/macOS `sed` needs backup

delete_section '^proc pemDecoderSetdest\*' gen/bearssl_pem.nim

generate_module bearssl_pem bearssl_pem <<EOF
import ./[consttypes, csources]
export consttypes

$PRAGMAS

{.compile: bearSrcPath & "codec/pemdec.c".}
{.compile: bearSrcPath & "codec/pemenc.c".}

EOF

# ------------------------------------------------------------------------------
# bearssl_prf.h

generate_module bearssl_prf bearssl_prf <<EOF
import ./[consttypes, csources]

$PRAGMAS

{.compile: bearSrcPath & "ssl/prf.c".}
{.compile: bearSrcPath & "ssl/prf_md5sha1.c".}
{.compile: bearSrcPath & "ssl/prf_sha256.c".}
{.compile: bearSrcPath & "ssl/prf_sha384.c".}

EOF

# ------------------------------------------------------------------------------
# bearssl_rand.h

# `aesctr_drbg.c` is not compiled
delete_section '[Aa]esctrDrbg' gen/bearssl_rand.nim

generate_module bearssl_rand bearssl_rand <<EOF
import ./[bearssl_hash, bearssl_hmac, consttypes, csources]

$PRAGMAS

{.compile: bearSrcPath & "rand/hmac_drbg.c".}
{.compile: bearSrcPath & "rand/sysrng.c".}

EOF

# ------------------------------------------------------------------------------
# bearssl_rsa.h

# Keep legacy names of the key buffer size templates
sed -i.bak -E 's/rsa_Kbuf_(Priv|Pub)_Size/rsaKbuf\1Size/g' gen/bearssl_rsa.nim
rm -f gen/bearssl_rsa.nim.bak  # Portable GNU/macOS `sed` needs backup

generate_module bearssl_rsa bearssl_rsa <<EOF
import ./[bearssl_hash, bearssl_rand, consttypes, csources, intx]

$PRAGMAS

# TODO Compile only the relevant backends for each platform
{.compile: currentSourceDir() & "/bearssl_rsa.c".} # includes i62
{.compile: currentSourceDir() & "/bearssl_rsa_i15.c".}
{.compile: currentSourceDir() & "/bearssl_rsa_i31.c".}
{.compile: currentSourceDir() & "/bearssl_rsa_i32.c".}

EOF

# ------------------------------------------------------------------------------
# bearssl_ssl.h

# Nim emits `ptr array[N, T]` as `T *` - the C `br_suite_translated *` points
# into `client_suites[BR_MAX_CIPHER_SUITES]`
sed -i.bak 's/\(proc sslServerGetClientSuites\*.*\): ptr SuiteTranslated/\1: ptr array[MAX_CIPHER_SUITES, SuiteTranslated]/' gen/bearssl_ssl.nim
rm -f gen/bearssl_ssl.nim.bak  # Portable GNU/macOS `sed` needs backup

# Legacy overloads taking `int` lengths - checked, as `int` and `size_t` differ
# in signedness and possibly in size
cat >> gen/bearssl_ssl.nim <<'EOF'

func toSizeT(len: int): csize_t =
  doAssert len >= 0 and uint64(len) <= uint64(high(csize_t))
  csize_t(len)

template sslClientSetSingleRsa*(cc: var SslClientContext; chain: ptr X509Certificate;
                               chainLen: int; sk: ptr RsaPrivateKey;
                               irsasign: RsaPkcs1Sign) =
  sslClientSetSingleRsa(cc, chain, toSizeT(chainLen), sk, irsasign)

template sslClientSetSingleEc*(cc: var SslClientContext; chain: ptr X509Certificate;
                              chainLen: int; sk: ptr EcPrivateKey;
                              allowedUsages: cuint; certIssuerKeyType: cuint;
                              iec: ptr EcImpl; iecdsa: EcdsaSign) =
  sslClientSetSingleEc(cc, chain, toSizeT(chainLen), sk, allowedUsages,
                       certIssuerKeyType, iec, iecdsa)

template sslSessionCacheLruInit*(cc: var SslSessionCacheLru; store: ptr byte;
                                storeLen: int) =
  sslSessionCacheLruInit(cc, store, toSizeT(storeLen))
EOF

generate_module bearssl_ssl bearssl_ssl <<EOF
import
  ./[
    bearssl_aead, bearssl_block, bearssl_ec, bearssl_hash, bearssl_hmac, bearssl_prf,
    bearssl_rand, bearssl_rsa, bearssl_x509, consttypes, csources,
  ]

$PRAGMAS

{.compile: currentSourceDir() & "/bearssl_ssl.c".}

# Unity conflicts
{.compile: bearSrcPath & "ssl/ssl_ccert_single_rsa.c".}
{.compile: bearSrcPath & "ssl/ssl_hs_server.c".}
{.compile: bearSrcPath & "ssl/ssl_scert_single_rsa.c".}

EOF

# ------------------------------------------------------------------------------
# bearssl_x509.h

# Keep legacy `bool` flags
sed -i.bak -E '/^    (decoded|isCA)\* /s/: byte$/: bool/' gen/bearssl_x509.nim
rm -f gen/bearssl_x509.nim.bak  # Portable GNU/macOS `sed` needs backup

generate_module bearssl_x509 bearssl_x509 <<EOF
import ./[bearssl_ec, bearssl_hash, bearssl_rsa, consttypes, csources]

$PRAGMAS

$(compile_all x509)

EOF

# ------------------------------------------------------------------------------
# brssl.h

# Only `x509_noanchor` is used from the command line tool sources
cat > gen/brssl.nim <<'EOF'
type
  X509NoanchorContext* {.importc: "x509_noanchor_context", header: "brssl_cpp.h", bycopy.} = object
    vtable* {.importc: "vtable".}: ptr X509Class
    inner* {.importc: "inner".}: X509ClassPointerConst

proc x509NoanchorInit*(xwc: var X509NoanchorContext; inner: X509ClassPointerConst) {.
    importcFunc, importc: "x509_noanchor_init", header: "brssl_cpp.h".}

proc initNoAnchor*(xwc: var X509NoanchorContext, inner: X509ClassPointerConst) {.
     importcFunc, importc: "x509_noanchor_init", header: "brssl_cpp.h", deprecated: "x509NoanchorInit".}
EOF

generate_module brssl brssl <<EOF
import ./[csources, bearssl_block, bearssl_pem, bearssl_x509]

$PRAGMAS

{.compile: currentSourceDir & "/brssl.c".}

EOF

rmdir gen
