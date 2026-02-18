#!/bin/sh
## Nim-BearSSL
## Copyright (c) 2026 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.
set -eu -o pipefail
cd -P -- "$(dirname -- "$0")"

if ! git diff --exit-code -- . ':(exclude)update.sh' > /dev/null; then
  echo "Commit changes before updating!"
  exit 1
fi

cd bearssl/certs

# Check if the certificates have changed
URL="https://curl.haxx.se/ca/cacert.pem"
curl -sSLO "${URL}"
HASH="$(shasum -a 256 cacert.pem | cut -d " " -f 1)"
sed -i.bak -E \
  -e "s|(// SHA-256: )[0-9a-f]+|\1${HASH}|" \
  cacert.c
rm cacert.c.bak
if git diff --exit-code > /dev/null; then
  echo "This repository is already up to date"
  rm cacert.pem
  exit 2  # No changes
fi

# Build brssl
if [ ! -x ../csources/build/brssl ]; then
  make -C ../csources build/brssl
fi

# Convert .pem to .c
TODAY="$(date +%Y-%m-%d)"
echo "// ${TODAY}: ${URL}" > cacert.c
echo "// SHA-256: ${HASH}" >> cacert.c
echo "" >> cacert.c
echo '#include <brssl.h>' >> cacert.c
../csources/build/brssl ta cacert.pem | sed "s/static //" >> cacert.c
rm cacert.pem

# Sync TAs_NUM to .nim
TAS_NUM="$(awk '/#define TAs_NUM/{print $3}' cacert.c)"
sed -i.bak -E \
  -e "s|[0-9]+( Status Research & Development GmbH)|$(date +%Y)\1|" \
  -e "s|[0-9]+(  # TAs_NUM)|${TAS_NUM}\1|" \
  cacert.nim
rm cacert.nim.bak

git commit -a \
  -m "Bump cacerts to ${TODAY}" \
  -m "- ${URL}"

echo "The repo has been updated with a commit recording the update."
echo "You can review the changes with 'git diff HEAD^' before pushing to a public repository."
