#!/usr/bin/env bash
set -euo pipefail

# This creates only disposable demo material.  The identity and ciphertext
# are ignored by git; no real secret should ever be placed in this script.
demo_dir=".demo"
key_file="$demo_dir/age-key.txt"
plain_file="$demo_dir/secrets.edn"
dev_cipher="resources/dev/secrets.edn.age"
prod_cipher="resources/prod/secrets.edn.age"

command -v age >/dev/null || { echo "age is required" >&2; exit 1; }
command -v age-keygen >/dev/null || { echo "age-keygen is required" >&2; exit 1; }

umask 077
mkdir -p "$demo_dir" resources/dev resources/prod
# Always remove the temporary plaintext, including when age or cp fails.
trap 'rm -f -- "$plain_file"' EXIT
# These are all disposable, gitignored outputs owned by this demo.
rm -f "$key_file" "$dev_cipher" "$prod_cipher"
age-keygen -o "$key_file" >/dev/null 2>&1
printf '%s\n' \
  '{:demo/api-url "https://example.invalid"' \
  ' :demo/token "fake-token-for-local-demo-only"}' > "$plain_file"
age -e -i "$key_file" -o "$dev_cipher" "$plain_file" >/dev/null 2>&1
cp "$dev_cipher" "$prod_cipher"
rm -f "$plain_file"

echo "Created disposable demo identity at $key_file"
echo "Created ignored classpath ciphertext under resources/dev and resources/prod"
echo "For local run: SECRETS_AGE_IDENTITY_FILE=$key_file clojure -M:dev -m example.integrant-service.main"
