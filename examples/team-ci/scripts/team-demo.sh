#!/bin/sh
set -eu

# This script deliberately keeps every identity and plaintext under .local/.
# It never puts a secret value in a command argument and never prints one.
demo_dir=.local/demo
alice_key="$demo_dir/alice-key.txt"
bob_key="$demo_dir/bob-key.txt"
recipients="$demo_dir/recipients.txt"
ciphertext="$demo_dir/secrets.edn.age"
manifest="$demo_dir/secrets.edn.manifest"
alice_plain="$demo_dir/alice-decrypted.edn"
bob_plain="$demo_dir/bob-decrypted.edn"

# Comparison plaintext is temporary even when a later command fails. Keep
# identities, ciphertext, and manifest for inspection until explicit cleanup.
trap 'rm -f "$alice_plain" "$bob_plain"' EXIT

cleanup() {
  rm -f "$alice_key" "$bob_key" "$recipients" "$ciphertext" "$manifest" \
    "$alice_plain" "$bob_plain"
}

if [ "${1:-}" = cleanup ]; then
  cleanup
  echo "Removed the demo's named .local files (if present)."
  exit 0
fi

mkdir -p "$demo_dir"
cleanup

echo "Generating disposable Alice identity…"
bb secrets keygen demo >/dev/null
bb secrets add-recipient demo >/dev/null

# Values arrive on stdin; neither value is a shell argument or output.
printf '%s\n' 'https://team-ci.local.invalid' |
  bb secrets set demo :demo/service-url >/dev/null
printf '%s\n' 'alice-demo-api-key' |
  bb secrets set demo :demo/api-key >/dev/null

echo "Generating disposable Bob identity and adding its public key…"
age-keygen -o "$bob_key" >/dev/null 2>&1
bob_public=$(age-keygen -y "$bob_key")
bb secrets add-recipient demo "$bob_public" >/dev/null
bb secrets reencrypt demo >/dev/null

# Save an Alice decrypt only for a byte-for-byte proof. The EXIT trap removes
# both comparison files on success or failure; no plaintext reaches the terminal.
SECRETS_AGE_IDENTITY_FILE="$alice_key" \
  bb secrets decrypt demo "$ciphertext" >"$alice_plain"
SECRETS_AGE_IDENTITY_FILE="$bob_key" \
  bb secrets verify demo >/dev/null
SECRETS_AGE_IDENTITY_FILE="$bob_key" \
  bb secrets decrypt demo "$ciphertext" >"$bob_plain"
cmp -s "$alice_plain" "$bob_plain"

echo "Demo complete: Bob's identity passed verify and decrypted the ciphertext."
