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
test ! -e "$ciphertext"
initial_add_output=$(bb secrets add-recipient demo 2>&1)
case $initial_add_output in
  *reencrypt*) exit 1 ;;
esac
case $initial_add_output in
  *"bb secrets set 'demo'"*) ;;
  *) exit 1 ;;
esac
case $initial_add_output in
  *"bb secrets new 'demo'"*) ;;
  *) exit 1 ;;
esac
test ! -e "$ciphertext"
alice_public=$(age-keygen -y "$alice_key")
awk -v alice="$alice_public" '
  /^[[:space:]]*($|#)/ { next }
  { count++; if ($0 == alice) alice_count++ }
  END { exit !(count == 1 && alice_count == 1) }
' "$recipients"

# Values arrive on stdin; neither value is a shell argument or output.
printf '%s\n' 'https://team-ci.local.invalid' |
  bb secrets set demo :demo/service-url >/dev/null
test -s "$ciphertext"
test -s "$manifest"
printf '%s\n' 'alice-demo-api-key' |
  bb secrets set demo :demo/api-key >/dev/null

echo "Generating disposable Bob identity and adding its public key…"
age-keygen -o "$bob_key" >/dev/null 2>&1
bob_public=$(age-keygen -y "$bob_key")
teammate_add_output=$(bb secrets add-recipient demo "$bob_public" 2>&1)
case $teammate_add_output in
  *"bb secrets reencrypt 'demo'"*) ;;
  *) exit 1 ;;
esac
bb secrets reencrypt demo >/dev/null
awk -v alice="$alice_public" -v bob="$bob_public" '
  /^[[:space:]]*($|#)/ { next }
  {
    count++
    if ($0 == alice) alice_count++
    if ($0 == bob) bob_count++
  }
  END { exit !(count == 2 && alice_count == 1 && bob_count == 1) }
' "$recipients"

# Save an Alice decrypt (straight through age) only for a byte-for-byte proof. The EXIT trap removes
# both comparison files on success or failure; no plaintext reaches the terminal.
age --decrypt --identity "$alice_key" "$ciphertext" >"$alice_plain"
SECRETS_AGE_IDENTITY_FILE="$bob_key" \
  bb secrets verify demo >/dev/null
age --decrypt --identity "$bob_key" "$ciphertext" >"$bob_plain"
cmp -s "$alice_plain" "$bob_plain"

echo "Demo complete: Bob's identity passed verify and decrypted the ciphertext."
