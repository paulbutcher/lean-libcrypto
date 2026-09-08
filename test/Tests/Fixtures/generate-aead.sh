#!/usr/bin/env bash
# Copyright (c) 2026 Paul Butcher. All rights reserved.
# Released under Apache 2.0 license as described in the file LICENSE.

# Rewrites Aead.lean from Project Wycheproof. Run it from this directory.

set -euo pipefail

base=https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -sSf -o "$work/gcm.json" "$base/aes_gcm_test.json"
curl -sSf -o "$work/chacha.json" "$base/chacha20_poly1305_test.json"

# Every vector with the standard nonce and a short message, plus the two longest
# valid messages, so that a multi-block update is exercised as well.
cat > "$work/select.jq" <<'JQ'
[ .testGroups[] | select(.ivSize == 96) | .keySize as $ks | .tests[]
  | select((.msg | length) <= 160)
  | {tcId, keySize: $ks, comment, result, key, iv, aad, msg, ct, tag} ]
+
[ .testGroups[] | .keySize as $ks | .tests[]
  | select((.msg | length) > 160 and .result == "valid")
  | {tcId, keySize: $ks, comment, result, key, iv, aad, msg, ct, tag} ][0:2]
JQ

# One valid vector for each of the other nonce lengths GCM is tested at and
# OpenSSL will accept; its GCM refuses anything longer than 128 bytes.
cat > "$work/nonce.jq" <<'JQ'
[ .testGroups[] | select(.ivSize != 96 and .ivSize >= 8 and .ivSize <= 1024) | .keySize as $ks
  | (.tests | map(select(.result == "valid")) | .[0:1] | .[])
  | {tcId, keySize: $ks, comment, result, key, iv, aad, msg, ct, tag} ]
JQ

cat > "$work/emit.jq" <<'JQ'
[ .[] | "  ⟨\(.tcId), \(.comment|@json), \(if .result=="valid" then "true" else "false" end), \(.keySize),\n   \"\(.key)\", \"\(.iv)\", \"\(.aad)\", \"\(.msg)\", \"\(.ct)\", \"\(.tag)\"⟩" ]
| join(",\n")
JQ

emit() { jq -f "$work/$1.jq" "$work/$2" | jq -rf "$work/emit.jq"; }

{
  cat <<'LEAN'
/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/

/-!
Generated from Project Wycheproof's `testvectors_v1/aes_gcm_test.json` and
`testvectors_v1/chacha20_poly1305_test.json`. The selection is every vector with
a 96 bit nonce and a message of at most 80 bytes, plus the two longest valid
messages, plus one valid vector for each other nonce length AES-GCM is tested
at, up to the 128 byte nonce OpenSSL will accept. Regenerate with `test/Tests/Fixtures/generate-aead.sh`.
-/

namespace Tests.Fixtures.Aead

/-- `valid` is Wycheproof's verdict: `false` means the ciphertext, tag or
additional data was altered, so decryption must refuse it. -/
structure Vector where
  id : Nat
  comment : String
  valid : Bool
  keyBits : Nat
  key : String
  nonce : String
  aad : String
  plaintext : String
  ciphertext : String
  tag : String

LEAN
  echo "def aesGcm : Array Vector := #["
  emit select gcm.json
  echo "]"
  echo
  echo "/-- GCM accepts a nonce of any length, and this is the only place that is"
  echo "exercised: one vector from each length Wycheproof covers that OpenSSL will
accept, which is up to the 128 bytes its GCM implementation allows. -/"
  echo "def aesGcmVariableNonce : Array Vector := #["
  emit nonce gcm.json
  echo "]"
  echo
  echo "def chaCha20Poly1305 : Array Vector := #["
  emit select chacha.json
  echo "]"
  echo
  echo "end Tests.Fixtures.Aead"
} > "$work/Aead.lean"

mv "$work/Aead.lean" Aead.lean
