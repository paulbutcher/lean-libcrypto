/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Libcrypto.Evp.Cipher

public section

namespace Libcrypto.Aead

/-- The AEADs worth reaching for by name. Anything else the linked OpenSSL
offers is reachable through `Evp.Cipher.fetch`. -/
inductive Algorithm where
  | aes128Gcm
  | aes192Gcm
  | aes256Gcm
  | chaCha20Poly1305
  deriving DecidableEq, Repr, Inhabited

def Algorithm.name : Algorithm → String
  | .aes128Gcm => "AES-128-GCM"
  | .aes192Gcm => "AES-192-GCM"
  | .aes256Gcm => "AES-256-GCM"
  | .chaCha20Poly1305 => "ChaCha20-Poly1305"

def Algorithm.keyLength : Algorithm → Nat
  | .aes128Gcm => 16
  | .aes192Gcm => 24
  | .aes256Gcm | .chaCha20Poly1305 => 32

/-- All four take a 96 bit nonce by default. GCM will accept others, and this
layer passes on whatever length it is given; ChaCha20-Poly1305 will not. -/
def Algorithm.nonceLength : Algorithm → Nat
  | _ => 12

/-- Every algorithm here authenticates with a full-length tag. A tag of any
other length was not produced by `encrypt`, and `decrypt` treats it as one that
does not authenticate rather than as a caller error. -/
def Algorithm.tagLength : Algorithm → Nat
  | _ => 16

/-- What `encrypt` produces. The tag is kept apart from the ciphertext rather
than appended to it, so that neither can be mistaken for the other. -/
structure Sealed where
  ciphertext : ByteArray
  tag : ByteArray

/-- Encrypts and authenticates. `aad` is covered by the tag but not encrypted,
so it comes back to `decrypt` unchanged and has to be supplied there too.

The nonce must never be reused with the same key: for these algorithms that
destroys confidentiality and lets an attacker forge tags. Nothing here can check
it, so it is the caller's to get right. -/
def encrypt (a : Algorithm) (key nonce aad plaintext : ByteArray) : IO Sealed := do
  let cipher ← Evp.Cipher.fetch a.name
  let ctx ← Evp.Cipher.Ctx.new
  ctx.encryptInit (some cipher) none none #[⟨"ivlen", .uint nonce.size⟩]
  ctx.encryptInit none (some key) (some nonce) #[]
  ctx.updateAad aad
  let body ← ctx.update plaintext
  let rest ← ctx.encryptFinal
  return { ciphertext := body ++ rest, tag := ← ctx.getOctets "tag" a.tagLength }

/-- `none` says the input does not authenticate under this key, nonce and
additional data, whether it was altered or never sealed at all. That is an
answer; a key of the wrong length for the algorithm is a caller error and
throws. -/
def decrypt (a : Algorithm) (key nonce aad : ByteArray) (sealed : Sealed) :
    IO (Option ByteArray) := do
  if sealed.tag.size ≠ a.tagLength then return none
  let cipher ← Evp.Cipher.fetch a.name
  let ctx ← Evp.Cipher.Ctx.new
  ctx.decryptInit (some cipher) none none #[⟨"ivlen", .uint nonce.size⟩]
  ctx.decryptInit none (some key) (some nonce) #[]
  ctx.updateAad aad
  let body ← ctx.update sealed.ciphertext
  ctx.setParams #[⟨"tag", .octets sealed.tag⟩]
  return (← ctx.decryptFinal).map (body ++ ·)

end Libcrypto.Aead
