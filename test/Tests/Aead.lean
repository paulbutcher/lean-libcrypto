/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Libcrypto
import Tests.Fixtures.Aead
public import Tests.Harness
import Tests.Hex

public section

namespace Tests.Aead

open Libcrypto
open Tests.Fixtures.Aead (Vector)

private def aesGcmFor (keyBits : Nat) : IO Aead.Algorithm :=
  match keyBits with
  | 128 => pure .aes128Gcm
  | 192 => pure .aes192Gcm
  | 256 => pure .aes256Gcm
  | other => throw <| IO.userError s!"no AES-GCM algorithm for a {other} bit key"

/-- A valid vector is checked in both directions, so that a cipher that produced
the right bytes but reported the wrong length, or vice versa, cannot pass; an
invalid one must be refused with `none` rather than by raising. -/
private def runVector (a : Aead.Algorithm) (v : Vector) : IO Unit := do
  let key ← Hex.ofHexOrThrow v.key
  let nonce ← Hex.ofHexOrThrow v.nonce
  let aad ← Hex.ofHexOrThrow v.aad
  let sealed : Aead.Sealed :=
    { ciphertext := ← Hex.ofHexOrThrow v.ciphertext, tag := ← Hex.ofHexOrThrow v.tag }
  let where_ := s!"vector {v.id}{if v.comment.isEmpty then "" else s! " ({v.comment})"}"
  if v.valid then
    let produced ← Aead.encrypt a key nonce aad (← Hex.ofHexOrThrow v.plaintext)
    expectEq s!"{where_} ciphertext" (Hex.toHex produced.ciphertext) v.ciphertext
    expectEq s!"{where_} tag" (Hex.toHex produced.tag) v.tag
    let some recovered ← Aead.decrypt a key nonce aad sealed
      | throw <| IO.userError s!"{where_} did not decrypt"
    expectEq s!"{where_} plaintext" (Hex.toHex recovered) v.plaintext
  else
    expect s!"{where_} was accepted" (← Aead.decrypt a key nonce aad sealed).isNone

private def runAll (vectors : Array Vector) (algorithm : Nat → IO Aead.Algorithm) : IO Unit :=
  vectors.forM fun v => do runVector (← algorithm v.keyBits) v

private def wycheproofCases : Array Case := #[
  { name := s!"{Fixtures.Aead.aesGcm.size} Wycheproof AES-GCM vectors"
    run := runAll Fixtures.Aead.aesGcm aesGcmFor },
  { name := s!"{Fixtures.Aead.aesGcmVariableNonce.size} AES-GCM vectors with other nonce lengths"
    run := runAll Fixtures.Aead.aesGcmVariableNonce aesGcmFor },
  { name := s!"{Fixtures.Aead.chaCha20Poly1305.size} Wycheproof ChaCha20-Poly1305 vectors"
    run := runAll Fixtures.Aead.chaCha20Poly1305 fun _ => pure .chaCha20Poly1305 }]

private def key : ByteArray := ByteArray.mk (Array.replicate 32 0x2b)
private def nonce : ByteArray := ByteArray.mk (Array.replicate 12 0x7c)
private def plaintext : ByteArray := "attack at dawn".toUTF8
private def aad : ByteArray := "to: bob".toUTF8

/-- Flips the low bit of the last byte, leaving the length alone. -/
private def tamper (bs : ByteArray) : ByteArray :=
  if h : bs.size = 0 then bs else bs.set (bs.size - 1) (bs[bs.size - 1]! ^^^ 1) (by omega)

private def tamperingCases : Array Case := #[
  { name := "a tampered ciphertext is refused rather than raising"
    run := do
      let sealed ← Aead.encrypt .aes256Gcm key nonce aad plaintext
      let altered := { sealed with ciphertext := tamper sealed.ciphertext }
      expect "accepted" (← Aead.decrypt .aes256Gcm key nonce aad altered).isNone },
  { name := "a tampered tag is refused rather than raising"
    run := do
      let sealed ← Aead.encrypt .aes256Gcm key nonce aad plaintext
      let altered := { sealed with tag := tamper sealed.tag }
      expect "accepted" (← Aead.decrypt .aes256Gcm key nonce aad altered).isNone },
  { name := "a tampered aad is refused, so the aad really is authenticated"
    run := do
      let sealed ← Aead.encrypt .aes256Gcm key nonce aad plaintext
      expect "accepted" (← Aead.decrypt .aes256Gcm key nonce (tamper aad) sealed).isNone },
  { name := "aad supplied at only one end is refused"
    run := do
      let sealed ← Aead.encrypt .aes256Gcm key nonce aad plaintext
      expect "accepted" (← Aead.decrypt .aes256Gcm key nonce ByteArray.empty sealed).isNone },
  { name := "another nonce is refused"
    run := do
      let sealed ← Aead.encrypt .aes256Gcm key nonce aad plaintext
      expect "accepted" (← Aead.decrypt .aes256Gcm key (tamper nonce) aad sealed).isNone },
  { name := "another key is refused"
    run := do
      let sealed ← Aead.encrypt .aes256Gcm key nonce aad plaintext
      expect "accepted" (← Aead.decrypt .aes256Gcm (tamper key) nonce aad sealed).isNone },
  { name := "a truncated tag is refused rather than raising"
    run := do
      let sealed ← Aead.encrypt .aes256Gcm key nonce aad plaintext
      let altered := { sealed with tag := sealed.tag.extract 0 12 }
      expect "accepted" (← Aead.decrypt .aes256Gcm key nonce aad altered).isNone },
  { name := "ChaCha20-Poly1305 round trips with additional data"
    run := do
      let sealed ← Aead.encrypt .chaCha20Poly1305 key nonce aad plaintext
      expectEq "ciphertext length" sealed.ciphertext.size plaintext.size
      let some recovered ← Aead.decrypt .chaCha20Poly1305 key nonce aad sealed
        | throw <| IO.userError "did not decrypt"
      expectEq "plaintext" (Hex.toHex recovered) (Hex.toHex plaintext) },
  { name := "a key of the wrong length raises rather than being refused"
    run := expectThrows "encrypt with a 16 byte key under AES-256-GCM"
      (Aead.encrypt .aes256Gcm (key.extract 0 16) nonce aad plaintext) },
  { name := "an empty nonce raises rather than being refused"
    run := expectThrows "encrypt with an empty nonce"
      (Aead.encrypt .aes256Gcm key ByteArray.empty aad plaintext) },
  -- OpenSSL 3.0 reads through the null cipher when asked a context's block size,
  -- so these check that the shim refuses before it gets that far.
  { name := "a cipher context rejects an update before init"
    run := do expectThrows "update before init" ((← Evp.Cipher.Ctx.new).update plaintext) },
  { name := "a cipher context rejects additional data before init"
    run := do expectThrows "aad before init" ((← Evp.Cipher.Ctx.new).updateAad aad) },
  { name := "a cipher context rejects a final before init"
    run := do
      expectThrows "encrypt final before init" (← Evp.Cipher.Ctx.new).encryptFinal
      expectThrows "decrypt final before init" (← Evp.Cipher.Ctx.new).decryptFinal
      expectThrows "reading the tag before init" ((← Evp.Cipher.Ctx.new).getOctets "tag" 16) },
  { name := "the lengths each algorithm reports are the ones its cipher takes"
    run :=
      [Aead.Algorithm.aes128Gcm, .aes192Gcm, .aes256Gcm, .chaCha20Poly1305].forM fun a => do
        let cipher ← Evp.Cipher.fetch a.name
        expectEq s!"{a.name} key length" a.keyLength cipher.keyLength
        expectEq s!"{a.name} nonce length" a.nonceLength cipher.ivLength }]

def cases : Array Case := wycheproofCases ++ tamperingCases

end Tests.Aead
