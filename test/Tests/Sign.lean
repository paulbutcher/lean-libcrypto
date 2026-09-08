/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto
import Tests.Fixtures.Ed25519
import Tests.Fixtures.Signature
import Tests.Harness
import Tests.Hex

namespace Tests.Sign

open Libcrypto

private def spki (hex : String) : IO Evp.PKey := do
  let some key ← Evp.PKey.fromSpki (← Hex.ofHexOrThrow hex)
    | throw <| IO.userError "fixture SubjectPublicKeyInfo did not decode"
  return key

private def rawEd25519 (hex : String) : IO Evp.PKey := do
  let some key ← Evp.PKey.fromRawPublicKey "ED25519" (← Hex.ofHexOrThrow hex)
    | throw <| IO.userError "fixture Ed25519 public key was rejected"
  return key

/-- Flips the low bit of the last byte, which is enough to make any signature or
message the wrong one without changing its length. -/
private def tamper (bs : ByteArray) : ByteArray :=
  if h : bs.size = 0 then bs else bs.set (bs.size - 1) (bs[bs.size - 1]! ^^^ 1) (by omega)

private def ed25519Cases : Array Case :=
  Fixtures.Ed25519.all.toArray.flatMap fun (label, v) => #[
    { name := s!"RFC 8032 {label} verifies"
      run := do
        let signature ← Hex.ofHexOrThrow v.signature
        expect "did not verify"
          (← Sign.verify .ed25519 (← rawEd25519 v.publicKey)
            (← Hex.ofHexOrThrow v.message) signature) },
    { name := s!"RFC 8032 {label} fails on a flipped bit in the signature"
      run := do
        let signature := tamper (← Hex.ofHexOrThrow v.signature)
        expect "verified a tampered signature"
          !(← Sign.verify .ed25519 (← rawEd25519 v.publicKey)
              (← Hex.ofHexOrThrow v.message) signature) }]

private def openSslCliCases : Array Case :=
  let message := Fixtures.Signature.message.toUTF8
  #[
  { name := "an RSA PKCS#1 v1.5 signature from the openssl CLI verifies"
    run := do
      let key ← spki Fixtures.Signature.rsaSpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.rsaPkcs1Sha256
      expect "did not verify" (← Sign.verify (.rsaPkcs1 .sha256) key message sig) },
  { name := "an RSA-PSS signature from the openssl CLI verifies"
    run := do
      let key ← spki Fixtures.Signature.rsaSpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.rsaPssSha256
      expect "did not verify" (← Sign.verify (.rsaPss .sha256 .digest) key message sig) },
  { name := "an RSA-PSS signature verifies with the salt length recovered"
    run := do
      let key ← spki Fixtures.Signature.rsaSpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.rsaPssSha256
      expect "did not verify" (← Sign.verify (.rsaPss .sha256 .auto) key message sig) },
  { name := "an ECDSA P-256 signature from the openssl CLI verifies"
    run := do
      let key ← spki Fixtures.Signature.ecP256SpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.ecdsaP256Sha256
      expect "did not verify" (← Sign.verify (.ecdsa .sha256) key message sig) }]

private def negativeCases : Array Case :=
  let message := Fixtures.Signature.message.toUTF8
  #[
  { name := "a PSS signature does not verify under PKCS#1 v1.5 parameters"
    run := do
      let key ← spki Fixtures.Signature.rsaSpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.rsaPssSha256
      expect "verified under the wrong padding"
        !(← Sign.verify (.rsaPkcs1 .sha256) key message sig) },
  { name := "a PKCS#1 v1.5 signature does not verify under PSS parameters"
    run := do
      let key ← spki Fixtures.Signature.rsaSpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.rsaPkcs1Sha256
      expect "verified under the wrong padding"
        !(← Sign.verify (.rsaPss .sha256 .auto) key message sig) },
  { name := "an RSA signature does not verify under the wrong hash"
    run := do
      let key ← spki Fixtures.Signature.rsaSpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.rsaPkcs1Sha256
      expect "verified under SHA2-384"
        !(← Sign.verify (.rsaPkcs1 .sha384) key message sig) },
  { name := "an RSA signature does not verify over a tampered message"
    run := do
      let key ← spki Fixtures.Signature.rsaSpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.rsaPkcs1Sha256
      expect "verified a tampered message"
        !(← Sign.verify (.rsaPkcs1 .sha256) key (tamper message) sig) },
  { name := "an ECDSA signature does not verify with a flipped bit"
    run := do
      let key ← spki Fixtures.Signature.ecP256SpkiDer
      let sig ← Hex.ofHexOrThrow Fixtures.Signature.ecdsaP256Sha256
      expect "verified a tampered signature"
        !(← Sign.verify (.ecdsa .sha256) key message (tamper sig)) },
  { name := "an Ed25519 signature does not verify under another key"
    run := do
      let sig := Fixtures.Ed25519.test1.signature
      let otherPub := Fixtures.Ed25519.test2.publicKey
      expect "verified under the wrong key"
        !(← Sign.verify .ed25519 (← rawEd25519 otherPub) ByteArray.empty
            (← Hex.ofHexOrThrow sig)) }]

private def decodingCases : Array Case := #[
  { name := "fromSpki reports what the key turned out to be"
    run := do
      expectEq "RSA" (← spki Fixtures.Signature.rsaSpkiDer).typeName "RSA"
      expectEq "EC" (← spki Fixtures.Signature.ecP256SpkiDer).typeName "EC" },
  { name := "fromSpki answers none for bytes that are not a SubjectPublicKeyInfo"
    run := do
      expect "decoded random bytes"
        (← Evp.PKey.fromSpki (ByteArray.mk #[0x30, 0x03, 0x02, 0x01, 0x00])).isNone },
  { name := "fromSpki answers none for a truncated SubjectPublicKeyInfo"
    run := do
      let der ← Hex.ofHexOrThrow Fixtures.Signature.ecP256SpkiDer
      expect "decoded a truncated key" (← Evp.PKey.fromSpki (der.extract 0 40)).isNone },
  { name := "fromRawPublicKey answers none for the wrong length"
    run := do
      let key ← Hex.ofHexOrThrow Fixtures.Ed25519.test1.publicKey
      expect "accepted a 31 byte Ed25519 key"
        (← Evp.PKey.fromRawPublicKey "ED25519" (key.extract 0 31)).isNone },
  { name := "fromRawPublicKey reports the algorithm it was given"
    run := do
      expectEq "ED25519" (← rawEd25519 Fixtures.Ed25519.test1.publicKey).typeName "ED25519" }]

def cases : Array Case := ed25519Cases ++ openSslCliCases ++ negativeCases ++ decodingCases

end Tests.Sign
