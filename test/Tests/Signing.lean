/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Libcrypto
import Tests.Fixtures.Ed25519
import Tests.Fixtures.Signature
public import Tests.Harness
import Tests.Hex

public section

namespace Tests.Signing

open Libcrypto

private def message : ByteArray := "a message to be signed".toUTF8

private def rawEd25519Private (hex : String) : IO Evp.PKey := do
  let some key ← Evp.PKey.fromRawPrivateKey "ED25519" (← Hex.ofHexOrThrow hex)
    | throw <| IO.userError "fixture Ed25519 secret key was rejected"
  return key

/-- Ed25519 is the one scheme here whose signature is a function of the key and
message alone, so it is the one that can be checked against a published value
rather than only against this library's own verifier. -/
private def ed25519ReproducesVectors : Array Case :=
  Fixtures.Ed25519.all.toArray.map fun (label, v) =>
    { name := s!"RFC 8032 {label} is reproduced by signing"
      run := do
        let key ← rawEd25519Private v.secret
        let signature ← Sign.sign .ed25519 key (← Hex.ofHexOrThrow v.message)
        expectEq "signature" (Hex.toHex signature) v.signature }

private def roundTripCases : Array Case := #[
  { name := "an ECDSA P-256 signature verifies, and does not once tampered with"
    run := do
      let key ← Evp.PKey.generate "EC" #[⟨"group", .utf8 "P-256"⟩]
      expectEq "key type" key.typeName "EC"
      let signature ← Sign.sign (.ecdsa .sha256) key message
      expect "did not verify" (← Sign.verify (.ecdsa .sha256) key message signature)
      expect "verified under the wrong hash"
        !(← Sign.verify (.ecdsa .sha384) key message signature) },
  { name := "an ECDSA P-384 signature verifies, so keygen parameters reach the provider"
    run := do
      let key ← Evp.PKey.generate "EC" #[⟨"group", .utf8 "P-384"⟩]
      let signature ← Sign.sign (.ecdsa .sha384) key message
      expect "did not verify" (← Sign.verify (.ecdsa .sha384) key message signature) },
  { name := "an RSA-PSS signature verifies, and does not under PKCS#1 v1.5"
    run := do
      -- `bits` is a `size_t` on the provider side, so a key of the size asked
      -- for is also the check that `uint` narrows the way section 8 assumes.
      let key ← Evp.PKey.generate "RSA" #[⟨"bits", .uint 2048⟩]
      expectEq "key type" key.typeName "RSA"
      let signature ← Sign.sign (.rsaPss .sha256 .digest) key message
      expectEq "signature length" signature.size 256
      expect "did not verify" (← Sign.verify (.rsaPss .sha256 .digest) key message signature)
      expect "verified under the wrong padding"
        !(← Sign.verify (.rsaPkcs1 .sha256) key message signature) },
  { name := "an RSA PKCS#1 v1.5 signature verifies, and does not over another message"
    run := do
      let key ← Evp.PKey.generate "RSA" #[⟨"bits", .uint 2048⟩]
      let signature ← Sign.sign (.rsaPkcs1 .sha256) key message
      expect "did not verify" (← Sign.verify (.rsaPkcs1 .sha256) key message signature)
      expect "verified over another message"
        !(← Sign.verify (.rsaPkcs1 .sha256) key (message ++ "!".toUTF8) signature) },
  { name := "generating with an algorithm no provider offers is an error"
    run := expectThrows "generate NO-SUCH-ALGORITHM" (Evp.PKey.generate "NO-SUCH-ALGORITHM" #[]) },
  { name := "generating RSA with a rejected parameter is an error"
    run := expectThrows "generate RSA with 7 bits"
      (Evp.PKey.generate "RSA" #[⟨"bits", .uint 7⟩]) }]

/-- What the encoder writes has to be what the decoder reads, and a key that
survives the trip has to still be the same key, which only a signature made
before it and checked after it can show. -/
private def encoderCases : Array Case := #[
  { name := "a public key survives toSpki then fromSpki"
    run := do
      let key ← Evp.PKey.generate "EC" #[⟨"group", .utf8 "P-256"⟩]
      let signature ← Sign.sign (.ecdsa .sha256) key message
      let some decoded ← Evp.PKey.fromSpki (← key.toSpki)
        | throw <| IO.userError "the encoded SubjectPublicKeyInfo did not decode"
      expect "the re-decoded key did not verify"
        (← Sign.verify (.ecdsa .sha256) decoded message signature) },
  { name := "a private key survives toPkcs8 then fromPkcs8"
    run := do
      let key ← Evp.PKey.generate "ED25519" #[]
      let some decoded ← Evp.PKey.fromPkcs8 (← key.toPkcs8)
        | throw <| IO.userError "the encoded PrivateKeyInfo did not decode"
      expectEq "the re-decoded key signs differently"
        (Hex.toHex (← Sign.sign .ed25519 decoded message))
        (Hex.toHex (← Sign.sign .ed25519 key message)) },
  { name := "re-encoding a fixture reproduces the bytes it was decoded from"
    run := do
      let some key ← Evp.PKey.fromSpki (← Hex.ofHexOrThrow Fixtures.Signature.rsaSpkiDer)
        | throw <| IO.userError "fixture SubjectPublicKeyInfo did not decode"
      expectEq "re-encoded" (Hex.toHex (← key.toSpki)) Fixtures.Signature.rsaSpkiDer },
  { name := "toSpki of a private key writes only the public half"
    run := do
      let key ← Evp.PKey.generate "ED25519" #[]
      let some decoded ← Evp.PKey.fromSpki (← key.toSpki)
        | throw <| IO.userError "the encoded SubjectPublicKeyInfo did not decode"
      expectThrows "signing with a public-only key" (Sign.sign .ed25519 decoded message) },
  { name := "encoding to a structure the key has no encoder for is an error"
    run := do
      let key ← Evp.PKey.generate "ED25519" #[]
      expectThrows "encode to NoSuchStructure"
        (key.encode .publicKey "DER" "NoSuchStructure") },
  { name := "fromPkcs8 answers none for a SubjectPublicKeyInfo"
    run := do
      let key ← Evp.PKey.generate "ED25519" #[]
      expect "decoded a public key as PKCS#8" (← Evp.PKey.fromPkcs8 (← key.toSpki)).isNone }]

def cases : Array Case := ed25519ReproducesVectors ++ roundTripCases ++ encoderCases

end Tests.Signing
