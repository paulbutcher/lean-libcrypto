/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto.Evp.PKey
import Libcrypto.Hash

namespace Libcrypto.Sign

/-- How long the salt in an RSA-PSS signature is. Verification usually wants
`auto`, which reads the length out of the signature; a protocol that pins the
length, as JOSE does, wants `digest`. -/
inductive PssSaltLength where
  | digest
  | max
  | auto
  | bytes (n : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- A signature scheme together with everything needed to interpret a signature
under it. The hash is part of the scheme because the same key verifies different
signatures under different hashes. -/
inductive Algorithm where
  | rsaPkcs1 (hash : Hash.Algorithm)
  | rsaPss (hash : Hash.Algorithm) (saltLength : PssSaltLength)
  | ecdsa (hash : Hash.Algorithm)
  | ed25519
  deriving DecidableEq, Repr, Inhabited

/-- `none` for Ed25519, which signs the message itself. -/
def Algorithm.digest : Algorithm → Option String
  | .rsaPkcs1 h | .rsaPss h _ | .ecdsa h => some h.name
  | .ed25519 => none

def PssSaltLength.param : PssSaltLength → Evp.Param
  | .digest => ⟨"saltlen", .utf8 "digest"⟩
  | .max => ⟨"saltlen", .utf8 "max"⟩
  | .auto => ⟨"saltlen", .utf8 "auto"⟩
  | .bytes n => ⟨"saltlen", .uint n⟩

/-- MGF1 is given the same hash as the signature, which is what every protocol
this library is likely to meet specifies. To differ, go through `Evp.PKey`. -/
def Algorithm.params : Algorithm → Array Evp.Param
  | .rsaPkcs1 _ => #[⟨"pad-mode", .utf8 "pkcs1"⟩]
  | .rsaPss h salt =>
    #[⟨"pad-mode", .utf8 "pss"⟩, ⟨"mgf1-digest", .utf8 h.name⟩, salt.param]
  | .ecdsa _ | .ed25519 => #[]

/-- Signatures are in the encoding OpenSSL uses, so an ECDSA signature is a DER
`SEQUENCE` of two integers rather than a fixed-width `R‖S`. Converting between
the two is the caller's business. -/
def sign (a : Algorithm) (key : Evp.PKey) (message : ByteArray) : IO ByteArray :=
  key.sign a.digest message a.params

/-- `false` says the signature does not verify under this key and scheme, whether
because it was forged, altered, or made with different parameters. -/
def verify (a : Algorithm) (key : Evp.PKey) (message signature : ByteArray) : IO Bool :=
  key.verify a.digest message signature a.params

end Libcrypto.Sign
