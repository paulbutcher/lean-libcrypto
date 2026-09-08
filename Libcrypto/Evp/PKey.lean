/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto.Evp.Param

namespace Libcrypto.Evp

private opaque PKeyImpl : NonemptyType

/-- An `EVP_PKEY`, holding a public key, a private key, or both. Immutable once
built here, so sharing one between threads is safe; the contexts the operations
below build from it are not shared, being created and dropped inside one call. -/
def PKey : Type := PKeyImpl.type

instance : Nonempty PKey := PKeyImpl.property

namespace PKey

/-- Which components of a key an encode or a decode is about. `privateKey` and
`keyPair` both carry the private half; they differ in whether the public half
has to be present too. -/
inductive Selection where
  | publicKey
  | privateKey
  | keyPair
  | parameters
  deriving DecidableEq, Repr, Inhabited

/-- `OSSL_DECODER`. `format` is an input type such as `"DER"` or `"PEM"` and
`structureName` an input structure such as `"SubjectPublicKeyInfo"`.

`none` means the bytes are not what they were said to be, which is an answer
about the input; a build with no provider for the key type throws instead, and a
caller must be able to tell those apart. -/
@[extern "lc_pkey_decode"]
opaque decode (der : @& ByteArray) (selection : Selection) (format structureName : @& String) :
    IO (Option PKey)

/-- `OSSL_ENCODER`, the inverse of `decode` and taking the same names. -/
@[extern "lc_pkey_encode"]
opaque encode (key : @& PKey) (selection : Selection) (format structureName : @& String) :
    IO ByteArray

/-- Decodes a DER `SubjectPublicKeyInfo`, the encoding a public key is normally
published in. -/
def fromSpki (der : ByteArray) : IO (Option PKey) :=
  decode der .publicKey "DER" "SubjectPublicKeyInfo"

/-- Decodes a DER PKCS#8 `PrivateKeyInfo`, which is unencrypted; an
`EncryptedPrivateKeyInfo` needs a passphrase and does not decode here. -/
def fromPkcs8 (der : ByteArray) : IO (Option PKey) :=
  decode der .privateKey "DER" "PrivateKeyInfo"

/-- Writes the public half as a DER `SubjectPublicKeyInfo`, discarding the
private half if the key has one. -/
def toSpki (key : PKey) : IO ByteArray :=
  key.encode .publicKey "DER" "SubjectPublicKeyInfo"

/-- Writes the private half as a DER PKCS#8 `PrivateKeyInfo`, unencrypted. -/
def toPkcs8 (key : PKey) : IO ByteArray :=
  key.encode .privateKey "DER" "PrivateKeyInfo"

/-- Builds a key from the bare public value, for algorithms that have one, such
as `"ED25519"`. Answers `none` if the length is wrong for the algorithm. -/
@[extern "lc_pkey_from_raw_public_key"]
opaque fromRawPublicKey (algorithm : @& String) (key : @& ByteArray) : IO (Option PKey)

/-- Builds a key from the bare private value. Answers `none` if the length is
wrong for the algorithm. -/
@[extern "lc_pkey_from_raw_private_key"]
opaque fromRawPrivateKey (algorithm : @& String) (key : @& ByteArray) : IO (Option PKey)

/-- What the key turned out to be, such as `"RSA"` or `"EC"`. After a `decode`
this is the only way to learn which algorithm the bytes carried. -/
@[extern "lc_pkey_type_name"]
opaque typeName (key : @& PKey) : String

/-- `EVP_PKEY_generate`. What `params` must carry depends on the algorithm:
`"bits"` for RSA, `"group"` for EC, nothing at all for Ed25519. -/
@[extern "lc_pkey_generate"]
opaque generate (algorithm : @& String) (params : @& Array Param) : IO PKey

/-- `EVP_DigestSign`. `digest` is `none` for pure EdDSA, which signs the message
rather than a digest of it; `params` carry padding and PSS settings.

Signing has no negative answer: either it produces a signature or something
prevented it, so everything that goes wrong here throws. -/
@[extern "lc_pkey_sign"]
opaque sign (key : @& PKey) (digest : @& Option String) (message : @& ByteArray)
    (params : @& Array Param) : IO ByteArray

/-- `EVP_DigestVerify`, taking the same `digest` and `params` as `sign`.

`false` means the signature does not verify, which is an answer. Anything that
prevents an answer being reached, an unavailable digest for instance, throws. -/
@[extern "lc_pkey_verify"]
opaque verify (key : @& PKey) (digest : @& Option String) (message signature : @& ByteArray)
    (params : @& Array Param) : IO Bool

end PKey

end Libcrypto.Evp
