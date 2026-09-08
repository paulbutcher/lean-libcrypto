/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto.Evp.Digest

namespace Libcrypto.Hash

/-- The SHA-2 family. Anything else the linked OpenSSL offers is reachable
through `Evp.Digest.fetch`, and `Evp.Digest.enumerate` says what that is. -/
inductive Algorithm where
  | sha224
  | sha256
  | sha384
  | sha512
  | sha512_224
  | sha512_256
  deriving DecidableEq, Repr, Inhabited

/-- The name OpenSSL 3 fetches by, which is not the name of the constructor:
SHA-224 is `"SHA2-224"`, not `"SHA224"`. -/
def Algorithm.name : Algorithm → String
  | .sha224 => "SHA2-224"
  | .sha256 => "SHA2-256"
  | .sha384 => "SHA2-384"
  | .sha512 => "SHA2-512"
  | .sha512_224 => "SHA2-512/224"
  | .sha512_256 => "SHA2-512/256"

/-- Fetches on every call. OpenSSL caches fetched algorithms internally, so hold
an `Evp.Digest` yourself only where profiling says to. -/
def hash (a : Algorithm) (data : ByteArray) : IO ByteArray := do
  Evp.Digest.digest (← Evp.Digest.fetch a.name) data #[]

end Libcrypto.Hash
