/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Libcrypto.Evp.Param
public import Libcrypto.Evp.Provider

public section

namespace Libcrypto.Evp

private opaque KdfImpl : NonemptyType

/-- A fetched `EVP_KDF`, such as `"PBKDF2"` or `"HKDF"`. Reference counted by
OpenSSL, so sharing one between threads is safe. -/
def Kdf : Type := KdfImpl.type

instance : Nonempty Kdf := KdfImpl.property

namespace Kdf

@[extern "lc_kdf_fetch"]
opaque fetchIn (ctx : @& Option LibCtx) (name : @& String) : IO Kdf

/-- `fetchIn` against the default library context. -/
def fetch (name : String) : IO Kdf := fetchIn none name

@[extern "lc_kdf_name"]
opaque name (k : @& Kdf) : String

/-- Derives `length` bytes. Every input the KDF needs, the password, the salt,
the digest and the iteration count among them, arrives in `params`; a KDF that
will not produce a key of the length asked for is an error, not an answer. -/
@[extern "lc_kdf_derive"]
opaque derive (k : @& Kdf) (length : Nat) (params : @& Array Param) : IO ByteArray

end Kdf

end Libcrypto.Evp
