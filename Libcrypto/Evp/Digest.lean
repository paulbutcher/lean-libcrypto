/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Libcrypto.Evp.Param
public import Libcrypto.Evp.Provider

public section

namespace Libcrypto.Evp

private opaque DigestImpl : NonemptyType

/-- A fetched `EVP_MD`. Reference counted by OpenSSL, so sharing one between
threads is safe. -/
def Digest : Type := DigestImpl.type

instance : Nonempty Digest := DigestImpl.property

namespace Digest

/-- Fails if no provider loaded into `ctx` offers `name`, which is an
environmental fact rather than an answer about the input. -/
@[extern "lc_md_fetch"]
opaque fetchIn (ctx : @& Option LibCtx) (name : @& String) : IO Digest

/-- `fetchIn` against the default library context. -/
def fetch (name : String) : IO Digest := fetchIn none name

/-- The length `final` will return. For an extendable-output function this is the
provider's default length rather than a limit. -/
@[extern "lc_md_size"]
opaque size (d : @& Digest) : Nat

/-- The provider's primary name, which need not be the one `fetch` was given:
fetching `"SHA256"` yields an algorithm named `"SHA2-256"`. -/
@[extern "lc_md_name"]
opaque name (d : @& Digest) : String

/-- Every digest the providers loaded into `ctx` offer, by primary name. What
this returns is a property of the linked OpenSSL and of which providers are
loaded, not of this library. -/
@[extern "lc_md_enumerate"]
opaque enumerateIn (ctx : @& Option LibCtx) : IO (Array String)

/-- `enumerateIn` against the default library context. -/
def enumerate : IO (Array String) := enumerateIn none

private opaque CtxImpl : NonemptyType

/-- An `EVP_MD_CTX`. Not reentrant: use one from a single thread at a time. -/
def Ctx : Type := CtxImpl.type

instance : Nonempty Ctx := CtxImpl.property

@[extern "lc_md_ctx_new"]
opaque Ctx.new : IO Ctx

/-- `EVP_DigestInit_ex2`. Also resets a context that has already been used. -/
@[extern "lc_md_ctx_init"]
opaque Ctx.init (ctx : @& Ctx) (d : @& Digest) (params : @& Array Param) : IO Unit

@[extern "lc_md_ctx_update"]
opaque Ctx.update (ctx : @& Ctx) (data : @& ByteArray) : IO Unit

/-- `EVP_DigestFinal_ex`, which leaves the context needing another `init` before
it can be used again. -/
@[extern "lc_md_ctx_final"]
opaque Ctx.final (ctx : @& Ctx) : IO ByteArray

/-- Init, update and final in one shim call, so no context escapes into Lean. -/
@[extern "lc_md_digest"]
opaque digest (d : @& Digest) (data : @& ByteArray) (params : @& Array Param) : IO ByteArray

end Digest

end Libcrypto.Evp
