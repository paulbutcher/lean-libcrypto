/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Libcrypto.Evp.Param
public import Libcrypto.Evp.Provider

public section

namespace Libcrypto.Evp

private opaque MacImpl : NonemptyType

/-- A fetched `EVP_MAC`, such as `"HMAC"` or `"POLY1305"`. Reference counted by
OpenSSL, so sharing one between threads is safe. -/
def Mac : Type := MacImpl.type

instance : Nonempty Mac := MacImpl.property

namespace Mac

@[extern "lc_mac_fetch"]
opaque fetchIn (ctx : @& Option LibCtx) (name : @& String) : IO Mac

/-- `fetchIn` against the default library context. -/
def fetch (name : String) : IO Mac := fetchIn none name

@[extern "lc_mac_name"]
opaque name (m : @& Mac) : String

private opaque CtxImpl : NonemptyType

/-- An `EVP_MAC_CTX`. Not reentrant: use one from a single thread at a time. -/
def Ctx : Type := CtxImpl.type

instance : Nonempty Ctx := CtxImpl.property

/-- Unlike a digest context, this one is bound to its algorithm when it is made. -/
@[extern "lc_mac_ctx_new"]
opaque Ctx.new (m : @& Mac) : IO Ctx

/-- Which parameters are required depends on the MAC: HMAC needs `"digest"`,
and nothing settles the key but this call. -/
@[extern "lc_mac_ctx_init"]
opaque Ctx.init (ctx : @& Ctx) (key : @& ByteArray) (params : @& Array Param) : IO Unit

@[extern "lc_mac_ctx_update"]
opaque Ctx.update (ctx : @& Ctx) (data : @& ByteArray) : IO Unit

@[extern "lc_mac_ctx_final"]
opaque Ctx.final (ctx : @& Ctx) : IO ByteArray

/-- A MAC over one buffer, which is what almost every caller wants. -/
def compute (m : Mac) (key data : ByteArray) (params : Array Param) : IO ByteArray := do
  let ctx ← Ctx.new m
  ctx.init key params
  ctx.update data
  ctx.final

end Mac

end Libcrypto.Evp
