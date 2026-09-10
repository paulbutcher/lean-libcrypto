/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public section

namespace Libcrypto.Evp

private opaque LibCtxImpl : NonemptyType

/-- An `OSSL_LIB_CTX`, the scope a set of providers is loaded into. Every `fetch`
in this library takes an `Option LibCtx`, and `none` means the default context,
which is the one an application that never mentions providers uses.

Whatever is fetched from a context holds it open, so there is no need to keep one
in hand to go on using what came out of it. -/
def LibCtx : Type := LibCtxImpl.type

instance : Nonempty LibCtx := LibCtxImpl.property

namespace LibCtx

/-- A context with nothing loaded into it, which falls back to the default
provider until something is. That fallback stops at the first explicit load, so
a context holding only `"legacy"` offers only what `"legacy"` has. -/
@[extern "lc_libctx_new"]
opaque new : IO LibCtx

/-- Loads a provider such as `"legacy"` or `"fips"`, where it stays for the life
of the context, since OpenSSL does not unload it when the context is freed.
Loading into the default context, `none`, lasts for the life of the process.

Like the other contexts here this is not reentrant: load from one thread at a
time, which for the usual case of loading once at startup is free. -/
@[extern "lc_provider_load"]
opaque load (ctx : @& Option LibCtx) (name : @& String) : IO Unit

/-- A fresh context with these providers loaded, which is how a non-default
provider is normally reached. Name `"default"` alongside it unless you mean to
exclude it, since loading anything ends the fallback described above. -/
def withProviders (names : Array String) : IO LibCtx := do
  let ctx ← new
  for name in names do load (some ctx) name
  return ctx

end LibCtx

end Libcrypto.Evp
