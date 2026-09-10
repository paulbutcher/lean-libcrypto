/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Libcrypto
public import Tests.Harness
import Tests.Memory

public section

namespace Tests.Lifetime

open Libcrypto

def cases : Array Case := #[
  { name := "dropped digest contexts do not accumulate"
    run :=
      -- Two million contexts leak well over a hundred megabytes if
      -- `EVP_MD_CTX_free` is never reached.
      Memory.expectNoGrowth Memory.allowance <|
        for _ in [0:2000000] do
          let _ ← Evp.Digest.Ctx.new },
  { name := "dropped library contexts do not accumulate"
    run :=
      -- A library context holds its providers, and OpenSSL does not unload them
      -- when the context is freed, so a round here costs tens of kilobytes.
      Memory.expectNoGrowth Memory.allowance <|
        for _ in [0:1000] do
          let _ ← Evp.LibCtx.withProviders #["default", "legacy"] },
  { name := "a context is still freed once what was fetched from it goes"
    run :=
      -- The digest holds the context open, so this leaks a context a round if
      -- the reference it takes is never given back.
      Memory.expectNoGrowth Memory.allowance <|
        for _ in [0:1000] do
          let _ ← Evp.Digest.fetchIn
            (some (← Evp.LibCtx.withProviders #["default", "legacy"])) "SHA2-256" },
  { name := "dropped keys do not accumulate"
    run := do
      let der ← (← Evp.PKey.generate "ED25519" #[]).toPkcs8
      Memory.expectNoGrowth Memory.allowance <|
        for _ in [0:200000] do
          let _ ← Evp.PKey.fromPkcs8 der },
  { name := "dropped cipher contexts do not accumulate"
    run :=
      Memory.expectNoGrowth Memory.allowance <|
        for _ in [0:2000000] do
          let _ ← Evp.Cipher.Ctx.new }]

end Tests.Lifetime
