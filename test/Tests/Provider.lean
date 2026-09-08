/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto
import Tests.Harness
import Tests.Hex

namespace Tests.Provider

open Libcrypto

/-- Whirlpool is in the legacy provider and nowhere else, so it is what tells one
context from another. Which algorithms are legacy is a property of the linked
OpenSSL and has moved between releases: RIPEMD-160 was legacy once and is in the
default provider from 3.0.7 on. -/
private def legacyOnly : String := "WHIRLPOOL"

/-- The digest of the empty string published with the algorithm. -/
private def emptyWhirlpool : String :=
  "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7"
    ++ "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"

def cases : Array Case := #[
  { name := "the default context does not offer a legacy digest"
    run := do
      expect s!"{legacyOnly} was enumerated" !((← Evp.Digest.enumerate).contains legacyOnly)
      expectThrows s!"fetch of {legacyOnly}" (Evp.Digest.fetch legacyOnly) },
  { name := "loading legacy adds it to what enumerate reports"
    run := do
      let ctx ← Evp.LibCtx.withProviders #["default", "legacy"]
      let names ← Evp.Digest.enumerateIn (some ctx)
      expect s!"{legacyOnly} missing" (names.contains legacyOnly)
      expect "SHA2-256 missing" (names.contains "SHA2-256") },
  { name := "a digest fetched from the legacy provider computes"
    run := do
      let ctx ← Evp.LibCtx.withProviders #["default", "legacy"]
      let md ← Evp.Digest.fetchIn (some ctx) legacyOnly
      expectEq s!"{legacyOnly} of the empty string"
        (Hex.toHex (← Evp.Digest.digest md ByteArray.empty #[])) emptyWhirlpool },
  -- Freeing an `OSSL_LIB_CTX` tears down its providers whatever is still using
  -- them, so each of these would be a use after free if the fetched object did
  -- not hold its context open. OpenSSL 3.0 crashes on it; 3.5 survives.
  { name := "a digest outlives the context it was fetched from"
    run := do
      let md ← Evp.Digest.fetchIn (some (← Evp.LibCtx.withProviders #["default", "legacy"]))
        legacyOnly
      expectEq s!"{legacyOnly} of the empty string"
        (Hex.toHex (← Evp.Digest.digest md ByteArray.empty #[])) emptyWhirlpool },
  { name := "a digest context outlives the digest and the context behind it"
    run := do
      let dctx ← Evp.Digest.Ctx.new
      dctx.init (← Evp.Digest.fetchIn
        (some (← Evp.LibCtx.withProviders #["default", "legacy"])) legacyOnly) #[]
      dctx.update ByteArray.empty
      expectEq s!"{legacyOnly} of the empty string" (Hex.toHex (← dctx.final)) emptyWhirlpool },
  { name := "a MAC context outlives the MAC and the context behind it"
    run := do
      let mctx ← Evp.Mac.Ctx.new
        (← Evp.Mac.fetchIn (some (← Evp.LibCtx.withProviders #["default"])) "HMAC")
      mctx.init "a key".toUTF8 #[⟨"digest", .utf8 "SHA2-256"⟩]
      mctx.update "a message".toUTF8
      expectEq "tag length" (← mctx.final).size 32 },
  { name := "a context with only default still refuses a legacy digest"
    run := do
      let ctx ← Evp.LibCtx.withProviders #["default"]
      expectThrows s!"fetch of {legacyOnly}" (Evp.Digest.fetchIn (some ctx) legacyOnly) },
  { name := "a context with nothing loaded falls back to the default provider"
    run := do
      let names ← Evp.Digest.enumerateIn (some (← Evp.LibCtx.new))
      expect "SHA2-256 missing" (names.contains "SHA2-256")
      expect s!"{legacyOnly} was enumerated" !(names.contains legacyOnly) },
  { name := "loading only legacy ends that fallback"
    run := do
      let names ← Evp.Digest.enumerateIn (some (← Evp.LibCtx.withProviders #["legacy"]))
      expect s!"{legacyOnly} missing" (names.contains legacyOnly)
      expect "SHA2-256 was still offered" !(names.contains "SHA2-256") },
  { name := "loading a provider that does not exist is an error"
    run := do
      let ctx ← Evp.LibCtx.new
      expectThrows "load of no-such-provider" (Evp.LibCtx.load (some ctx) "no-such-provider") },
  { name := "a cipher is reachable through a context of its own too"
    run := do
      let ctx ← Evp.LibCtx.withProviders #["default"]
      expectEq "name" (← Evp.Cipher.fetchIn (some ctx) "AES-256-GCM").name "AES-256-GCM" }]

end Tests.Provider
