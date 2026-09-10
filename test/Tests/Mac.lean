/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Libcrypto
import Tests.Fixtures.Mac
public import Tests.Harness
import Tests.Hex

public section

namespace Tests.Mac

open Libcrypto

private def hmacCases : Array Case :=
  Fixtures.Mac.rfc4231.map fun v =>
    { name := s!"RFC 4231 {v.label}"
      run := do
        let key ← Hex.ofHexOrThrow v.key
        let data ← Hex.ofHexOrThrow v.data
        for (algorithm, expected) in
            [(Hash.Algorithm.sha224, v.sha224), (.sha256, v.sha256),
             (.sha384, v.sha384), (.sha512, v.sha512)] do
          expectEq algorithm.name (Hex.toHex (← Hmac.compute algorithm key data)) expected }

private def hmacVerifyCases : Array Case := #[
  { name := "Hmac.verify accepts the tag Hmac.compute produced"
    run := do
      let key := "a key".toUTF8
      let data := "a message".toUTF8
      expect "rejected" (← Hmac.verify .sha256 key data (← Hmac.compute .sha256 key data)) },
  { name := "Hmac.verify rejects a tag from another message"
    run := do
      let key := "a key".toUTF8
      let elsewhere ← Hmac.compute .sha256 key "b".toUTF8
      expect "accepted" !(← Hmac.verify .sha256 key "a message".toUTF8 elsewhere) },
  { name := "Hmac.verify rejects a truncated tag"
    run := do
      let key := "a key".toUTF8
      let data := "a message".toUTF8
      let tag ← Hmac.compute .sha256 key data
      expect "accepted" !(← Hmac.verify .sha256 key data (tag.extract 0 16)) }]

/-- RFC 6070 is the check §8 asks for on integer width: `iter` is a `size_t` on
the provider side, and 4096 arriving as 0 or as a byte-swapped value would give a
different key rather than an error. -/
private def pbkdf2Cases : Array Case :=
  Fixtures.Mac.rfc6070.map fun v =>
    { name := s!"RFC 6070 PBKDF2 with {v.iterations} iterations, {v.length} bytes"
      run := do
        let kdf ← Evp.Kdf.fetch "PBKDF2"
        let derived ← kdf.derive v.length
          #[⟨"digest", .utf8 "SHA1"⟩,
            ⟨"pass", .octets v.password.toUTF8⟩,
            ⟨"salt", .octets v.salt.toUTF8⟩,
            ⟨"iter", .uint v.iterations⟩]
        expectEq "derived key" (Hex.toHex derived) v.expected }

private def evpCases : Array Case := #[
  { name := "an HMAC built through Evp.Mac in pieces matches the one-shot"
    run := do
      let mac ← Evp.Mac.fetch "HMAC"
      let key := "a key".toUTF8
      let params := #[(⟨"digest", .utf8 "SHA2-256"⟩ : Evp.Param)]
      let ctx ← Evp.Mac.Ctx.new mac
      ctx.init key params
      ctx.update "a ".toUTF8
      ctx.update "message".toUTF8
      expectEq "streamed" (Hex.toHex (← ctx.final))
        (Hex.toHex (← mac.compute key "a message".toUTF8 params)) },
  { name := "fetching a MAC no provider offers is an error"
    run := expectThrows "fetch NO-SUCH-MAC" (Evp.Mac.fetch "NO-SUCH-MAC") },
  { name := "initialising HMAC without naming a digest is an error"
    run := do
      let mac ← Evp.Mac.fetch "HMAC"
      expectThrows "init with no digest" (mac.compute "k".toUTF8 "m".toUTF8 #[]) },
  { name := "fetching a KDF no provider offers is an error"
    run := expectThrows "fetch NO-SUCH-KDF" (Evp.Kdf.fetch "NO-SUCH-KDF") },
  { name := "deriving with a parameter the KDF rejects is an error"
    run := do
      let kdf ← Evp.Kdf.fetch "PBKDF2"
      expectThrows "derive with no password"
        (kdf.derive 20 #[⟨"digest", .utf8 "NO-SUCH-DIGEST"⟩]) }]

def cases : Array Case := hmacCases ++ hmacVerifyCases ++ pbkdf2Cases ++ evpCases

end Tests.Mac
