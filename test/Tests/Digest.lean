/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Libcrypto
public import Tests.Harness
import Tests.Hex

public section

namespace Tests.Digest

open Libcrypto

private def bytes (s : String) : ByteArray := s.toUTF8

/-- Decodes a hex fixture, failing the case rather than defaulting if it is
malformed, since a silently empty expectation would match nothing useful. -/
private def fixture (hex : String) : IO ByteArray :=
  match Hex.ofHex hex with
  | some bs => pure bs
  | none => throw <| IO.userError s!"malformed hex fixture: {hex}"

private def expectDigest (a : Hash.Algorithm) (input expected : String) : IO Unit := do
  let actual ← Hash.hash a (bytes input)
  expectEq s!"{a.name} of {repr input}" (Hex.toHex actual) (Hex.toHex (← fixture expected))

/-- FIPS 180-4 appendix examples, one per member of the family, so that a wrong
name in `Algorithm.name` shows up as a wrong digest rather than passing quietly. -/
private def fips1804 : Array Case := #[
  { name := "SHA2-256 of the empty string"
    run := expectDigest .sha256 ""
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { name := "SHA2-256 of \"abc\""
    run := expectDigest .sha256 "abc"
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
  { name := "SHA2-224 of \"abc\""
    run := expectDigest .sha224 "abc"
      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
  { name := "SHA2-384 of \"abc\""
    run := expectDigest .sha384 "abc"
      ("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        ++ "8086072ba1e7cc2358baeca134c825a7") },
  { name := "SHA2-512 of \"abc\""
    run := expectDigest .sha512 "abc"
      ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        ++ "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f") },
  { name := "SHA2-512/224 of \"abc\""
    run := expectDigest .sha512_224 "abc"
      "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa" },
  { name := "SHA2-512/256 of \"abc\""
    run := expectDigest .sha512_256 "abc"
      "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23" }]

/-- The one-shot runs entirely inside the shim, so agreeing with a two-part
stream at every split point is a claim about this binding, not about SHA-256. -/
private def streamingAgreesWithOneShot : IO Unit := do
  let md ← Evp.Digest.fetch "SHA2-256"
  let message := ByteArray.mk <| Array.range 200 |>.map (fun i => UInt8.ofNat (i * 7 % 251))
  let oneShot ← Evp.Digest.digest md message #[]
  let ctx ← Evp.Digest.Ctx.new
  for split in [0:message.size + 1] do
    ctx.init md #[]
    ctx.update (message.extract 0 split)
    ctx.update (message.extract split message.size)
    let streamed ← ctx.final
    expect s!"split at {split} disagrees with the one-shot" (constantTimeEq streamed oneShot)

private def digestCases : Array Case := #[
  { name := "a stream split at every offset matches the one-shot"
    run := streamingAgreesWithOneShot },
  { name := "enumerate reports SHA2-256"
    run := do expect "SHA2-256 missing" ((← Evp.Digest.enumerate).contains "SHA2-256") },
  { name := "fetch accepts an alias and reports the primary name"
    run := do expectEq "primary name" (← Evp.Digest.fetch "SHA256").name "SHA2-256" },
  { name := "the digest length matches the algorithm"
    run := do
      let md ← Evp.Digest.fetch "SHA2-512"
      expectEq "length" (← Evp.Digest.digest md (bytes "abc") #[]).size md.size },
  { name := "fetching an algorithm no provider offers is an error"
    run := expectThrows "fetch of NO-SUCH-DIGEST" (Evp.Digest.fetch "NO-SUCH-DIGEST") },
  -- OpenSSL 3.0 calls through a null function pointer for an update on a context
  -- with no digest set, so this is a check that the shim refuses first.
  { name := "a context rejects an update before init"
    run := do expectThrows "update before init" ((← Evp.Digest.Ctx.new).update (bytes "abc")) },
  { name := "a context rejects an empty update before init"
    run := do
      expectThrows "empty update before init" ((← Evp.Digest.Ctx.new).update ByteArray.empty) },
  { name := "a context rejects a final before init"
    run := do expectThrows "final before init" (← Evp.Digest.Ctx.new).final }]

def cases : Array Case := fips1804 ++ digestCases

end Tests.Digest
