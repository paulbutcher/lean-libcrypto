/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto.ConstantTime
import Libcrypto.Evp.Mac
import Libcrypto.Hash

namespace Libcrypto.Hmac

/-- HMAC over the SHA-2 family. Any other digest the linked OpenSSL offers is
reachable by fetching `"HMAC"` through `Evp.Mac` and naming the digest there. -/
def compute (a : Hash.Algorithm) (key data : ByteArray) : IO ByteArray := do
  let mac ← Evp.Mac.fetch "HMAC"
  mac.compute key data #[⟨"digest", .utf8 a.name⟩]

/-- Compares in constant time, which is the reason to use this rather than
recomputing and comparing with `==`: a comparison that stops at the first
differing byte tells an attacker how much of a forged tag was right. -/
def verify (a : Hash.Algorithm) (key data tag : ByteArray) : IO Bool := do
  return constantTimeEq (← compute a key data) tag

end Libcrypto.Hmac
