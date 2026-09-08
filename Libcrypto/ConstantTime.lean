/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/

namespace Libcrypto

/-- `CRYPTO_memcmp`, so the time taken does not depend on where the two first
differ. Arrays of different lengths are unequal, and that is decided on the
lengths alone; only the contents are compared in constant time. -/
@[extern "lc_constant_time_eq"]
opaque constantTimeEq (a b : @& ByteArray) : Bool

end Libcrypto
