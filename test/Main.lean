/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Tests.Aead
import Tests.ConstantTime
import Tests.Digest
import Tests.Hex
import Tests.Lifetime
import Tests.Mac
import Tests.Param
import Tests.Provider
import Tests.Sign
import Tests.Signing

public def main : IO UInt32 := do
  let failed ← Tests.runCases <|
    Tests.Hex.cases ++ Tests.Param.cases ++ Tests.ConstantTime.cases ++ Tests.Mac.cases
      ++ Tests.Aead.cases
      ++ Tests.Digest.cases ++ Tests.Sign.cases ++ Tests.Signing.cases ++ Tests.Provider.cases
      ++ Tests.Lifetime.cases
  if failed == 0 then
    IO.println "all tests passed"
    return 0
  else
    IO.eprintln s!"{failed} test(s) failed"
    return 1
