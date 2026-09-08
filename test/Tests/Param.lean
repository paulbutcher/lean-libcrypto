/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto
import Tests.Harness

namespace Tests.Param

open Libcrypto.Evp

/-- Which constructor a value was built with, so that the theorem below can say
the data type determines it without reaching for a generated ordinal. -/
private def kind : ParamValue → Nat
  | .int _ => 0
  | .uint _ => 1
  | .utf8 _ => 2
  | .octets _ => 3

/-- No two kinds of `ParamValue` are handed to OpenSSL under the same
`data_type`. That is what makes the tag a faithful description of the union
member the shim points at: were two kinds to share a tag, a provider reading one
back would interpret the other's bytes, and the mistake would surface as
plausible wrong output rather than as an error.

`ParamValue.dataType` is the tag the shim writes, and `kind` is the constructor
the value came from, numbered arbitrarily but distinctly. The `iff` reads in both
directions at once: left to right, equal tags force the same constructor, which
is injectivity; right to left, the same constructor forces equal tags, which
rules out a tag that varies with the payload. Quantifying over two arbitrary
values covers all sixteen ordered pairs of constructors, so no case is assumed
away. -/
theorem dataType_eq_iff_kind_eq (v w : ParamValue) :
    v.dataType = w.dataType ↔ kind v = kind w := by
  cases v <;> cases w <;> simp [ParamValue.dataType, kind]

private def samples : Array (String × ParamValue) := #[
  ("int", .int (-7)),
  ("uint", .uint 4096),
  ("utf8", .utf8 "pkcs1"),
  ("octets", .octets (ByteArray.mk #[1, 2, 3]))]

/-- The theorem above constrains the Lean mapping to itself; only OpenSSL can say
whether those numbers are the constants it defines, so ask the shim. -/
private def shimAgreesWithLean : IO Unit := do
  for (name, value) in samples do
    let param : Libcrypto.Evp.Param := { key := "test", value }
    expectEq s!"{name} data type" param.shimDataType value.dataType

def cases : Array Case := #[
  { name := "the shim tags each ParamValue as ParamValue.dataType says"
    run := shimAgreesWithLean }]

end Tests.Param
