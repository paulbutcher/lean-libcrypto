/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto
import Tests.Harness

namespace Tests.ConstantTime

open Libcrypto

private def tag : ByteArray := ByteArray.mk #[0x9f, 0x00, 0x11, 0xa3]

def cases : Array Case := #[
  { name := "equal contents compare equal"
    run := expect "equal" (constantTimeEq tag (ByteArray.mk #[0x9f, 0x00, 0x11, 0xa3])) },
  { name := "a difference in the last byte compares unequal"
    run := expect "unequal" !(constantTimeEq tag (ByteArray.mk #[0x9f, 0x00, 0x11, 0xa4])) },
  { name := "a prefix does not compare equal to the whole"
    run := expect "unequal" !(constantTimeEq tag (tag.extract 0 3)) },
  { name := "two empty arrays compare equal"
    run := expect "equal" (constantTimeEq ByteArray.empty ByteArray.empty) },
  { name := "the empty array does not compare equal to a tag"
    run := expect "unequal" !(constantTimeEq ByteArray.empty tag) }]

end Tests.ConstantTime
