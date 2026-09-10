/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

import Tests.Harness

public section

namespace Tests.Memory

/-- Resident size in bytes. Only Linux is covered; elsewhere there is nothing
portable to read, and the caller skips rather than guessing. -/
def residentBytes : IO (Option Nat) := do
  let statm : System.FilePath := "/proc/self/statm"
  if !(← statm.pathExists) then return none
  let some pages := ((← IO.FS.readFile statm).splitOn " ")[1]?.bind (·.trimAscii.toString.toNat?)
    | return none
  let pageSize ← IO.Process.run { cmd := "getconf", args := #["PAGESIZE"] }
  return (pageSize.trimAscii.toString.toNat?).map (pages * ·)

/-- Runs `round` once to pay for any one-off growth in the allocators, then again
with the resident size measured either side. A finalizer that never runs shows up
as growth far larger than `allowance`; ordinary allocator behaviour does not show
up at all, since what the first round used is reused by the second. -/
def expectNoGrowth (allowance : Nat) (round : IO Unit) : IO Unit := do
  round
  match ← residentBytes with
  | none => IO.println "     (skipped: resident size is unavailable here)"
  | some before =>
    round
    let some after ← residentBytes
      | throw <| IO.userError "resident size became unreadable mid-test"
    expect s!"resident size grew by {after - before} bytes, allowing {allowance}"
      (after ≤ before + allowance)

/-- Eight megabytes, which is wide enough that no allocator behaviour reaches it
and narrow enough that every leak the tests below provoke exceeds it. -/
def allowance : Nat := 8 * 1024 * 1024

end Tests.Memory
