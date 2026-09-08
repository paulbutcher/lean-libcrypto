/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/

namespace Tests

/-- A named check. Failure is signalled by throwing, so a check can be written as
straight-line `IO` rather than threading a result through. -/
structure Case where
  name : String
  run : IO Unit

/-- Fails the enclosing case unless `ok`. -/
def expect (what : String) (ok : Bool) : IO Unit :=
  unless ok do throw <| IO.userError what

/-- Fails the enclosing case unless the two agree, reporting both. -/
def expectEq [BEq α] [ToString α] (what : String) (actual expected : α) : IO Unit :=
  unless actual == expected do
    throw <| IO.userError s!"{what}: expected {expected}, got {actual}"

/-- Fails the enclosing case unless `act` throws, since an operation that must
reject bad input silently succeeding is the failure worth catching. -/
def expectThrows (what : String) (act : IO α) : IO Unit := do
  match ← act.toBaseIO with
  | .ok _ => throw <| IO.userError s!"{what}: expected an error, but it succeeded"
  | .error _ => pure ()

/-- Runs every case, reporting each, and returns the number that failed.

The name goes out and is flushed before the case runs, and the verdict follows on
the same line. A case that takes the whole process down with it, rather than
throwing, therefore still leaves its own name as the last thing in the log; a
buffered report would be lost with the process. -/
def runCases (cases : Array Case) : IO Nat := do
  let stdout ← IO.getStdout
  let mut failed := 0
  for case in cases do
    stdout.putStr s!"{case.name} ... "
    stdout.flush
    match ← case.run.toBaseIO with
    | .ok _ => stdout.putStrLn "ok"
    | .error e =>
      failed := failed + 1
      stdout.putStrLn s!"FAILED: {e}"
    stdout.flush
  return failed

end Tests
