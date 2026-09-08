/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Lake
open Lake DSL

package test where
  builtinLint := true
  leanOptions := #[⟨`linter.extra, true⟩, ⟨`warningAsError, true⟩]

require «lean-libcrypto» from ".."

@[default_target]
lean_lib Tests where
  globs := #[.submodules `Tests]

@[default_target, test_driver]
lean_exe tests where
  root := `Main
