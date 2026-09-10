/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Lake
open Lake DSL

package «lean-libcrypto» where
  version := v!"0.2.0"
  builtinLint := true
  leanOptions := #[⟨`linter.extra, true⟩, ⟨`warningAsError, true⟩]

def pkgConfigFlags (args : Array String) (lib : String) : IO (Array String) := do
  let out ← IO.Process.run { cmd := "pkg-config", args := args.push lib }
  return out.trimAscii.toString.splitOn " " |>.filter (· ≠ "") |>.toArray

/-- Compiled together into one `libcrypto_shim` shared library. -/
def shimSources : Array String :=
  #["core.c", "digest.c", "pkey.c", "cipher.c", "mac.c", "kdf.c", "provider.c"]

/-- Traced alongside the sources, so that editing one rebuilds the shim. -/
def shimHeaders : Array String := #["shim.h"]

target cryptoShimDynlib pkg : Dynlib := do
  let cDir := pkg.dir / "c"
  let srcJobs ← shimSources.mapM fun (name : String) => inputTextFile <| cDir / name
  let hdrJobs ← shimHeaders.mapM fun (name : String) => inputTextFile <| cDir / name
  let inputs := Job.collectArray (srcJobs ++ hdrJobs) "crypto_shim sources"
  inputs.mapM fun _ => do
    addPlatformTrace
    let cflags ← pkgConfigFlags #["--cflags"] "libcrypto"
    let libs ← pkgConfigFlags #["--libs"] "libcrypto"
    let cArgs := #["-fPIC", "-pthread", "-Wall", "-Wextra", "-I", (← getLeanIncludeDir).toString,
      "-I", cDir.toString] ++ cflags
    let libFile := pkg.sharedLibDir / (nameToSharedLib "crypto_shim")
    let art ← buildArtifactUnlessUpToDate libFile (ext := sharedLibExt) (restore := true) do
      let mut oFiles := #[]
      for name in shimSources do
        let oFile := pkg.buildDir / "c" / (name ++ ".o")
        compileO oFile (cDir / name) cArgs "cc"
        oFiles := oFiles.push oFile.toString
      let undefinedArgs := if System.Platform.isOSX then #["-undefined", "dynamic_lookup"] else #[]
      compileSharedLib libFile (oFiles ++ libs ++ #["-pthread"] ++ undefinedArgs) "cc"
    return { path := art.path, name := "crypto_shim" : Dynlib }

@[default_target]
lean_lib Libcrypto where
  precompileModules := true
  moreLinkLibs := #[cryptoShimDynlib]

@[test_driver]
script tests (args) do
  let lake ← IO.appPath
  let suite ← IO.Process.spawn {
    cmd := lake.toString
    args := #["test"] ++ args.toArray
    cwd := some "test"
    env := #[("LEAN_PATH", none), ("LEAN_SRC_PATH", none), ("LAKE", none), ("LAKE_HOME", none),
      ("LAKE_PKG_URL_MAP", none), ("ELAN_TOOLCHAIN", none)]
  }
  suite.wait
