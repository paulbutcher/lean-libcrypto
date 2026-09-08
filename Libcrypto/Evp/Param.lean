/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/

namespace Libcrypto.Evp

/-- The value side of an `OSSL_PARAM`. Integers are handed to OpenSSL at 64 bits
and narrowed by its own width conversion, so a parameter the provider declares as
`size_t` or `unsigned int` takes a `uint` here. -/
inductive ParamValue where
  | int (v : Int)
  | uint (v : Nat)
  | utf8 (v : String)
  | octets (v : ByteArray)
  deriving Inhabited

/-- One entry of the `OSSL_PARAM` array a fetch or an init is parameterised by. -/
structure Param where
  key : String
  value : ParamValue
  deriving Inhabited

/-- The `data_type` the shim tags each constructor with, from `openssl/core.h`.
Stated in Lean so it can be reasoned about; `Param.shimDataType` reports what the
shim really builds, which is what makes this worth stating separately. -/
def ParamValue.dataType : ParamValue → UInt32
  | .int _ => 1
  | .uint _ => 2
  | .utf8 _ => 4
  | .octets _ => 5

/-- The `data_type` of the `OSSL_PARAM` the shim constructs for this parameter. -/
@[extern "lc_param_data_type"]
opaque Param.shimDataType (p : @& Param) : UInt32

end Libcrypto.Evp
