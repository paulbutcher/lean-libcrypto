/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#include <lean/lean.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

LEAN_EXPORT uint8_t lc_constant_time_eq(b_lean_obj_arg a, b_lean_obj_arg b) {
  size_t na = lean_sarray_size(a);
  if (na != lean_sarray_size(b)) return 0;
  return CRYPTO_memcmp(lean_sarray_cptr(a), lean_sarray_cptr(b), na) == 0 ? 1 : 0;
}

LEAN_EXPORT lean_obj_res lc_initialize(lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  return lean_io_result_mk_ok(lean_box(0));
}
