/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#include "shim.h"

LEAN_EXPORT lean_obj_res lc_kdf_fetch(b_lean_obj_arg libctx, b_lean_obj_arg name,
                                      lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_KDF *kdf = EVP_KDF_fetch(lc_libctx_of(libctx), lean_string_cstr(name), NULL);
  if (kdf == NULL) return lc_io_error("EVP_KDF_fetch");
  return lean_io_result_mk_ok(lean_alloc_external(lc_kdf_class, kdf));
}

LEAN_EXPORT lean_obj_res lc_kdf_name(b_lean_obj_arg kdf) {
  const char *name = EVP_KDF_get0_name((EVP_KDF *)lean_get_external_data(kdf));
  return lean_mk_string(name == NULL ? "" : name);
}

LEAN_EXPORT lean_obj_res lc_kdf_derive(b_lean_obj_arg kdf, b_lean_obj_arg length,
                                       b_lean_obj_arg params, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  size_t size = (size_t)lean_uint64_of_nat(length);
  EVP_KDF_CTX *ctx = EVP_KDF_CTX_new((EVP_KDF *)lean_get_external_data(kdf));
  lean_obj_res out = lean_alloc_sarray(1, size, size == 0 ? 1 : size);
  const char *failed = NULL;
  if (ctx == NULL)
    failed = "EVP_KDF_CTX_new";
  else if (EVP_KDF_derive(ctx, lean_sarray_cptr(out), size, built.params) <= 0)
    failed = "EVP_KDF_derive";
  EVP_KDF_CTX_free(ctx);
  lc_params_release(&built);
  if (failed != NULL) {
    lean_dec_ref(out);
    return lc_io_error(failed);
  }
  return lean_io_result_mk_ok(out);
}
