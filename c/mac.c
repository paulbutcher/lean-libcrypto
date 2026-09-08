/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#include "shim.h"

static EVP_MAC *lc_mac(b_lean_obj_arg mac) {
  return (EVP_MAC *)lean_get_external_data(mac);
}

static EVP_MAC_CTX *lc_mac_ctx(b_lean_obj_arg ctx) {
  return (EVP_MAC_CTX *)lean_get_external_data(ctx);
}

LEAN_EXPORT lean_obj_res lc_mac_fetch(b_lean_obj_arg libctx, b_lean_obj_arg name,
                                      lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_MAC *mac = EVP_MAC_fetch(lc_libctx_of(libctx), lean_string_cstr(name), NULL);
  if (mac == NULL) return lc_io_error("EVP_MAC_fetch");
  return lean_io_result_mk_ok(lean_alloc_external(lc_mac_class, mac));
}

LEAN_EXPORT lean_obj_res lc_mac_name(b_lean_obj_arg mac) {
  const char *name = EVP_MAC_get0_name(lc_mac(mac));
  return lean_mk_string(name == NULL ? "" : name);
}

LEAN_EXPORT lean_obj_res lc_mac_ctx_new(b_lean_obj_arg mac, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(lc_mac(mac));
  if (ctx == NULL) return lc_io_error("EVP_MAC_CTX_new");
  return lean_io_result_mk_ok(lean_alloc_external(lc_mac_ctx_class, ctx));
}

LEAN_EXPORT lean_obj_res lc_mac_ctx_init(b_lean_obj_arg ctx, b_lean_obj_arg key,
                                         b_lean_obj_arg params, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  int ok = EVP_MAC_init(lc_mac_ctx(ctx), lean_sarray_cptr(key), lean_sarray_size(key),
                        built.params);
  lc_params_release(&built);
  if (!ok) return lc_io_error("EVP_MAC_init");
  return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lc_mac_ctx_update(b_lean_obj_arg ctx, b_lean_obj_arg data,
                                           lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  if (!EVP_MAC_update(lc_mac_ctx(ctx), lean_sarray_cptr(data), lean_sarray_size(data)))
    return lc_io_error("EVP_MAC_update");
  return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lc_mac_ctx_final(b_lean_obj_arg ctx, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  size_t size = 0;
  if (!EVP_MAC_final(lc_mac_ctx(ctx), NULL, &size, 0))
    return lc_io_error("EVP_MAC_final sizing the output");
  lean_obj_res out = lean_alloc_sarray(1, size, size);
  if (!EVP_MAC_final(lc_mac_ctx(ctx), lean_sarray_cptr(out), &size, size)) {
    lean_dec_ref(out);
    return lc_io_error("EVP_MAC_final");
  }
  lean_sarray_set_size(out, size);
  return lean_io_result_mk_ok(out);
}
