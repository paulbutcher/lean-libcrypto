/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#include <string.h>

#include "shim.h"

LEAN_EXPORT lean_obj_res lc_md_fetch(b_lean_obj_arg libctx, b_lean_obj_arg name,
                                     lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_MD *md = EVP_MD_fetch(lc_libctx_of(libctx), lean_string_cstr(name), NULL);
  if (md == NULL) return lc_io_error("EVP_MD_fetch");
  return lean_io_result_mk_ok(lean_alloc_external(lc_md_class, md));
}

LEAN_EXPORT lean_obj_res lc_md_size(b_lean_obj_arg md) {
  int size = EVP_MD_get_size((const EVP_MD *)lean_get_external_data(md));
  return lean_box(size < 0 ? 0 : (size_t)size);
}

LEAN_EXPORT lean_obj_res lc_md_name(b_lean_obj_arg md) {
  const char *name = EVP_MD_get0_name((const EVP_MD *)lean_get_external_data(md));
  return lean_mk_string(name == NULL ? "" : name);
}

static void lc_md_collect(EVP_MD *md, void *acc) {
  const char *name = EVP_MD_get0_name(md);
  if (name == NULL) return;
  lean_object **names = (lean_object **)acc;
  *names = lean_array_push(*names, lean_mk_string(name));
}

LEAN_EXPORT lean_obj_res lc_md_enumerate(b_lean_obj_arg libctx, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lean_object *names = lean_mk_empty_array();
  EVP_MD_do_all_provided(lc_libctx_of(libctx), lc_md_collect, &names);
  return lean_io_result_mk_ok(names);
}

LEAN_EXPORT lean_obj_res lc_md_ctx_new(lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL) return lc_io_error("EVP_MD_CTX_new");
  return lean_io_result_mk_ok(lean_alloc_external(lc_md_ctx_class, ctx));
}

LEAN_EXPORT lean_obj_res lc_md_ctx_init(b_lean_obj_arg ctx, b_lean_obj_arg md,
                                        b_lean_obj_arg params, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  int ok = EVP_DigestInit_ex2((EVP_MD_CTX *)lean_get_external_data(ctx),
                              (const EVP_MD *)lean_get_external_data(md), built.params);
  lc_params_release(&built);
  if (!ok) return lc_io_error("EVP_DigestInit_ex2");
  return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lc_md_ctx_update(b_lean_obj_arg ctx, b_lean_obj_arg data,
                                          lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  if (!EVP_DigestUpdate((EVP_MD_CTX *)lean_get_external_data(ctx), lean_sarray_cptr(data),
                        lean_sarray_size(data)))
    return lc_io_error("EVP_DigestUpdate");
  return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lc_md_ctx_final(b_lean_obj_arg ctx, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned int size = 0;
  if (!EVP_DigestFinal_ex((EVP_MD_CTX *)lean_get_external_data(ctx), out, &size))
    return lc_io_error("EVP_DigestFinal_ex");
  return lean_io_result_mk_ok(lc_byte_array(out, size));
}

LEAN_EXPORT lean_obj_res lc_md_digest(b_lean_obj_arg md, b_lean_obj_arg data,
                                      b_lean_obj_arg params, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned int size = 0;
  const char *failed = NULL;
  if (ctx == NULL)
    failed = "EVP_MD_CTX_new";
  else if (!EVP_DigestInit_ex2(ctx, (const EVP_MD *)lean_get_external_data(md), built.params))
    failed = "EVP_DigestInit_ex2";
  else if (!EVP_DigestUpdate(ctx, lean_sarray_cptr(data), lean_sarray_size(data)))
    failed = "EVP_DigestUpdate";
  else if (!EVP_DigestFinal_ex(ctx, out, &size))
    failed = "EVP_DigestFinal_ex";
  EVP_MD_CTX_free(ctx);
  lc_params_release(&built);
  if (failed != NULL) return lc_io_error(failed);
  return lean_io_result_mk_ok(lc_byte_array(out, size));
}
