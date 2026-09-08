/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#include <stdlib.h>

#include "shim.h"

LEAN_EXPORT lean_obj_res lc_libctx_new(lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_libctx *held = calloc(1, sizeof(lc_libctx));
  if (held == NULL) return lc_io_error("allocating the library context handle");
  held->refs = 1;
  held->ctx = OSSL_LIB_CTX_new();
  if (held->ctx == NULL) {
    free(held);
    return lc_io_error("OSSL_LIB_CTX_new");
  }
  lean_object *wrapped = lc_alloc_external(&lc_libctx_class, held);
  if (wrapped == NULL) {
    lc_libctx_release(held);
    return lc_io_error("registering the external classes");
  }
  return lean_io_result_mk_ok(wrapped);
}

LEAN_EXPORT lean_obj_res lc_provider_load(b_lean_obj_arg libctx, b_lean_obj_arg name,
                                          lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_libctx *held = lc_libctx_opt(libctx);
  OSSL_PROVIDER *provider =
      OSSL_PROVIDER_load(held == NULL ? NULL : held->ctx, lean_string_cstr(name));
  if (provider == NULL) return lc_io_error("OSSL_PROVIDER_load");
  /* Nothing owns the default context, so a provider loaded there stays for the
     life of the process. One loaded into a context of our own is recorded so
     that it can be unloaded before the context is freed; freeing the context
     alone does not unload it. */
  if (held == NULL) return lean_io_result_mk_ok(lean_box(0));
  if (held->count == held->capacity) {
    size_t capacity = held->capacity == 0 ? 4 : held->capacity * 2;
    OSSL_PROVIDER **grown = realloc(held->providers, capacity * sizeof(OSSL_PROVIDER *));
    if (grown == NULL) {
      OSSL_PROVIDER_unload(provider);
      return lc_io_error("recording the loaded provider");
    }
    held->providers = grown;
    held->capacity = capacity;
  }
  held->providers[held->count++] = provider;
  return lean_io_result_mk_ok(lean_box(0));
}
