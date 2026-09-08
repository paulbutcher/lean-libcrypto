/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#ifndef LIBCRYPTO_SHIM_H
#define LIBCRYPTO_SHIM_H

#include <string.h>

#include <lean/lean.h>
#include <openssl/core.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

/* Registered once by `lc_initialize`; see `Libcrypto.Init`. */
extern lean_external_class *lc_md_class;
extern lean_external_class *lc_md_ctx_class;
extern lean_external_class *lc_pkey_class;
extern lean_external_class *lc_cipher_class;
extern lean_external_class *lc_cipher_ctx_class;
extern lean_external_class *lc_mac_class;
extern lean_external_class *lc_mac_ctx_class;
extern lean_external_class *lc_kdf_class;
extern lean_external_class *lc_libctx_class;

/* A library context together with what has been loaded into it. Freeing the
   context does not unload its providers, so they are kept here to be unloaded
   first. */
typedef struct {
  OSSL_LIB_CTX *ctx;
  OSSL_PROVIDER **providers;
  size_t count;
  size_t capacity;
} lc_libctx;

/* Both take an `Option LibCtx`, whose `none` is a scalar and means the default
   library context. */
static inline lc_libctx *lc_libctx_opt(b_lean_obj_arg option) {
  return lean_is_scalar(option)
             ? NULL
             : (lc_libctx *)lean_get_external_data(lean_ctor_get(option, 0));
}

static inline OSSL_LIB_CTX *lc_libctx_of(b_lean_obj_arg option) {
  lc_libctx *held = lc_libctx_opt(option);
  return held == NULL ? NULL : held->ctx;
}

/* Drains the OpenSSL error queue into an `IO.userError` prefixed with `context`.
   Callers must have run `ERR_clear_error()` on entry, so the queue holds only
   what this call produced. */
lean_obj_res lc_io_error(const char *context);

/* Scratch storage for the integers an `OSSL_PARAM` points at. It has to outlive
   the OpenSSL call, so it cannot be a temporary inside the conversion. */
typedef union {
  int64_t i;
  uint64_t u;
} lc_scratch;

typedef struct {
  OSSL_PARAM *params;
  lc_scratch *scratch;
} lc_params;

/* Converts a Lean `Array Param`. The octet strings and keys point into the
   borrowed Lean objects, so `arr` must outlive the OpenSSL call. Returns 0 only
   on allocation failure, having left `out` safe to pass to `lc_params_release`. */
int lc_params_build(b_lean_obj_arg arr, lc_params *out);
void lc_params_release(lc_params *out);

/* Fills one `OSSL_PARAM` from a Lean `Param`, pointing integers at `scratch`. */
void lc_param_fill(b_lean_obj_arg param, OSSL_PARAM *out, lc_scratch *scratch);

static inline lean_obj_res lc_byte_array(const uint8_t *data, size_t size) {
  lean_obj_res arr = lean_alloc_sarray(1, size, size);
  if (size > 0) memcpy(lean_sarray_cptr(arr), data, size);
  return arr;
}

#endif
