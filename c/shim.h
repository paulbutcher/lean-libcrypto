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

/* Registered by the first call to `lc_alloc_external`, which is the only place an
   external object is made. Registering from an `initialize` block in Lean would
   put it out of reach of `lake lint`, which runs a module's initializers with
   the .olean alone and so without the shim to call into. */
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
   first. `refs` counts the Lean handle and everything fetched through it. */
typedef struct {
  OSSL_LIB_CTX *ctx;
  OSSL_PROVIDER **providers;
  size_t count;
  size_t capacity;
  size_t refs;
} lc_libctx;

/* Both take NULL for the default context, which is never freed. */
lc_libctx *lc_libctx_retain(lc_libctx *held);
void lc_libctx_release(lc_libctx *held);

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

/* For a fault of the caller's making, which OpenSSL has not been asked about and
   so has said nothing about.

   The callers that matter most are the checks for a context with no algorithm
   set. OpenSSL 3.0 reads through the null in `EVP_DigestUpdate` and in
   `EVP_CIPHER_CTX_get_block_size`, killing the process rather than failing the
   call; 3.5 returns an error from both. Checking before the call makes it an
   error on every version. */
static inline lean_obj_res lc_caller_error(const char *message) {
  return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string(message)));
}

/* An OpenSSL object together with the library context it came from, which it
   holds open. Freeing an `OSSL_LIB_CTX` tears down the providers loaded into it
   whatever is still using them, and nothing OpenSSL hands out counts as a use,
   so the reference has to be kept here. `owner` is NULL for the default context.

   A context derived from such an object, an `EVP_MD_CTX` for one, needs the same
   reference: OpenSSL's own counting keeps its algorithm and that algorithm's
   provider alive, but reaches no further. */
typedef struct {
  void *handle;
  lc_libctx *owner;
} lc_owned;

static inline void *lc_handle(b_lean_obj_arg o) {
  return ((lc_owned *)lean_get_external_data(o))->handle;
}

static inline lc_libctx *lc_owner(b_lean_obj_arg o) {
  return ((lc_owned *)lean_get_external_data(o))->owner;
}

/* Makes an external object. Returns NULL only if the classes could not be
   registered. */
lean_object *lc_alloc_external(lean_external_class **cls, void *data);

/* Wraps `handle`, taking a reference to `owner`. Returns NULL only on allocation
   failure, leaving `handle` for the caller to free. */
lean_object *lc_owned_alloc(lean_external_class **cls, void *handle, lc_libctx *owner);

/* Moves an already wrapped object to `owner`, for a context that has just been
   given the algorithm it will work with. */
void lc_owned_set_owner(b_lean_obj_arg o, lc_libctx *owner);

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
