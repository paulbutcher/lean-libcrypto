/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shim.h"

lean_external_class *lc_md_class = NULL;
lean_external_class *lc_md_ctx_class = NULL;
lean_external_class *lc_pkey_class = NULL;
lean_external_class *lc_cipher_class = NULL;
lean_external_class *lc_cipher_ctx_class = NULL;
lean_external_class *lc_mac_class = NULL;
lean_external_class *lc_mac_ctx_class = NULL;
lean_external_class *lc_kdf_class = NULL;
lean_external_class *lc_libctx_class = NULL;

lean_obj_res lc_io_error(const char *context) {
  char buf[640];
  int off = snprintf(buf, sizeof buf, "%s", context);
  if (off < 0) off = 0;
  if ((size_t)off >= sizeof buf) off = (int)sizeof buf - 1;
  int found = 0;
  unsigned long code;
  /* Drained to the end even once `buf` is full, so the next call starts clean. */
  while ((code = ERR_get_error()) != 0) {
    if ((size_t)off + 1 < sizeof buf) {
      char detail[256];
      ERR_error_string_n(code, detail, sizeof detail);
      int written = snprintf(buf + off, sizeof buf - off, "%s%s", found ? "; " : ": ", detail);
      if (written > 0) {
        off += written;
        if ((size_t)off >= sizeof buf) off = (int)sizeof buf - 1;
      }
    }
    found = 1;
  }
  if (!found) snprintf(buf + off, sizeof buf - off, ": no OpenSSL error recorded");
  return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string(buf)));
}

void lc_param_fill(b_lean_obj_arg param, OSSL_PARAM *out, lc_scratch *scratch) {
  /* `Param` is `⟨key, value⟩`; every `ParamValue` constructor carries one object. */
  char *key = (char *)lean_string_cstr(lean_ctor_get(param, 0));
  b_lean_obj_arg value = lean_ctor_get(param, 1);
  b_lean_obj_arg payload = lean_ctor_get(value, 0);
  switch (lean_obj_tag(value)) {
    case 0:
      scratch->i = (int64_t)lean_int64_of_int(payload);
      *out = OSSL_PARAM_construct_int64(key, &scratch->i);
      break;
    case 1:
      scratch->u = lean_uint64_of_nat(payload);
      *out = OSSL_PARAM_construct_uint64(key, &scratch->u);
      break;
    case 2:
      /* Lean keeps its strings NUL terminated, so a size of zero is safe here. */
      *out = OSSL_PARAM_construct_utf8_string(key, (char *)lean_string_cstr(payload), 0);
      break;
    default:
      *out = OSSL_PARAM_construct_octet_string(key, lean_sarray_cptr(payload),
                                               lean_sarray_size(payload));
      break;
  }
}

int lc_params_build(b_lean_obj_arg arr, lc_params *out) {
  size_t count = lean_array_size(arr);
  out->params = calloc(count + 1, sizeof(OSSL_PARAM));
  out->scratch = calloc(count + 1, sizeof(lc_scratch));
  if (out->params == NULL || out->scratch == NULL) {
    lc_params_release(out);
    return 0;
  }
  for (size_t i = 0; i < count; i++)
    lc_param_fill(lean_array_get_core(arr, i), &out->params[i], &out->scratch[i]);
  out->params[count] = OSSL_PARAM_construct_end();
  return 1;
}

void lc_params_release(lc_params *out) {
  free(out->params);
  free(out->scratch);
  out->params = NULL;
  out->scratch = NULL;
}

LEAN_EXPORT uint32_t lc_param_data_type(b_lean_obj_arg param) {
  OSSL_PARAM built;
  lc_scratch scratch;
  lc_param_fill(param, &built, &scratch);
  return (uint32_t)built.data_type;
}

LEAN_EXPORT uint8_t lc_constant_time_eq(b_lean_obj_arg a, b_lean_obj_arg b) {
  size_t size = lean_sarray_size(a);
  if (size != lean_sarray_size(b)) return 0;
  if (size == 0) return 1;
  return CRYPTO_memcmp(lean_sarray_cptr(a), lean_sarray_cptr(b), size) == 0 ? 1 : 0;
}

lc_libctx *lc_libctx_retain(lc_libctx *held) {
  if (held != NULL) __atomic_fetch_add(&held->refs, 1, __ATOMIC_RELAXED);
  return held;
}

/* Atomic because a fetched algorithm may be shared between threads, so the last
   reference to a context can be dropped from any of them.

   Unloading comes before the free: `OSSL_LIB_CTX_free` leaves what was loaded
   into it in place, and the providers hold the context alive until they go. */
void lc_libctx_release(lc_libctx *held) {
  if (held == NULL || __atomic_fetch_sub(&held->refs, 1, __ATOMIC_ACQ_REL) != 1) return;
  while (held->count > 0) OSSL_PROVIDER_unload(held->providers[--held->count]);
  free(held->providers);
  OSSL_LIB_CTX_free(held->ctx);
  free(held);
}

static void lc_owned_free(void *ptr) {
  lc_owned *held = (lc_owned *)ptr;
  lc_libctx_release(held->owner);
  free(held);
}

lean_object *lc_owned_alloc(lean_external_class **cls, void *handle, lc_libctx *owner) {
  lc_owned *held = malloc(sizeof(lc_owned));
  if (held == NULL) return NULL;
  held->handle = handle;
  held->owner = lc_libctx_retain(owner);
  lean_object *wrapped = lc_alloc_external(cls, held);
  if (wrapped == NULL) lc_owned_free(held);
  return wrapped;
}

void lc_owned_set_owner(b_lean_obj_arg o, lc_libctx *owner) {
  lc_owned *held = (lc_owned *)lean_get_external_data(o);
  lc_libctx *previous = held->owner;
  /* Retained before the release, since the two may be the same context. */
  held->owner = lc_libctx_retain(owner);
  lc_libctx_release(previous);
}

static void lc_md_finalize(void *ptr) {
  EVP_MD_free((EVP_MD *)((lc_owned *)ptr)->handle);
  lc_owned_free(ptr);
}
static void lc_md_ctx_finalize(void *ptr) {
  EVP_MD_CTX_free((EVP_MD_CTX *)((lc_owned *)ptr)->handle);
  lc_owned_free(ptr);
}
static void lc_cipher_finalize(void *ptr) {
  EVP_CIPHER_free((EVP_CIPHER *)((lc_owned *)ptr)->handle);
  lc_owned_free(ptr);
}
static void lc_cipher_ctx_finalize(void *ptr) {
  EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)((lc_owned *)ptr)->handle);
  lc_owned_free(ptr);
}
static void lc_mac_finalize(void *ptr) {
  EVP_MAC_free((EVP_MAC *)((lc_owned *)ptr)->handle);
  lc_owned_free(ptr);
}
static void lc_mac_ctx_finalize(void *ptr) {
  EVP_MAC_CTX_free((EVP_MAC_CTX *)((lc_owned *)ptr)->handle);
  lc_owned_free(ptr);
}
static void lc_kdf_finalize(void *ptr) {
  EVP_KDF_free((EVP_KDF *)((lc_owned *)ptr)->handle);
  lc_owned_free(ptr);
}
/* Keys are fetched from the default context alone, so they carry no owner. */
static void lc_pkey_finalize(void *ptr) { EVP_PKEY_free((EVP_PKEY *)ptr); }
static void lc_libctx_finalize(void *ptr) { lc_libctx_release((lc_libctx *)ptr); }
static void lc_foreach_noop(void *ptr, b_lean_obj_arg fn) {
  (void)ptr;
  (void)fn;
}

static void lc_register_classes(void) {
  struct {
    lean_external_class **slot;
    lean_external_finalize_proc finalize;
  } registrations[] = {{&lc_md_class, lc_md_finalize},
                       {&lc_md_ctx_class, lc_md_ctx_finalize},
                       {&lc_pkey_class, lc_pkey_finalize},
                       {&lc_cipher_class, lc_cipher_finalize},
                       {&lc_cipher_ctx_class, lc_cipher_ctx_finalize},
                       {&lc_mac_class, lc_mac_finalize},
                       {&lc_mac_ctx_class, lc_mac_ctx_finalize},
                       {&lc_kdf_class, lc_kdf_finalize},
                       {&lc_libctx_class, lc_libctx_finalize}};
  for (size_t i = 0; i < sizeof registrations / sizeof registrations[0]; i++)
    *registrations[i].slot =
        lean_register_external_class(registrations[i].finalize, lc_foreach_noop);
}

static pthread_once_t lc_classes_once = PTHREAD_ONCE_INIT;

lean_object *lc_alloc_external(lean_external_class **cls, void *data) {
  pthread_once(&lc_classes_once, lc_register_classes);
  if (*cls == NULL) return NULL;
  return lean_alloc_external(*cls, data);
}
