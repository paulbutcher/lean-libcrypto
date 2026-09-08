/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#include <openssl/decoder.h>
#include <openssl/encoder.h>

#include "shim.h"

static lean_obj_res lc_some(lean_obj_arg value) {
  lean_object *wrapper = lean_alloc_ctor(1, 1, 0);
  lean_ctor_set(wrapper, 0, value);
  return wrapper;
}

/* Matches the constructor order of `Evp.PKey.Selection`. */
static int lc_selection(uint8_t tag) {
  switch (tag) {
    case 0: return EVP_PKEY_PUBLIC_KEY;
    case 1: return EVP_PKEY_PRIVATE_KEY;
    case 2: return EVP_PKEY_KEYPAIR;
    default: return EVP_PKEY_KEY_PARAMETERS;
  }
}

/* `digest` is an `Option String`: `none` is a scalar and means pure EdDSA, which
   works on the message itself rather than on a digest of it. */
static const char *lc_digest_name(b_lean_obj_arg digest) {
  return lean_is_scalar(digest) ? NULL : lean_string_cstr(lean_ctor_get(digest, 0));
}

LEAN_EXPORT lean_obj_res lc_pkey_decode(b_lean_obj_arg der, uint8_t selection,
                                        b_lean_obj_arg format, b_lean_obj_arg structure,
                                        lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_PKEY *pkey = NULL;
  OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(
      &pkey, lean_string_cstr(format), lean_string_cstr(structure), NULL,
      lc_selection(selection), NULL, NULL);
  if (dctx == NULL) return lc_io_error("OSSL_DECODER_CTX_new_for_pkey");
  const unsigned char *cursor = lean_sarray_cptr(der);
  size_t remaining = lean_sarray_size(der);
  int decoded = OSSL_DECODER_from_data(dctx, &cursor, &remaining);
  OSSL_DECODER_CTX_free(dctx);
  if (!decoded || pkey == NULL) {
    /* Input that is not what it claimed to be is an answer, not a fault, so the
       queue is dropped here rather than reported. */
    ERR_clear_error();
    EVP_PKEY_free(pkey);
    return lean_io_result_mk_ok(lean_box(0));
  }
  return lean_io_result_mk_ok(lc_some(lean_alloc_external(lc_pkey_class, pkey)));
}

LEAN_EXPORT lean_obj_res lc_pkey_encode(b_lean_obj_arg pkey, uint8_t selection,
                                        b_lean_obj_arg format, b_lean_obj_arg structure,
                                        lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(
      (EVP_PKEY *)lean_get_external_data(pkey), lc_selection(selection),
      lean_string_cstr(format), lean_string_cstr(structure), NULL);
  if (ectx == NULL) return lc_io_error("OSSL_ENCODER_CTX_new_for_pkey");
  unsigned char *out = NULL;
  size_t size = 0;
  int encoded = OSSL_ENCODER_to_data(ectx, &out, &size);
  OSSL_ENCODER_CTX_free(ectx);
  if (!encoded) {
    OPENSSL_free(out);
    return lc_io_error("OSSL_ENCODER_to_data");
  }
  lean_obj_res result = lc_byte_array(out, size);
  OPENSSL_free(out);
  return lean_io_result_mk_ok(result);
}

LEAN_EXPORT lean_obj_res lc_pkey_from_raw_public_key(b_lean_obj_arg algorithm, b_lean_obj_arg key,
                                                     lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key_ex(NULL, lean_string_cstr(algorithm), NULL,
                                                  lean_sarray_cptr(key), lean_sarray_size(key));
  if (pkey == NULL) {
    ERR_clear_error();
    return lean_io_result_mk_ok(lean_box(0));
  }
  return lean_io_result_mk_ok(lc_some(lean_alloc_external(lc_pkey_class, pkey)));
}

LEAN_EXPORT lean_obj_res lc_pkey_from_raw_private_key(b_lean_obj_arg algorithm, b_lean_obj_arg key,
                                                      lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key_ex(NULL, lean_string_cstr(algorithm), NULL,
                                                   lean_sarray_cptr(key), lean_sarray_size(key));
  if (pkey == NULL) {
    ERR_clear_error();
    return lean_io_result_mk_ok(lean_box(0));
  }
  return lean_io_result_mk_ok(lc_some(lean_alloc_external(lc_pkey_class, pkey)));
}

LEAN_EXPORT lean_obj_res lc_pkey_type_name(b_lean_obj_arg pkey) {
  const char *name = EVP_PKEY_get0_type_name((EVP_PKEY *)lean_get_external_data(pkey));
  return lean_mk_string(name == NULL ? "" : name);
}

LEAN_EXPORT lean_obj_res lc_pkey_generate(b_lean_obj_arg algorithm, b_lean_obj_arg params,
                                          lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, lean_string_cstr(algorithm), NULL);
  EVP_PKEY *pkey = NULL;
  const char *failed = NULL;
  if (pctx == NULL)
    failed = "EVP_PKEY_CTX_new_from_name";
  else if (EVP_PKEY_keygen_init(pctx) <= 0)
    failed = "EVP_PKEY_keygen_init";
  else if (EVP_PKEY_CTX_set_params(pctx, built.params) <= 0)
    failed = "EVP_PKEY_CTX_set_params";
  else if (EVP_PKEY_generate(pctx, &pkey) <= 0)
    failed = "EVP_PKEY_generate";
  EVP_PKEY_CTX_free(pctx);
  lc_params_release(&built);
  if (failed != NULL) {
    EVP_PKEY_free(pkey);
    return lc_io_error(failed);
  }
  return lean_io_result_mk_ok(lean_alloc_external(lc_pkey_class, pkey));
}

LEAN_EXPORT lean_obj_res lc_pkey_sign(b_lean_obj_arg pkey, b_lean_obj_arg digest,
                                      b_lean_obj_arg message, b_lean_obj_arg params,
                                      lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned char *signature = NULL;
  size_t size = 0;
  const char *failed = NULL;
  if (ctx == NULL)
    failed = "EVP_MD_CTX_new";
  else if (EVP_DigestSignInit_ex(ctx, NULL, lc_digest_name(digest), NULL, NULL,
                                 (EVP_PKEY *)lean_get_external_data(pkey), built.params) <= 0)
    failed = "EVP_DigestSignInit_ex";
  /* The first call reports an upper bound; the second narrows `size` to what was
     actually written, which for ECDSA is shorter whenever a DER integer is. */
  else if (EVP_DigestSign(ctx, NULL, &size, lean_sarray_cptr(message),
                          lean_sarray_size(message)) <= 0)
    failed = "EVP_DigestSign";
  else if ((signature = OPENSSL_malloc(size == 0 ? 1 : size)) == NULL)
    failed = "allocating the signature buffer";
  else if (EVP_DigestSign(ctx, signature, &size, lean_sarray_cptr(message),
                          lean_sarray_size(message)) <= 0)
    failed = "EVP_DigestSign";
  EVP_MD_CTX_free(ctx);
  lc_params_release(&built);
  if (failed != NULL) {
    OPENSSL_free(signature);
    return lc_io_error(failed);
  }
  lean_obj_res result = lc_byte_array(signature, size);
  OPENSSL_free(signature);
  return lean_io_result_mk_ok(result);
}

LEAN_EXPORT lean_obj_res lc_pkey_verify(b_lean_obj_arg pkey, b_lean_obj_arg digest,
                                        b_lean_obj_arg message, b_lean_obj_arg signature,
                                        b_lean_obj_arg params, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int verified = -1;
  const char *failed = NULL;
  if (ctx == NULL)
    failed = "EVP_MD_CTX_new";
  else if (EVP_DigestVerifyInit_ex(ctx, NULL, lc_digest_name(digest), NULL, NULL,
                                   (EVP_PKEY *)lean_get_external_data(pkey), built.params) <= 0)
    failed = "EVP_DigestVerifyInit_ex";
  else {
    verified = EVP_DigestVerify(ctx, lean_sarray_cptr(signature), lean_sarray_size(signature),
                                lean_sarray_cptr(message), lean_sarray_size(message));
    if (verified < 0) failed = "EVP_DigestVerify";
  }
  EVP_MD_CTX_free(ctx);
  lc_params_release(&built);
  if (failed != NULL) return lc_io_error(failed);
  /* A signature that does not verify leaves the queue populated; that is an
     answer rather than a fault, so it is dropped here. */
  ERR_clear_error();
  return lean_io_result_mk_ok(lean_box(verified == 1 ? 1 : 0));
}
