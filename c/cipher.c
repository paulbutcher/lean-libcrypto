/*
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
*/

#include <limits.h>
#include <stdlib.h>

#include "shim.h"

LEAN_EXPORT lean_obj_res lc_cipher_fetch(b_lean_obj_arg libctx, b_lean_obj_arg name,
                                         lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_CIPHER *cipher = EVP_CIPHER_fetch(lc_libctx_of(libctx), lean_string_cstr(name), NULL);
  if (cipher == NULL) return lc_io_error("EVP_CIPHER_fetch");
  return lean_io_result_mk_ok(lean_alloc_external(lc_cipher_class, cipher));
}

static const EVP_CIPHER *lc_cipher(b_lean_obj_arg cipher) {
  return (const EVP_CIPHER *)lean_get_external_data(cipher);
}

static EVP_CIPHER_CTX *lc_cipher_ctx(b_lean_obj_arg ctx) {
  return (EVP_CIPHER_CTX *)lean_get_external_data(ctx);
}

LEAN_EXPORT lean_obj_res lc_cipher_name(b_lean_obj_arg cipher) {
  const char *name = EVP_CIPHER_get0_name(lc_cipher(cipher));
  return lean_mk_string(name == NULL ? "" : name);
}

static lean_obj_res lc_nat_of_int(int value) {
  return lean_box(value < 0 ? 0 : (size_t)value);
}

LEAN_EXPORT lean_obj_res lc_cipher_key_length(b_lean_obj_arg cipher) {
  return lc_nat_of_int(EVP_CIPHER_get_key_length(lc_cipher(cipher)));
}

LEAN_EXPORT lean_obj_res lc_cipher_iv_length(b_lean_obj_arg cipher) {
  return lc_nat_of_int(EVP_CIPHER_get_iv_length(lc_cipher(cipher)));
}

LEAN_EXPORT lean_obj_res lc_cipher_block_size(b_lean_obj_arg cipher) {
  return lc_nat_of_int(EVP_CIPHER_get_block_size(lc_cipher(cipher)));
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_new(lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return lc_io_error("EVP_CIPHER_CTX_new");
  return lean_io_result_mk_ok(lean_alloc_external(lc_cipher_ctx_class, ctx));
}

/* Each of `cipher`, `key` and `iv` is an `Option`, and `none` arrives as a
   scalar. Passing `none` leaves that part of the context as it was, which is how
   a nonce of other than the default length is set: once with the cipher and the
   length, then again with the key and the nonce itself. */
static const unsigned char *lc_opt_bytes(b_lean_obj_arg option) {
  return lean_is_scalar(option) ? NULL : lean_sarray_cptr(lean_ctor_get(option, 0));
}

/* Clamped rather than wrapped, so that an absurdly long key fails the comparison
   below instead of matching some small length by accident. */
static int lc_opt_size(b_lean_obj_arg option) {
  if (lean_is_scalar(option)) return -1;
  size_t size = lean_sarray_size(lean_ctor_get(option, 0));
  return size > INT_MAX ? INT_MAX : (int)size;
}

static lean_obj_res lc_cipher_ctx_init(b_lean_obj_arg ctx, b_lean_obj_arg cipher,
                                       b_lean_obj_arg key, b_lean_obj_arg iv, int encrypt,
                                       b_lean_obj_arg params) {
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  EVP_CIPHER_CTX *c = lc_cipher_ctx(ctx);
  const EVP_CIPHER *chosen = lean_is_scalar(cipher) ? NULL : lc_cipher(lean_ctor_get(cipher, 0));
  int ok = 1;
  /* The cipher and the parameters are applied on their own first, so that the
     context's key and nonce lengths are settled before any buffer is handed
     over. OpenSSL reads those lengths from the context rather than being told
     them, so a buffer shorter than the context expects would be read past its
     end. */
  if (chosen != NULL || lean_array_size(params) > 0)
    ok = EVP_CipherInit_ex2(c, chosen, NULL, NULL, encrypt, built.params);
  lc_params_release(&built);
  if (!ok) return lc_io_error(encrypt ? "EVP_EncryptInit_ex2" : "EVP_DecryptInit_ex2");

  int key_size = lc_opt_size(key);
  int iv_size = lc_opt_size(iv);
  if (key_size < 0 && iv_size < 0) return lean_io_result_mk_ok(lean_box(0));
  if (key_size >= 0 && key_size != EVP_CIPHER_CTX_get_key_length(c))
    return lc_io_error("the key is not the length this cipher takes");
  if (iv_size >= 0 && iv_size != EVP_CIPHER_CTX_get_iv_length(c))
    return lc_io_error("the nonce is not the length this context was set up for");
  if (!EVP_CipherInit_ex2(c, NULL, lc_opt_bytes(key), lc_opt_bytes(iv), encrypt, NULL))
    return lc_io_error(encrypt ? "EVP_EncryptInit_ex2" : "EVP_DecryptInit_ex2");
  return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_encrypt_init(b_lean_obj_arg ctx, b_lean_obj_arg cipher,
                                                    b_lean_obj_arg key, b_lean_obj_arg iv,
                                                    b_lean_obj_arg params, lean_obj_arg world) {
  (void)world;
  return lc_cipher_ctx_init(ctx, cipher, key, iv, 1, params);
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_decrypt_init(b_lean_obj_arg ctx, b_lean_obj_arg cipher,
                                                    b_lean_obj_arg key, b_lean_obj_arg iv,
                                                    b_lean_obj_arg params, lean_obj_arg world) {
  (void)world;
  return lc_cipher_ctx_init(ctx, cipher, key, iv, 0, params);
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_update(b_lean_obj_arg ctx, b_lean_obj_arg input,
                                              lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  size_t size = lean_sarray_size(input);
  /* `EVP_CipherUpdate` counts in `int`, so anything larger has to be refused
     rather than silently truncated to the low bits of its length. */
  if (size > INT_MAX) return lc_io_error("this input is too long for one update");
  /* A block cipher may hold back part of a previous update and emit it now, so
     the most this can produce is the input plus a full block. */
  size_t capacity = size + (size_t)EVP_CIPHER_CTX_get_block_size(lc_cipher_ctx(ctx));
  lean_obj_res out = lean_alloc_sarray(1, capacity, capacity);
  int written = 0;
  if (!EVP_CipherUpdate(lc_cipher_ctx(ctx), lean_sarray_cptr(out), &written,
                        lean_sarray_cptr(input), (int)size)) {
    lean_dec_ref(out);
    return lc_io_error("EVP_CipherUpdate");
  }
  lean_sarray_set_size(out, (size_t)written);
  return lean_io_result_mk_ok(out);
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_update_aad(b_lean_obj_arg ctx, b_lean_obj_arg aad,
                                                  lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  size_t size = lean_sarray_size(aad);
  if (size > INT_MAX) return lc_io_error("this additional data is too long for one update");
  int written = 0;
  if (!EVP_CipherUpdate(lc_cipher_ctx(ctx), NULL, &written, lean_sarray_cptr(aad), (int)size))
    return lc_io_error("EVP_CipherUpdate for additional authenticated data");
  return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_encrypt_final(b_lean_obj_arg ctx, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  size_t capacity = (size_t)EVP_CIPHER_CTX_get_block_size(lc_cipher_ctx(ctx));
  lean_obj_res out = lean_alloc_sarray(1, capacity, capacity);
  int written = 0;
  if (!EVP_EncryptFinal_ex(lc_cipher_ctx(ctx), lean_sarray_cptr(out), &written)) {
    lean_dec_ref(out);
    return lc_io_error("EVP_EncryptFinal_ex");
  }
  lean_sarray_set_size(out, (size_t)written);
  return lean_io_result_mk_ok(out);
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_decrypt_final(b_lean_obj_arg ctx, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  size_t capacity = (size_t)EVP_CIPHER_CTX_get_block_size(lc_cipher_ctx(ctx));
  lean_obj_res out = lean_alloc_sarray(1, capacity, capacity);
  int written = 0;
  int ok = EVP_DecryptFinal_ex(lc_cipher_ctx(ctx), lean_sarray_cptr(out), &written);
  if (!ok) {
    /* The tag did not match, or the padding was wrong. Both are answers about
       the input rather than faults, so the queue is dropped here. */
    lean_dec_ref(out);
    ERR_clear_error();
    return lean_io_result_mk_ok(lean_box(0));
  }
  lean_sarray_set_size(out, (size_t)written);
  lean_object *wrapper = lean_alloc_ctor(1, 1, 0);
  lean_ctor_set(wrapper, 0, out);
  return lean_io_result_mk_ok(wrapper);
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_set_params(b_lean_obj_arg ctx, b_lean_obj_arg params,
                                                  lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  lc_params built;
  if (!lc_params_build(params, &built)) return lc_io_error("allocating OSSL_PARAM array");
  int ok = EVP_CIPHER_CTX_set_params(lc_cipher_ctx(ctx), built.params);
  lc_params_release(&built);
  if (!ok) return lc_io_error("EVP_CIPHER_CTX_set_params");
  return lean_io_result_mk_ok(lean_box(0));
}

LEAN_EXPORT lean_obj_res lc_cipher_ctx_get_octets(b_lean_obj_arg ctx, b_lean_obj_arg key,
                                                  b_lean_obj_arg size, lean_obj_arg world) {
  (void)world;
  ERR_clear_error();
  size_t wanted = (size_t)lean_uint64_of_nat(size);
  lean_obj_res out = lean_alloc_sarray(1, wanted, wanted);
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_octet_string((char *)lean_string_cstr(key),
                                                lean_sarray_cptr(out), wanted);
  params[1] = OSSL_PARAM_construct_end();
  if (!EVP_CIPHER_CTX_get_params(lc_cipher_ctx(ctx), params)) {
    lean_dec_ref(out);
    return lc_io_error("EVP_CIPHER_CTX_get_params");
  }
  /* The caller sizes the buffer, so a provider that wanted to write a different
     number of bytes means the caller asked for the wrong thing. Not every
     provider records how much it wrote, ChaCha20-Poly1305 among them; one that
     does not has filled the buffer it was given. */
  if (OSSL_PARAM_modified(&params[0]) && params[0].return_size != wanted) {
    lean_dec_ref(out);
    return lc_io_error("EVP_CIPHER_CTX_get_params returned a different length");
  }
  return lean_io_result_mk_ok(out);
}
