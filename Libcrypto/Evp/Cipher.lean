/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
import Libcrypto.Init
import Libcrypto.Evp.Param
import Libcrypto.Evp.Provider

namespace Libcrypto.Evp

private opaque CipherImpl : NonemptyType

/-- A fetched `EVP_CIPHER`. Reference counted by OpenSSL, so sharing one between
threads is safe. -/
def Cipher : Type := CipherImpl.type

instance : Nonempty Cipher := CipherImpl.property

namespace Cipher

@[extern "lc_cipher_fetch"]
opaque fetchIn (ctx : @& Option LibCtx) (name : @& String) : IO Cipher

/-- `fetchIn` against the default library context. -/
def fetch (name : String) : IO Cipher := fetchIn none name

/-- The provider's primary name, which need not be the one `fetch` was given. -/
@[extern "lc_cipher_name"]
opaque name (c : @& Cipher) : String

@[extern "lc_cipher_key_length"]
opaque keyLength (c : @& Cipher) : Nat

/-- The default nonce length. An AEAD will usually accept others, once the
context has been told the length through the `"ivlen"` parameter. -/
@[extern "lc_cipher_iv_length"]
opaque ivLength (c : @& Cipher) : Nat

/-- One for a stream cipher, which is what makes an AEAD's output the same
length as its input. -/
@[extern "lc_cipher_block_size"]
opaque blockSize (c : @& Cipher) : Nat

private opaque CtxImpl : NonemptyType

/-- An `EVP_CIPHER_CTX`. Not reentrant: use one from a single thread at a time. -/
def Ctx : Type := CtxImpl.type

instance : Nonempty Ctx := CtxImpl.property

@[extern "lc_cipher_ctx_new"]
opaque Ctx.new : IO Ctx

/-- `EVP_EncryptInit_ex2`. Each of the first three arguments may be `none`,
leaving that part of the context as it was, which is how a nonce of other than
the default length is set: once with the cipher and `"ivlen"`, then again with
the key and the nonce. -/
@[extern "lc_cipher_ctx_encrypt_init"]
opaque Ctx.encryptInit (ctx : @& Ctx) (cipher : @& Option Cipher) (key iv : @& Option ByteArray)
    (params : @& Array Param) : IO Unit

/-- `EVP_DecryptInit_ex2`, taking the same arguments as `Ctx.encryptInit`. -/
@[extern "lc_cipher_ctx_decrypt_init"]
opaque Ctx.decryptInit (ctx : @& Ctx) (cipher : @& Option Cipher) (key iv : @& Option ByteArray)
    (params : @& Array Param) : IO Unit

/-- `EVP_CipherUpdate`. What comes back may be shorter or longer than what went
in, since a block cipher holds back a partial block and emits it later. -/
@[extern "lc_cipher_ctx_update"]
opaque Ctx.update (ctx : @& Ctx) (input : @& ByteArray) : IO ByteArray

/-- Feeds additional authenticated data, which is covered by the tag but not
encrypted. It must all be supplied before the first `update`. -/
@[extern "lc_cipher_ctx_update_aad"]
opaque Ctx.updateAad (ctx : @& Ctx) (aad : @& ByteArray) : IO Unit

@[extern "lc_cipher_ctx_encrypt_final"]
opaque Ctx.encryptFinal (ctx : @& Ctx) : IO ByteArray

/-- `EVP_DecryptFinal_ex`. `none` says the input did not authenticate, whether
because the tag, the ciphertext or the additional data was not what was sealed.
That is an answer, so it is not raised. -/
@[extern "lc_cipher_ctx_decrypt_final"]
opaque Ctx.decryptFinal (ctx : @& Ctx) : IO (Option ByteArray)

/-- Sets parameters on a context already initialised, which is how the tag to
check is given before `Ctx.decryptFinal`. -/
@[extern "lc_cipher_ctx_set_params"]
opaque Ctx.setParams (ctx : @& Ctx) (params : @& Array Param) : IO Unit

/-- Reads back an octet-string parameter, such as the tag after encrypting.
OpenSSL will not size the buffer, so the caller says how many bytes it wants and
it is an error if the provider had a different number to write. -/
@[extern "lc_cipher_ctx_get_octets"]
opaque Ctx.getOctets (ctx : @& Ctx) (key : @& String) (size : Nat) : IO ByteArray

end Cipher

end Libcrypto.Evp
