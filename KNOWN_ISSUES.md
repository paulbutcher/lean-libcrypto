# Known issues

## Key material cannot be wiped

Lean's garbage collector may copy a `ByteArray`, and nothing here can find the copies. `OPENSSL_cleanse` over the array you are holding would be theatre: it would clear one copy and leave any others where they were. If your threat model needs keys erased from memory, this binding cannot give you that, and no amount of care at the call site will change it.

## Gaps

- Extendable-output functions are listed by `enumerate` but cannot be used: `Digest.size` answers 0 for `SHAKE-128` and `SHAKE-256`, and finalising one fails, because `EVP_DigestFinalXOF` is not bound.
- `Evp.PKey` always works in the default library context, so a key type only a legacy or FIPS provider offers is out of reach even when you have built a `LibCtx` for it.
- Encrypted PKCS#8 and encrypted PEM do not decode: `PKey.decode` takes format and structure names, but no passphrase callback is bound.
- `Libcrypto.Aead` fixes the tag at 16 bytes, so the truncated GCM tags some protocols use need `Evp.Cipher` directly.
- `Cipher.Ctx.update` refuses an input longer than `INT_MAX` rather than chunking it, leaving a caller with a payload that large to split it.

## Sharp edges

- `enumerate` does not deduplicate: with `default` and `legacy` both loaded, `RIPEMD-160` comes back twice, because both providers offer it.
- `Aead.Algorithm.nonceLength` reports the 12 byte default, but `encrypt` passes on whatever length it is given; GCM takes 1 to 128 bytes, and ChaCha20-Poly1305 takes only 12.
- `Cipher.Ctx.getOctets` cannot always check what it was handed: a provider that leaves `return_size` unmodified, as ChaCha20-Poly1305 does, would let a short write through unnoticed.
- `no OpenSSL error recorded` is a real outcome, seen when a call fails without queueing anything; the context in the message is then the only clue, and the text is truncated at 640 bytes.
- `Libcrypto.Hash` and `Libcrypto.Hmac` fetch their algorithm on every call, so hold an `Evp` handle yourself where profiling says to.

## Why the package is not called `libcrypto`

Lake names each precompiled module's plugin after the package, which for a package called `libcrypto` gives `libcrypto_Libcrypto_Hash.so`. Lean's plugin loader then strips a leading `lib` from that filename before deriving the module's initialiser symbol, so it looks for `initialize_crypto_Libcrypto_Hash` while the file exports `initialize_libcrypto_Libcrypto_Hash`.

Dropping `precompileModules` is not a way out, because Lake then passes no dynamic libraries at all and the `initialize` block cannot find the shim. Hence `lean-libcrypto`. Observed on Lean 4.33.1.

## Untested ground

- Only three OpenSSL builds are exercised: 3.0.13 on x86_64 Linux in continuous integration, 3.5.5 on aarch64 Linux in development, and 3.6.4 on macOS. The releases in between are inferred from the API each documents rather than tested.
- The finalizer tests read `/proc/self/statm`, so on macOS they skip, saying so as they go. Nothing outside Linux has confirmed that the finalizers run.
