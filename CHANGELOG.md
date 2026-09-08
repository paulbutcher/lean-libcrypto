# Changelog

## 0.1.1

- A fetched algorithm now holds its library context open, so dropping the context first is no longer a use after free.
- The external classes are registered on first use rather than from an `initialize` block, which removes `Libcrypto.Init` and lets `lake lint` run.

## 0.1.0

- Digests over the EVP interface, with the `OSSL_PARAM` bridge, the error bridge and constant-time comparison.
- Public key decoding and signature verification for RSA PKCS#1 v1.5, RSA-PSS, ECDSA and Ed25519.
- Key generation, signing, and reading keys back out through `OSSL_ENCODER`.
- Ciphers, MACs and KDFs, with `Libcrypto.Aead` for AES-GCM and ChaCha20-Poly1305 and `Libcrypto.Hmac`.
- Library contexts, so that providers such as `legacy` and `fips` can be loaded and fetched from.
