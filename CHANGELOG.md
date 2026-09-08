# Changelog

## 0.1.0

- Digests over the EVP interface, with the `OSSL_PARAM` bridge, the error bridge and constant-time comparison.
- Public key decoding and signature verification for RSA PKCS#1 v1.5, RSA-PSS, ECDSA and Ed25519.
- Key generation, signing, and reading keys back out through `OSSL_ENCODER`.
- Ciphers, MACs and KDFs, with `Libcrypto.Aead` for AES-GCM and ChaCha20-Poly1305 and `Libcrypto.Hmac`.
- Library contexts, so that providers such as `legacy` and `fips` can be loaded and fetched from.
