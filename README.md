# libcrypto

A Lean 4 binding to OpenSSL 3's libcrypto, covering the EVP interfaces generically. The set of algorithms you can reach is whatever the linked OpenSSL provides, not a list written into this library.

## Requirements

OpenSSL 3.0 or later, its development headers, and `pkg-config`. The build asks `pkg-config` for `libcrypto`'s compile and link flags, so nothing about where OpenSSL lives is written down here; on macOS that is what makes a Homebrew install work without any path hunting. If `pkg-config --exists libcrypto` fails, the build stops and says so.

OpenSSL 1.1.1, LibreSSL and BoringSSL are not supported and will not be: the whole design rests on OpenSSL 3's name-based `EVP_*_fetch` and on `OSSL_PARAM`.

## Getting it

The package is named `lean-libcrypto` and the module root is `Libcrypto`, so a `require` reads:

```lean
require «lean-libcrypto» from git "<this repository>"
```

The name carries the `lean-` prefix because Lake derives each precompiled module's plugin filename from the package name, and Lean strips a leading `lib` from that filename when it looks for the module's initialiser. A package called `libcrypto` therefore cannot use `precompileModules`, which this one needs.

## The two layers

`Libcrypto.Evp.*` is a thin binding: fetch an algorithm by name, set parameters, init, update, final. Everything OpenSSL can do is reachable here, at the cost of saying what you mean in full.

`Libcrypto.Hash`, `Libcrypto.Hmac`, `Libcrypto.Aead` and `Libcrypto.Sign` are a one-shot layer over it for the operations people actually reach for. They never reuse an `Evp` module name, so an import tells you which layer you are in.

```lean
import Libcrypto

open Libcrypto

def roundTrip (key nonce : ByteArray) : IO Unit := do
  IO.println (← Hash.hash .sha256 "hello".toUTF8).size
  let aad := "to: bob".toUTF8
  let sealed ← Aead.encrypt .aes256Gcm key nonce aad "hello".toUTF8
  match ← Aead.decrypt .aes256Gcm key nonce aad sealed with
  | some plaintext => IO.println s!"{plaintext.size} bytes recovered"
  | none => IO.println "not authentic"
```

## Errors against answers

The two are never mixed. An environmental or programming failure throws in `IO`, carrying the message from the OpenSSL error queue: no such algorithm, a parameter the provider rejected, a key of the wrong length. An expected negative answer comes back as `Bool` or `Option`: a signature that does not verify, an AEAD tag that does not match, a decode of bytes that were not what they claimed to be.

A caller can therefore always tell "this token is forged" from "this build has no SHA-256". A bad signature is an answer, not an error.

## Threading

Fetched algorithm handles, `Evp.Digest`, `Evp.Cipher`, `Evp.Mac` and `Evp.Kdf`, are reference counted by OpenSSL and safe to share between threads. So is an `Evp.PKey`, which is immutable once built.

Contexts are not: `Evp.Digest.Ctx`, `Evp.Cipher.Ctx` and `Evp.Mac.Ctx` must be used from one thread at a time, and Lean will not stop you doing otherwise. Loading a provider into an `Evp.LibCtx` is not reentrant either. The one-shot functions in the top-level modules keep a context inside a single call, which is why they are the path of least resistance.

## What algorithms you get

Ask, rather than assuming:

```lean
#eval do IO.println (← Libcrypto.Evp.Digest.enumerate)
```

`enumerate` reports what the loaded providers offer, by the primary name `fetch` will report back. That name is not always the one you fetched by: `fetch "SHA256"` gives you an algorithm named `SHA2-256`.

For anything outside the default provider, build a library context with what you want in it:

```lean
let ctx ← Evp.LibCtx.withProviders #["default", "legacy"]
let md ← Evp.Digest.fetchIn (some ctx) "WHIRLPOOL"
```

A context with nothing loaded falls back to the default provider, and that fallback ends at the first explicit load, so name `"default"` alongside `"legacy"` unless you mean to exclude it. Which algorithms are legacy is a property of the linked OpenSSL and has moved between releases.

## Key material cannot be wiped

Lean's garbage collector may copy a `ByteArray`, and nothing here can find the copies. `OPENSSL_cleanse` over the array you are holding would be theatre: it would clear one copy and leave any others where they were. If your threat model needs keys erased from memory, this binding cannot give you that, and no amount of care at the call site will change it.

## What is proved

Almost nothing, and deliberately. The binding is `opaque` FFI throughout, so there is no Lean definition to reason about. What proofs there are sit at the pure Lean edges, in the test package: that no two kinds of `OSSL_PARAM` value are handed to OpenSSL under the same type tag, and that the hex helper the fixtures are written in round trips.

Everything else is held up by known-answer vectors: FIPS 180-4 for SHA-2, RFC 8032 for Ed25519, RFC 4231 for HMAC, RFC 6070 for PBKDF2, and Project Wycheproof for AES-GCM and ChaCha20-Poly1305, invalid cases included.

## What this is not

No JOSE, JWT, JWK or OIDC: this binding does not know what a `kty` or an `alg` string is. No X.509, CSR, CRL, PKCS#12 or OCSP. No TLS, which is libssl. No `BIGNUM`: to build a key from raw integers, encode a DER `SubjectPublicKeyInfo` yourself and hand it to `Evp.PKey.fromSpki`.

ECDSA signatures are taken and produced in the encoding OpenSSL uses, which is a DER `SEQUENCE` of two integers. Converting to and from a fixed-width `R‖S` is a caller's concern and is not done here.

## Tests

```
lake test
```

The tests live in a `test` subproject with its own lakefile, so nothing they need appears in the dependency graph a downstream consumer resolves.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
