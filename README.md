# libcrypto

A Lean 4 binding to OpenSSL 3's libcrypto, covering the EVP interfaces generically. The set of algorithms you can reach is whatever the linked OpenSSL provides.

## Usage

**Requirements:** OpenSSL 3.0 or later, its development headers, and `pkg-config`.

```lean
require «lean-libcrypto» from git "<this repository>"
```

## The two layers

`Libcrypto.Evp.*` is a thin binding: fetch an algorithm by name, set parameters, init, update, final. Everything OpenSSL can do is reachable here.

`Libcrypto.Hash`, `Libcrypto.Hmac`, `Libcrypto.Aead` and `Libcrypto.Sign` are a one-shot layer over it for commonly used features.

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

## Threading

Fetched algorithm handles, `Evp.Digest`, `Evp.Cipher`, `Evp.Mac` and `Evp.Kdf`, are reference counted by OpenSSL and safe to share between threads. So is an `Evp.PKey`, which is immutable once built.

Contexts are not: `Evp.Digest.Ctx`, `Evp.Cipher.Ctx` and `Evp.Mac.Ctx` must be used from one thread at a time, and Lean will not stop you doing otherwise. Loading a provider into an `Evp.LibCtx` is not reentrant either. The one-shot functions in the top-level modules keep a context inside a single call, which is why they are the path of least resistance.

## Discovering available algorithms

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

## Known issues

Read [KNOWN_ISSUES.md](KNOWN_ISSUES.md) before relying on this for anything.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
