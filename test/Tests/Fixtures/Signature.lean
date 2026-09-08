/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/

/-!
Regenerate with, in a scratch directory:

    printf 'libcrypto binding fixture message' > msg.bin
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.pem
    openssl pkey -in rsa.pem -pubout -outform DER -out rsa_pub.der
    openssl dgst -sha256 -sign rsa.pem -out rsa_pkcs1.sig msg.bin
    openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
      -sign rsa.pem -out rsa_pss.sig msg.bin
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.pem
    openssl pkey -in ec.pem -pubout -outform DER -out ec_pub.der
    openssl dgst -sha256 -sign ec.pem -out ec_p256.sig msg.bin

The private keys are deliberately not kept: nothing here needs to sign, and a
signing key in a public repository invites someone to reuse it.
-/

namespace Tests.Fixtures.Signature

/-- The message every signature below was made over. -/
def message : String := "libcrypto binding fixture message"

def rsaSpkiDer : String :=
  "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
    ++ "00d52c8157666cf5044c700dd6b32ca948c29874969b250901497f1ce9be511a"
    ++ "065b1ed0c5a89a1d6d7cbaa0ffbebdbc0ed4f7ccf63dd265dcdd12e3cc090d2e"
    ++ "422cdfb6d3de82a8e0fb2c69fa2b9c38742c76b889ab1f7a5a65a8612857d983"
    ++ "82a0e0f2b0589c77ed210b0916998727df0b5cd437f999948cc8f00834f14248"
    ++ "da07125c581d86a303bbbfe103cacb8cb6a1c5ef53422e9b02be3047142daecd"
    ++ "6d64700d337623457a3898e810b1965252269984d9f4a9b64248d8366a6d6680"
    ++ "ccc10f17f6f522af715242d3fa5339bba487529671b183560c5d9d7d8e747411"
    ++ "3010444fbd67e1f57bb7c8c1bb11a9e3722e25b5805399ec7c0e9c63a43fb935"
    ++ "bb0203010001"
def rsaPkcs1Sha256 : String :=
  "7e0d58ad643c6f1649ff72d75a952e09dbf83d5c5557ceb0cac34d03749b6bf7"
    ++ "c05df83c6c49bf0660f5c718e3ac7c0aadc9a9c214bc1d6741ae9197e7ec6da3"
    ++ "64556e96600f5129ccab0d44bc0d8175255e6afffeff4eba50bf64eaae986159"
    ++ "89eedd9cdbd3655bbf448b8ee647e929040a22660b24df0836d91fb6ab41932f"
    ++ "4c2a81b0df6a07a99f44fc61fffa3d60306faccfc90b2fa2aeef6fc95f9c14c3"
    ++ "4110bba5959e90458fec0ed3468ee8a7b16c24d84e67e5331efa11eec087563f"
    ++ "873b69763188ff20978636830d6924da79752435a8f11e2ed85ddf808cc65ab0"
    ++ "969181c19910070fb6e4bea3f667a54c5b6152071a59b2d7dfecce8051217f30"
def rsaPssSha256 : String :=
  "86ed0b42b5d4694066799478f18d460a398af3c9b198339a375812e1dc811cdd"
    ++ "594f63c8b8459ebb98a6227d25e3a5a37d3acc8a4279109afd5ebadad9e1e0d2"
    ++ "1cfd426c8cf4cb6d383c501f2a0ba3715e0926ead84df739068c81557fcbde95"
    ++ "bb3b95edcc386e1a9d6b4002682c519ac23605293d11ca7995319aa369999474"
    ++ "d353fe465b9cb142929f3139e14c0387997e54aa21368207b05d804be8d7faa1"
    ++ "e941c62ec2e7e16ebf5d8b7ac2e9ca0a9ef98267d59fe14ed1a4ca66a1a885bc"
    ++ "3e98a828618727bfc146e678a3d411eecad97bced6ff1daf0c06e92b83ab05f1"
    ++ "47953647248c63849c8086c47ec907cbfda5ba9544672a3addcc41142dcb99d4"
def ecP256SpkiDer : String :=
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004bdaa3671b9"
    ++ "898e4a7c01385400573e1e02c885983048be2c7e43c7353e05ee630b8638c352"
    ++ "e42e855912fde775a48c3cab261db6dbd2df2d959ed4f81cc24c4a"
def ecdsaP256Sha256 : String :=
  "3045022100c05fdec8f10dc5c2af3a49e9983761cb4e1bc478f6320de65d3e91"
    ++ "2a15e0572d022005410b88231f1cd7ff31747d03d047a2274671d2754f93ea01"
    ++ "9899afce60a557"
end Tests.Fixtures.Signature
