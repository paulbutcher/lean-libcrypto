/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/

/-!
The Ed25519 vectors of RFC 8032 section 7.1, as hex. Ed25519 signing is
deterministic, so the signature below is the only one the secret key and message
can produce, which is what makes these usable as known answers for signing and
not only for verification.
-/

namespace Tests.Fixtures.Ed25519

/-- Secret key, public key, message and signature, in that order. -/
structure Vector where
  secret : String
  publicKey : String
  message : String
  signature : String

def test1 : Vector where
  secret := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  publicKey := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  message := ""
  signature := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
    ++ "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

def test2 : Vector where
  secret := "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  publicKey := "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
  message := "72"
  signature := "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69"
    ++ "da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"

def test3 : Vector where
  secret := "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
  publicKey := "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
  message := "af82"
  signature := "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3"
    ++ "ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"

/-- The vector RFC 8032 labels `SHA(abc)`: the message is itself a SHA-512
digest, which makes it the longest of the four. -/
def testSha : Vector where
  secret := "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
  publicKey := "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
  message := "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    ++ "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
  signature := "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
    ++ "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"

def all : List (String × Vector) :=
  [("test 1", test1), ("test 2", test2), ("test 3", test3), ("test SHA(abc)", testSha)]

end Tests.Fixtures.Ed25519
