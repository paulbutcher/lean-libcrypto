/-
Copyright (c) 2026 Paul Butcher. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import Tests.Harness

public section

namespace Tests.Hex

/-- The lower-case hex digit for a nibble. `encode` only ever passes a value
below 16; larger ones run off the end of the alphabet and are not decodable. -/
def digit (n : UInt8) : Char :=
  if n < 10 then Char.ofNat (48 + n.toNat) else Char.ofNat (87 + n.toNat)

/-- Accepts either case, since published vectors come in both. -/
def digitValue (c : Char) : Option UInt8 :=
  if '0' ≤ c && c ≤ '9' then some (UInt8.ofNat (c.toNat - 48))
  else if 'a' ≤ c && c ≤ 'f' then some (UInt8.ofNat (c.toNat - 87))
  else if 'A' ≤ c && c ≤ 'F' then some (UInt8.ofNat (c.toNat - 55))
  else none

def encodeByte (b : UInt8) : Char × Char := (digit (b >>> 4), digit (b &&& 15))

def decodeByte (hi lo : Char) : Option UInt8 := do
  let hi ← digitValue hi
  let lo ← digitValue lo
  return (hi <<< 4) ||| lo

def encode : List UInt8 → List Char
  | [] => []
  | b :: bs => (encodeByte b).1 :: (encodeByte b).2 :: encode bs

def decode : List Char → Option (List UInt8)
  | [] => some []
  | hi :: lo :: rest => do
      let b ← decodeByte hi lo
      let bs ← decode rest
      return b :: bs
  | _ => none

/-- Every byte, written as a natural below 256, survives a hex encode followed by
a decode. This is the form the claim is proved in, because the 256 cases are
finite and can be discharged by evaluation, whereas Lean has no decision
procedure for a quantifier over `UInt8` itself.

`n < 256` is exactly the range `UInt8.ofNat` maps injectively, so no byte is
missed and none is counted twice; the bound admits 256 values rather than none,
so it cannot make the statement vacuous. `encodeByte` returns the high and low
hex characters of its argument, and `decodeByte` reads such a pair back,
answering `none` when either character is not a hex digit. The equation therefore
says that for each of those 256 values the decode both succeeds and returns the
byte the encode started from. -/
private theorem decodeByte_encodeByte_ofNat : ∀ n < 256,
    decodeByte (encodeByte (UInt8.ofNat n)).1 (encodeByte (UInt8.ofNat n)).2
      = some (UInt8.ofNat n) := by
  decide +kernel

/-- Hex encoding loses nothing about a byte: the two characters written for it
decode back to it. Worth establishing because every known-answer vector in this
suite reaches the code under test through this pair, so a fault here would make
the vectors agree with each other rather than with the published values.

`encodeByte b` is the pair of characters written for `b`, high nibble first, so
`.1` and `.2` are those two characters in that order. `decodeByte` answers `some`
only when both are hex digits, and the byte it then returns is the first nibble
shifted up four bits with the second placed under it. The equation says that for
every `UInt8`, without exception, that decode succeeds and recovers exactly the
byte the encode started from. -/
theorem decodeByte_encodeByte (b : UInt8) :
    decodeByte (encodeByte b).1 (encodeByte b).2 = some b := by
  simpa using decodeByte_encodeByte_ofNat b.toNat b.toNat_lt

/-- A whole byte string survives the round trip, not merely each byte in
isolation. This is what the fixtures rely on, since they are decoded from hex in
bulk, and it rules out a framing error such as pairing the low nibble of one byte
with the high nibble of the next, which a per-byte claim would not catch.

`encode` writes two characters per byte, and `decode` consumes them two at a
time, answering `none` on an odd-length input or on a character that is not a hex
digit. `some bs` therefore says both that the decode succeeds, so an encoding is
never of odd length nor unreadable, and that what comes back is the original list
in the original order. The induction is on the list, so lists of every length are
covered, the empty one included. -/
theorem decode_encode (bs : List UInt8) : decode (encode bs) = some bs := by
  induction bs with
  | nil => rfl
  | cons b bs ih => simp [encode, decode, decodeByte_encodeByte, ih]

/-- Fixtures are written as hex strings, so this is how they reach a test. -/
def ofHex (s : String) : Option ByteArray :=
  (decode s.toList).map fun bytes => bytes.toByteArray

def toHex (bs : ByteArray) : String :=
  String.ofList (encode bs.toList)


/-- `decode_encode` is stated over lists, so this is the one check that the
`ByteArray` wrappers convert in the direction they claim to. -/
private def byteArrayRoundTrip : IO Unit := do
  let bs := ByteArray.mk <| Array.range 256 |>.map (fun i => UInt8.ofNat i)
  match ofHex (toHex bs) with
  | some back => expect "round trip changed the bytes" (back.toList == bs.toList)
  | none => throw <| IO.userError "toHex produced something ofHex rejects"

def cases : Array Case := #[
  { name := "a ByteArray survives toHex then ofHex", run := byteArrayRoundTrip },
  { name := "ofHex rejects an odd-length string"
    run := expect "odd length accepted" (ofHex "abc").isNone },
  { name := "ofHex rejects a non-hex character"
    run := expect "non-hex accepted" (ofHex "0g").isNone }]

/-- Decodes a fixture, failing the case rather than defaulting, since a silently
empty expectation would match anything the code under test happened to produce. -/
def ofHexOrThrow (s : String) : IO ByteArray :=
  match ofHex s with
  | some bs => pure bs
  | none => throw <| IO.userError s!"malformed hex fixture: {s}"

end Tests.Hex
