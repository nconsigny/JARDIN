/-
  WotsOts/WotsC.lean — WOTS+C verification model.

  Models the WOTS+C signature verification from WotsPlusC.sol.
  The key innovation: checksum chains are replaced by a grinding nonce (count)
  that forces the base-16 digit sum to equal 240.

  Reference: ePrint 2025/2203 (Blockstream Research)
-/

import WotsOts.Types
import WotsOts.Hash

namespace WotsOts.WotsC

open WotsOts WotsOts.Hash

/-- Extract base-16 digits from a 128-bit value.
    Returns a function mapping digit index to digit value.
    digit[i] = (val >> (i * 4)) & 0xF -/
def extractDigits (val : Nat) : Fin 32 → Nat :=
  fun i => (val / 2^(i.val * 4)) % 16

/-- Sum of all 32 base-16 digits -/
def digitSum (val : Nat) : Nat :=
  (List.range 32).foldl (fun acc i => acc + (extractDigits val ⟨i, by omega⟩)) 0

/-- WOTS+C constraint: digit sum must equal 240 -/
def validDigitSum (val : Nat) : Prop :=
  digitSum val = 240

/-- Verify a single WOTS+C chain.
    Given sigma[i] at position digits[i], complete the chain to position W-1.
    Returns the chain endpoint (public key element). -/
def verifyChain (seed : Nat) (leafIdx : Nat) (chainIdx : Nat)
    (sigma_i : Nat) (digit_i : Nat) : Nat :=
  let adrs : Types.Adrs := {
    adrsType := .wots
    keyPair := leafIdx
    chainIdx := chainIdx
  }
  let steps := 15 - digit_i  -- W - 1 - digit_i
  chainHash seed adrs sigma_i digit_i steps

/-- Compress 32 chain endpoints into the WOTS+C public key -/
def compressPk (seed : Nat) (leafIdx : Nat) (endpoints : Fin 32 → Nat) : Nat :=
  let adrs : Types.Adrs := {
    adrsType := .wotsPk
    keyPair := leafIdx
  }
  thMulti seed adrs (List.ofFn endpoints)

/-- Full WOTS+C verification.
    Returns Some wotsPk on success, None on failure.
    Models WotsPlusC.verify() from the Solidity contract. -/
def verify (seed : Nat) (leafIdx : Nat) (msgHash : Nat)
    (sigma : Fin 32 → Nat) (count : Nat) : Option Nat := do
  -- Step 1: Compute constrained digest
  let adrs : Types.Adrs := {
    adrsType := .wots
    keyPair := leafIdx
  }
  let d := hMsg seed adrs msgHash count

  -- Step 2: Extract and validate digits
  let digits := extractDigits d
  guard (digitSum d = 240)

  -- Step 3: Complete chains and compress
  let endpoints : Fin 32 → Nat := fun i =>
    verifyChain seed leafIdx i.val (sigma i) (digits i)

  let wotsPk := compressPk seed leafIdx endpoints
  return wotsPk

-- ════════════════════════════════════════════════════════════
--  Key Properties
-- ════════════════════════════════════════════════════════════

/-- If verification succeeds, the digit sum constraint was satisfied -/
theorem verify_implies_valid_sum (seed leafIdx msgHash count : Nat)
    (sigma : Fin 32 → Nat) (pk : Nat)
    (h : verify seed leafIdx msgHash sigma count = some pk) :
    let adrs : Types.Adrs := { adrsType := .wots, keyPair := leafIdx }
    validDigitSum (hMsg seed adrs msgHash count) := by
  simp [verify, validDigitSum] at h ⊢
  obtain ⟨h_guard, _⟩ := h
  exact h_guard

/-- Different counts produce different digests (from hash domain separation) -/
theorem different_count_different_digest (seed leafIdx msgHash : Nat)
    (c1 c2 : Nat) (h : c1 ≠ c2) :
    hMsg seed { adrsType := .wots, keyPair := leafIdx } msgHash c1 ≠
    hMsg seed { adrsType := .wots, keyPair := leafIdx } msgHash c2 := by
  -- This follows from the hash function being injective in its last argument
  -- when all other arguments are fixed. Formally requires the PRF assumption.
  sorry -- Requires concrete hash model or additional axiom

end WotsOts.WotsC
