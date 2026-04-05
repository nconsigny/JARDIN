/-
  WotsOts/Contract.lean — Full contract model (state transitions).

  Models the WotsOts / WotsOtsAsm smart contract as a state machine.
  Each operation is a pure function from (state, inputs) → Option (output, state').
  `none` represents a revert (invalid sig, double use, etc.).

  This follows the Morpho-Verity pattern of modeling Solidity logic functionally.
-/

import WotsOts.Types
import WotsOts.Bitmap
import WotsOts.WotsC
import WotsOts.MerkleTree

namespace WotsOts.Contract

open WotsOts WotsOts.Bitmap WotsOts.WotsC WotsOts.MerkleTree

-- ════════════════════════════════════════════════════════════
--  Pure Verification (view function)
-- ════════════════════════════════════════════════════════════

/-- Pure WOTS+C OTS verification against the Merkle root.
    Models the verify(bytes32, bytes) view function. -/
def verifyPure (s : ContractState) (message : Nat) (sig : OtsSig) : Bool :=
  -- Check leaf index bounds
  if sig.leafIdx >= maxKeys then false
  else
    -- WOTS+C verification
    match WotsC.verify s.pkSeed sig.leafIdx message sig.sigma sig.count with
    | none => false  -- digit sum constraint failed
    | some wotsPk =>
      -- Merkle auth path verification
      let computedRoot := MerkleTree.verifyPath s.pkSeed wotsPk sig.leafIdx sig.authPath
      computedRoot == s.merkleRoot

-- ════════════════════════════════════════════════════════════
--  Verify and Mark (state-changing)
-- ════════════════════════════════════════════════════════════

/-- Verify and mark a leaf as consumed.
    Returns Some (leafIdx, newState) on success, None on revert.
    Models _verifyAndMark() from the Solidity contract. -/
def verifyAndMark (s : ContractState) (message : Nat) (sig : OtsSig) :
    Option (Nat × ContractState) := do
  -- Bounds check
  guard (sig.leafIdx < maxKeys)
  -- One-time use check
  guard (Bitmap.isUsed s.usedBitmap sig.leafIdx == false)
  -- Cryptographic verification
  guard (verifyPure s message sig)
  -- Mark leaf and return new state
  let newBitmap := Bitmap.mark s.usedBitmap sig.leafIdx
  return (sig.leafIdx, { s with usedBitmap := newBitmap })

-- ════════════════════════════════════════════════════════════
--  Execute (full transaction)
-- ════════════════════════════════════════════════════════════

/-- Compute the transaction hash.
    txHash = keccak256(chainId || address || nonce || dest || value || dataHash)
    We model this abstractly as a pure function of its inputs. -/
opaque computeTxHash (chainId : Nat) (contractAddr : Nat) (nonce : Nat)
    (dest : Nat) (value : Nat) (dataHash : Nat) : Nat

/-- Execute a transaction.
    Returns Some newState on success, None on revert.
    Models execute() from the Solidity contract. -/
def execute (s : ContractState) (tx : TxParams) (sig : OtsSig)
    (contractAddr : Nat) : Option ContractState := do
  -- Build transaction hash
  let txHash := computeTxHash tx.chainId contractAddr s.nonce tx.dest tx.value tx.dataHash
  -- Verify and mark
  let (_, s') ← verifyAndMark s txHash sig
  -- Increment nonce
  return { s' with nonce := s.nonce + 1 }

-- ════════════════════════════════════════════════════════════
--  View Functions
-- ════════════════════════════════════════════════════════════

/-- Check if a leaf is used. Models isLeafUsed(). -/
def isLeafUsed (s : ContractState) (idx : Nat) : Bool :=
  Bitmap.isUsed s.usedBitmap idx

/-- Count remaining keys. Models remainingKeys(). -/
def remainingKeys (s : ContractState) : Nat :=
  Bitmap.remainingKeys s.usedBitmap

end WotsOts.Contract
