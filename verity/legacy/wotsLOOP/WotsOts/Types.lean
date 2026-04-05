/-
  WotsOts/Types.lean — Core type definitions for the WOTS+C OTS contract model.

  Models the contract state and parameters matching the Solidity implementation.
  All values use Nat (unbounded) with explicit modular constraints where needed.
  This follows the Morpho-Verity pattern of modeling Solidity state functionally.
-/

namespace WotsOts

/-- 256-bit unsigned integer (modeling Solidity uint256) -/
abbrev UInt256 := Nat

/-- 128-bit hash output (n = 128 bits, matching the SPHINCS+ parameter) -/
abbrev Hash128 := Nat

/-- Maximum value for 256-bit unsigned integer -/
def UInt256.max : Nat := 2^256 - 1

/-- WOTS+C parameters (hardcoded in the contract) -/
structure WotsParams where
  w     : Nat := 16       -- Winternitz parameter
  l     : Nat := 32       -- Number of chains
  len1  : Nat := 32       -- Message digits
  targetSum : Nat := 240  -- Fixed digit sum constraint
  z     : Nat := 0        -- Forced zero chains
  deriving Repr, DecidableEq

/-- Default WOTS+C parameters -/
def defaultParams : WotsParams := {}

/-- Merkle tree parameters -/
def treeHeight : Nat := 10
def maxKeys : Nat := 1024  -- 2^treeHeight

/-- ADRS type constants (matching TweakableHash.sol) -/
inductive AdrsType where
  | wots     : AdrsType  -- 0
  | wotsPk   : AdrsType  -- 1
  | tree     : AdrsType  -- 2
  deriving Repr, DecidableEq

/-- ADRS tweak (simplified model of the 32-byte address structure) -/
structure Adrs where
  layer    : Nat := 0
  treeAddr : Nat := 0
  adrsType : AdrsType := .wots
  keyPair  : Nat := 0
  chainIdx : Nat := 0
  chainPos : Nat := 0
  hashAddr : Nat := 0
  deriving Repr, DecidableEq

/-- Bitmap word index (0..3) -/
abbrev BitmapWordIdx := Fin 4

/-- Leaf index (0..1023) -/
abbrev LeafIdx := Fin maxKeys

/-- The on-chain bitmap state: 4 × 256-bit words = 1024 bits -/
structure Bitmap where
  words : Fin 4 → UInt256
  deriving Repr

/-- The full contract state -/
structure ContractState where
  pkSeed     : Hash128
  merkleRoot : Hash128
  usedBitmap : Bitmap
  nonce      : Nat
  deriving Repr

/-- Initial contract state after deployment -/
def initialState (seed : Hash128) (root : Hash128) : ContractState :=
  { pkSeed := seed
  , merkleRoot := root
  , usedBitmap := { words := fun _ => 0 }
  , nonce := 0 }

/-- Transaction parameters for execute() -/
structure TxParams where
  dest    : Nat     -- target address
  value   : Nat     -- ETH value
  dataHash : Hash128 -- keccak256(calldata)
  chainId : Nat
  deriving Repr

/-- A WOTS+C OTS signature -/
structure OtsSig where
  leafIdx  : Nat
  sigma    : Fin 32 → Hash128   -- 32 chain values
  count    : Nat
  authPath : Fin 10 → Hash128   -- Merkle auth path (H=10)
  deriving Repr

end WotsOts
