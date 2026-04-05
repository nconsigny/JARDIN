/-
  SphincsC6V — Full SPHINCS+ C6 verifier using verity_contract macro.

  Uses memory-as-state pattern for forEach loop-carried variables:
  mutable state lives in EVM memory (mstore/mload) rather than Lean
  `let mut` bindings, avoiding the closure mutation limitation.

  Memory layout:
    0x00:  seed (warm)
    0x20:  ADRS scratch
    0x40:  input1 / left child
    0x60:  input2 / right child
    0x80:  buffer (32×32 endpoints / 8×32 FORS roots)
    --- scratch for loop-carried state ---
    0x500: node (FORS tree walk)
    0x520: pathIdx (FORS tree walk)
    0x540: digitSum (WOTS accumulator)
    0x560: currentNode (hypertree)
    0x580: idxTree (hypertree decomposition)
    0x5A0: sigOff (signature offset cursor)
    0x5C0: val (WOTS chain value)
    0x5E0: pos (WOTS chain position)
    0x600: merkleNode (Merkle walk)
    0x620: mIdx (Merkle leaf index)

  C6: W+C_F+C h=24 d=2 a=16 k=8 w=16 l=32 target_sum=240, sig=3352 bytes
-/

import Contracts.Common

namespace Contracts

open Verity hiding pure bind
open Verity.EVM.Uint256



verity_contract SphincsC6V where
  storage
    pkSeed : Uint256 := slot 0
    pkRoot : Uint256 := slot 1

  constructor (seed : Bytes32, root : Bytes32) := do
    setStorage pkSeed seed
    setStorage pkRoot root

  function verify (message : Bytes32, sig : Bytes)
    local_obligations [
      memory_layout := assumed "Fixed memory layout per header comment. Slots 0x500-0x620 are scratch for loop state.",
      calldataload_sig := assumed "Signature at calldata offset 100. calldataload(68) = sig length.",
      sphincs_correctness := assumed "Verification loops implement SPHINCS+ C6 per ePrint 2025/2203."
    ]
    : Uint256 := do
    let seed ← getStorage pkSeed
    let root ← getStorage pkRoot

    let sigLen := calldataload 68
    require (sigLen == 3352) "Invalid sig length"

    let sigBase := 100
    mstore 0x00 seed

    -- H_msg digest
    let r := bitAnd (calldataload sigBase) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
    mstore 0x20 root
    mstore 0x40 r
    mstore 0x60 message
    let digest := keccak256 0x00 0x80
    let htIdx := bitAnd (shr 128 digest) 0xFFFFFF

    -- FORS+C forced-zero
    let lastIdx := bitAnd (shr 112 digest) 0xFFFF
    require (lastIdx == 0) "FORS+C forced-zero violated"

    -- 7 FORS trees
    forEach "fi" 7 (do
      let treeIdx := bitAnd (shr (mul fi 16) digest) 0xFFFF
      let secretVal := bitAnd (calldataload (add sigBase (add 16 (mul fi 16)))) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
      mstore 0x20 (bitOr (shl 128 3) (bitOr (shl 96 fi) treeIdx))
      mstore 0x40 secretVal
      mstore 0x500 (bitAnd (keccak256 0x00 0x60) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
      mstore 0x520 treeIdx
      let authBase := add sigBase (add 144 (mul fi 256))

      forEach "ah" 16 (do
        let node := mload 0x500
        let pathIdx := mload 0x520
        let sibling := bitAnd (calldataload (add authBase (mul ah 16))) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
        let parentIdx := shr 1 pathIdx
        let treeAdrsBase := bitOr (shl 128 3) (shl 96 fi)
        mstore 0x20 (bitOr treeAdrsBase (bitOr (shl 32 (add ah 1)) parentIdx))
        let bit := bitAnd pathIdx 1
        mstore 0x40 (bitXor node (mul (bitXor node sibling) bit))
        mstore 0x60 (bitXor sibling (mul (bitXor sibling node) bit))
        mstore 0x500 (bitAnd (keccak256 0x00 0x80) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
        mstore 0x520 parentIdx
        pure ())

      mstore (add 0x80 (mul fi 0x20)) (mload 0x500)
      pure ())

    -- Last FORS tree (forced-zero)
    let lastSecret := bitAnd (calldataload (add sigBase (add 16 (mul 7 16)))) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
    mstore 0x20 (bitOr (shl 128 3) (shl 96 7))
    mstore 0x40 lastSecret
    mstore (add 0x80 (mul 7 0x20)) (bitAnd (keccak256 0x00 0x60) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)

    -- Compress 8 FORS roots
    mstore 0x00 seed
    mstore 0x20 (shl 128 4)
    forEach "ri" 8 (do
      mstore (add 0x40 (mul ri 0x20)) (mload (add 0x80 (mul ri 0x20)))
      pure ())
    mstore 0x560 (bitAnd (keccak256 0x00 0x140) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)

    -- Hypertree: 2 layers
    mstore 0x580 htIdx
    mstore 0x5A0 1936

    forEach "layer" 2 (do
      let idxTree := mload 0x580
      let sigOff := mload 0x5A0
      let idxLeaf := bitAnd idxTree 0xFFF
      mstore 0x580 (shr 12 idxTree)

      let wotsAdrs := bitOr (shl 224 layer) (bitOr (shl 160 (mload 0x580)) (shl 96 idxLeaf))
      let countOff := add sigOff 512
      let count := shr 224 (calldataload (add sigBase countOff))

      mstore 0x00 seed
      mstore 0x20 wotsAdrs
      mstore 0x40 (mload 0x560)
      mstore 0x60 count
      let d := keccak256 0x00 0x80

      -- Digit sum
      mstore 0x540 0
      forEach "di" 32 (do
        mstore 0x540 (add (mload 0x540) (bitAnd (shr (mul di 4) d) 0xF))
        pure ())
      require (mload 0x540 == 240) "WOTS+C sum violated"

      -- 32 WOTS chains
      forEach "ci" 32 (do
        let digit := bitAnd (shr (mul ci 4) d) 0xF
        let steps := sub 15 digit
        mstore 0x5C0 (bitAnd (calldataload (add sigBase (add sigOff (mul ci 16)))) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
        let chainAdrs := bitOr wotsAdrs (shl 64 ci)
        mstore 0x5E0 digit

        mstore 0x00 seed
        forEach "step" steps (do
          mstore 0x20 (bitOr (bitAnd chainAdrs 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF) (shl 32 (mload 0x5E0)))
          mstore 0x40 (mload 0x5C0)
          mstore 0x5C0 (bitAnd (keccak256 0x00 0x60) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
          mstore 0x5E0 (add (mload 0x5E0) 1)
          pure ())

        mstore (add 0x80 (mul ci 0x20)) (mload 0x5C0)
        pure ())

      -- PK compression
      let pkAdrs := bitOr (shl 224 layer) (bitOr (shl 160 (mload 0x580)) (bitOr (shl 128 1) (shl 96 idxLeaf)))
      mstore 0x00 seed
      mstore 0x20 pkAdrs
      forEach "pi" 32 (do
        mstore (add 0x40 (mul pi 0x20)) (mload (add 0x80 (mul pi 0x20)))
        pure ())
      let wotsPk := bitAnd (keccak256 0x00 0x440) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

      -- Merkle auth path (12 levels)
      let authOff := add countOff 4
      let treeAdrs := bitOr (shl 224 layer) (bitOr (shl 160 (mload 0x580)) (shl 128 2))
      mstore 0x600 wotsPk
      mstore 0x620 idxLeaf

      forEach "mh" 12 (do
        let mn := mload 0x600
        let mi := mload 0x620
        let mSibling := bitAnd (calldataload (add sigBase (add authOff (mul mh 16)))) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000
        let mParent := shr 1 mi
        mstore 0x20 (bitOr (bitAnd treeAdrs 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000) (bitOr (shl 32 (add mh 1)) mParent))
        let mBit := bitAnd mi 1
        mstore 0x40 (bitXor mn (mul (bitXor mn mSibling) mBit))
        mstore 0x60 (bitXor mSibling (mul (bitXor mSibling mn) mBit))
        mstore 0x600 (bitAnd (keccak256 0x00 0x80) 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
        mstore 0x620 mParent
        pure ())

      mstore 0x560 (mload 0x600)
      mstore 0x5A0 (add authOff (mul 12 16))
      pure ())

    -- Final comparison
    if mload 0x560 == root then
      return 1
    else
      return 0

  function view getPkSeed () : Uint256 := do
    let s ← getStorage pkSeed
    return s

  function view getPkRoot () : Uint256 := do
    let r ← getStorage pkRoot
    return r

end Contracts
