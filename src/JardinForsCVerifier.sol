// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardinForsCVerifier — variable-height FORS+C verifier
/// @dev JARDÍN compact path variant 2: k=26, a=5, n=16 bytes (128-bit).
///      Verifies FORS+C signature and walks a balanced Merkle tree of
///      height h ∈ [2, 8] up to pkRoot. h is inferred from the signature
///      length (no extra wire byte):
///
///          h = (sig.length - 2453) / 16
///          valid iff 2 ≤ h ≤ 8 and (sig.length - 2453) % 16 == 0
///
///      Signature layout:
///        R(32) | counter(4) | 25 × (secret 16B + auth 5×16B) | lastRoot(16)
///        | q(1) | merkleAuth(h × 16)
///
///      For h=7 the behaviour and gas profile match the earlier fixed-h
///      verifier byte-for-byte (all loop bounds resolve to identical
///      constants).
contract JardinForsCVerifier {

    function verifyForsC(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig
    ) external pure returns (bool valid) {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // ── Infer h from sig length, validate shape ──
            //   sig.length == 2452 (body) + 1 (q) + 16 * h
            //   → h = (sig.length - 2453) / 16, must be in [2, 8]
            if lt(sig.length, 2485) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }
            let merkleBytes := sub(sig.length, 2453)
            if and(merkleBytes, 15) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }
            let hh := shr(4, merkleBytes)
            if gt(hh, 8) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }

            let seed := pkSeed
            let root := pkRoot
            let sigBase := sig.offset

            // ── Read explicit 1-byte q at offset 2452 (after FORSC_BODY) ──
            let q := shr(248, calldataload(add(sigBase, 2452)))
            // q ∈ [1, 2^h]; shl(hh, 1) = 2^h ≤ 256 for h ≤ 8, fits in a byte.
            if or(iszero(q), gt(q, shl(hh, 1))) { revert(0, 0) }
            let leafIdx := sub(q, 1)

            // ── H_msg (192 bytes): seed || root || R || message || counter || domain ──
            mstore(0x00, seed)
            mstore(0x20, root)
            mstore(0x40, calldataload(sigBase))                    // R (32 bytes)
            mstore(0x60, message)
            mstore(0x80, shr(224, calldataload(add(sigBase, 32)))) // counter (4B)
            mstore(0xA0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            let dVal := keccak256(0x00, 0xC0)

            // ── Forced-zero: tree 25 index (bits 125-129) must be 0 ──
            if and(shr(125, dVal), 0x1F) { revert(0, 0) }

            // ── FORS+C verification: K=26, A=5, K-1=25 normal trees ──
            // ADRS convention (FIPS 205): kp=0, ci=q, x=treeHeight, y=continuous
            // index across all k trees. For tree i at height z with local parent
            // index p, global y = (i << (A - z)) | p.
            let forsBase := add(sigBase, 36)
            let adrsForsCq := or(shl(128, 3), shl(64, q))

            for { let i := 0 } lt(i, 25) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 5), dVal), 0x1F)

                let treeOff := add(forsBase, mul(i, 96))
                let secretVal := and(calldataload(treeOff), N_MASK)

                // Leaf ADRS: x=0, y = (i << 5) | treeIdx
                mstore(0x20, or(adrsForsCq, or(shl(5, i), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := treeIdx
                let authPtr := add(treeOff, 16)

                for { let h := 0 } lt(h, 5) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, h))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // Height = h+1; global y = (i << (4-h)) | parentIdx
                    let globalY := or(shl(sub(4, h), i), parentIdx)
                    mstore(0x20, or(adrsForsCq, or(shl(32, add(h, 1)), globalY)))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                mstore(add(0x80, shl(5, i)), node)
            }

            // ── Last tree (tree 25, forced-zero): hash the provided root ──
            // Leaf ADRS: x=0, y = 25 << 5 = 800
            {
                let lastRootOff := add(forsBase, 2400)
                let lastRootVal := and(calldataload(lastRootOff), N_MASK)
                mstore(0x20, or(adrsForsCq, shl(5, 25)))
                mstore(0x40, lastRootVal)
                mstore(0x3A0, and(keccak256(0x00, 0x60), N_MASK))
            }

            // ── Compress 26 FORS roots ──
            mstore(0x20, or(shl(128, 4), shl(64, q)))
            for { let i := 0 } lt(i, 26) { i := add(i, 1) } {
                mstore(add(0x40, shl(5, i)), mload(add(0x80, shl(5, i))))
            }
            let forsPk := and(keccak256(0x00, 0x380), N_MASK)

            // ── Balanced Merkle walk (h levels, runtime-determined) ──
            // Auth path at sigBase + 2453 (after 2452-byte body + 1 byte q)
            // Type=16 JARDIN_MERKLE, x=level, y=parentIndex, ci=0, kp=0
            let authStart := add(sigBase, 2453)
            let adrsMerkle := shl(128, 16)
            let merkleNode := forsPk
            let hminus1 := sub(hh, 1)

            for { let j := 0 } lt(j, hh) { j := add(j, 1) } {
                let sibling := and(calldataload(add(authStart, shl(4, j))), N_MASK)
                let level := sub(hminus1, j)
                let parentIdx := shr(add(j, 1), leafIdx)
                mstore(0x20, or(adrsMerkle, or(shl(32, level), parentIdx)))
                // L/R ordering from bit j of leafIdx: 0 → node left, 1 → node right
                let s := shl(5, and(shr(j, leafIdx), 1))
                mstore(xor(0x40, s), merkleNode)
                mstore(xor(0x60, s), sibling)
                merkleNode := and(keccak256(0x00, 0x80), N_MASK)
            }

            // ── Final root comparison ──
            valid := eq(merkleNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
