// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title JardinForsPlainVerifier — plain FORS compact-path verifier (variable h)
/// @dev Replaces FORS+C as JARDÍN Type 2. Parameters: k=32, a=4, n=16 bytes
///      (128-bit). All k FORS trees are revealed with real secrets + auth
///      paths; there is no counter grinding and no forced-zero tree. The outer
///      balanced Merkle tree of FORS public keys has variable height h ∈ [2, 8],
///      inferred from the signature length with no extra wire byte:
///
///          h = (sig.length - 2593) / 16
///          valid iff 2 ≤ h ≤ 8 and (sig.length - 2593) % 16 == 0
///
///      Signature layout (2593 + 16·h bytes):
///        R(32) | K=32 × (secret 16B + auth 4×16B) = 2560 | q(1) | merkleAuth(h × 16)
///
///      ADRS convention (32-byte FIPS-205 packed, matches JardinForsCVerifier):
///        layer(4)‖tree(8)‖type(4)‖kp(4)‖ci=q(4)‖cp=height(4)‖ha=y(4)
///        FORS_TREE    (type=3) — leaves and internal nodes, global y across k trees
///        FORS_ROOTS   (type=4) — compression of the k roots
///        JARDIN_MERKLE(type=16) — outer balanced tree
///
///      H_msg (160 bytes, no counter — plain FORS skips grinding):
///        keccak256(seed || root || R || msg || 0xFF..FD)
///      Domain 0xFF..FD is distinct from C11 (FF..FF), T0 (FF..FE), and the
///      192-byte FORS+C H_msg (which is structurally different — with counter).
contract JardinForsPlainVerifier {

    function verifyForsPlain(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig
    ) external pure returns (bool valid) {
        assembly ("memory-safe") {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // ── Infer h from sig length, validate shape ──
            //   sig.length == 2593 + 16·h, h ∈ [2, 8]
            if lt(sig.length, 2625) {
                mstore(0x00, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(0x04, 0x20)
                mstore(0x24, 18)
                mstore(0x44, "Invalid sig length")
                revert(0x00, 0x64)
            }
            let merkleBytes := sub(sig.length, 2593)
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

            // ── Read explicit 1-byte q at offset 2592 (after R + FORS body) ──
            let q := shr(248, calldataload(add(sigBase, 2592)))
            if or(iszero(q), gt(q, shl(hh, 1))) { revert(0, 0) }
            let leafIdx := sub(q, 1)

            // ── H_msg (160 bytes): seed || root || R || message || domain ──
            mstore(0x00, seed)
            mstore(0x20, root)
            mstore(0x40, calldataload(sigBase))                    // R (32 bytes, full word)
            mstore(0x60, message)
            mstore(0x80, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD)
            let dVal := keccak256(0x00, 0xA0)

            // ── Plain FORS verification: K=32, A=4 ──
            // adrsForsQ: type=3 (FORS_TREE), ci=q (other fields zero)
            let forsBase := add(sigBase, 32)
            let adrsForsQ := or(shl(128, 3), shl(64, q))

            for { let t := 0 } lt(t, 32) { t := add(t, 1) } {
                // md[t] = (dVal >> t*4) & 0xF  — LSB-first, matches FORS+C convention
                let mdT := and(shr(shl(2, t), dVal), 0xF)

                let treeOff := add(forsBase, mul(t, 80))  // 80 = sk(16) + auth(4×16)
                let secretVal := and(calldataload(treeOff), N_MASK)

                // Leaf ADRS: cp=0 (leaf), ha = (t << 4) | mdT  — global y across 32 trees
                mstore(0x20, or(adrsForsQ, or(shl(4, t), mdT)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let pathIdx := mdT
                let authPtr := add(treeOff, 16)

                // Climb A=4 auth levels
                for { let hh2 := 0 } lt(hh2, 4) { hh2 := add(hh2, 1) } {
                    let sibling := and(calldataload(add(authPtr, shl(4, hh2))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    // Height = hh2+1; global y = (t << (3-hh2)) | parentIdx
                    let globalY := or(shl(sub(3, hh2), t), parentIdx)
                    mstore(0x20, or(adrsForsQ, or(shl(32, add(hh2, 1)), globalY)))
                    let s := shl(5, and(pathIdx, 1))
                    mstore(xor(0x40, s), node)
                    mstore(xor(0x60, s), sibling)
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }
                // Stash root at 0x80 + t*0x20
                mstore(add(0x80, shl(5, t)), node)
            }

            // ── Compress 32 FORS roots: keccak(seed || FORS_ROOTS adrs || roots[0..31]) ──
            // total = 32 + 32 + 32 × 32 = 1088 = 0x440
            mstore(0x20, or(shl(128, 4), shl(64, q)))
            for { let t := 0 } lt(t, 32) { t := add(t, 1) } {
                mstore(add(0x40, shl(5, t)), mload(add(0x80, shl(5, t))))
            }
            let forsPk := and(keccak256(0x00, 0x440), N_MASK)

            // ── Balanced outer Merkle walk (hh levels, runtime-determined) ──
            let authStart := add(sigBase, 2593)
            let adrsMerkle := shl(128, 16)
            let merkleNode := forsPk
            let hminus1 := sub(hh, 1)

            for { let j := 0 } lt(j, hh) { j := add(j, 1) } {
                let sibling := and(calldataload(add(authStart, shl(4, j))), N_MASK)
                let level := sub(hminus1, j)
                let parentIdx := shr(add(j, 1), leafIdx)
                mstore(0x20, or(adrsMerkle, or(shl(32, level), parentIdx)))
                let s := shl(5, and(shr(j, leafIdx), 1))
                mstore(xor(0x40, s), merkleNode)
                mstore(xor(0x60, s), sibling)
                merkleNode := and(keccak256(0x00, 0x80), N_MASK)
            }

            valid := eq(merkleNode, root)
            mstore(0x00, valid)
            return(0x00, 0x20)
        }
    }
}
