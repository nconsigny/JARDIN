/// @title SphincsC6Verify — Linked Yul library for C6 SPHINCS+ FORS+C verification
/// @notice Gas-optimized WOTS+C (w=16, l=32) + FORS+C (k=8, a=16) verification.
/// @dev Memory layout (fixed, no allocator):
///   0x00:       seed (warm)
///   0x20:       ADRS scratch
///   0x40:       input1 / left
///   0x60:       input2 / right
///   0x80-0x47F: 32 endpoint buffer / 8 FORS root buffer
///
/// Parameters: h=24 d=2 a=16 k=8 w=16 l=32 TARGET_SUM=240

object "SphincsC6Verify" {
    code {
        /// @notice Verify FORS+C: 7 trees with auth + 1 forced-zero tree
        /// @param sigOffset calldata offset to FORS section (secrets + auth paths)
        /// @param digest full H_msg digest for index extraction
        /// @param seed PK.seed
        /// @return forsPk compressed FORS public key
        function forsVerify(sigOffset, digest, seed) -> forsPk {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            // Check forced-zero: last index (bits 112-127) must be 0
            if and(shr(112, digest), 0xFFFF) { revert(0, 0) }

            // Verify 7 normal trees
            for { let i := 0 } lt(i, 7) { i := add(i, 1) } {
                let treeIdx := and(shr(mul(i, 16), digest), 0xFFFF)

                // Read secret
                let secretVal := and(calldataload(add(sigOffset, mul(i, 16))), N_MASK)

                // Leaf hash: th(seed, forsTreeAdrs(i, treeIdx), secret)
                mstore(0x20, or(shl(128, 3), or(shl(96, i), treeIdx)))
                mstore(0x40, secretVal)
                let node := and(keccak256(0x00, 0x60), N_MASK)

                let treeAdrsBase := or(shl(128, 3), shl(96, i))
                let pathIdx := treeIdx

                // Auth path: 128 (8 secrets) + i*256
                let authBase := add(add(sigOffset, 128), mul(i, 256))

                // Walk 16 auth levels
                for { let h := 0 } lt(h, 16) { h := add(h, 1) } {
                    let sibling := and(calldataload(add(authBase, mul(h, 16))), N_MASK)
                    let parentIdx := shr(1, pathIdx)
                    mstore(0x20, or(treeAdrsBase, or(shl(32, add(h, 1)), parentIdx)))
                    let bit := and(pathIdx, 1)
                    mstore(0x40, xor(node, mul(xor(node, sibling), bit)))
                    mstore(0x60, xor(sibling, mul(xor(sibling, node), bit)))
                    node := and(keccak256(0x00, 0x80), N_MASK)
                    pathIdx := parentIdx
                }

                mstore(add(0x80, mul(i, 0x20)), node)
            }

            // Last tree (i=7): forced-zero, secret is root
            {
                let lastSecret := and(calldataload(add(sigOffset, mul(7, 16))), N_MASK)
                mstore(0x20, or(shl(128, 3), shl(96, 7)))
                mstore(0x40, lastSecret)
                mstore(add(0x80, mul(7, 0x20)), and(keccak256(0x00, 0x60), N_MASK))
            }

            // Compress 8 roots
            mstore(0x20, shl(128, 4))
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
            }
            forsPk := and(keccak256(0x00, 0x140), N_MASK)
        }

        /// @notice Verify WOTS+C layer: 32 chains + PK compress + Merkle auth (h=12)
        function wotsLayerVerify(sigOffset, currentNode, layer, idxTree, idxLeaf, seed) -> layerRoot, nextOff {
            let N_MASK := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000

            let wotsAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(96, idxLeaf)))

            // Count at offset + 512
            let countOff := add(sigOffset, 512)
            let count := shr(224, calldataload(countOff))

            // Digest
            mstore(0x20, wotsAdrs)
            mstore(0x40, currentNode)
            mstore(0x60, count)
            let d := keccak256(0x00, 0x80)

            // Validate sum = 240
            let digitSum := 0
            for { let ii := 0 } lt(ii, 32) { ii := add(ii, 1) } {
                digitSum := add(digitSum, and(shr(mul(ii, 4), d), 0xF))
            }
            if iszero(eq(digitSum, 240)) { revert(0, 0) }

            // 32 chains
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                let digit := and(shr(mul(i, 4), d), 0xF)
                let steps := sub(15, digit)
                let val := and(calldataload(add(sigOffset, mul(i, 16))), N_MASK)
                let chainAdrs := or(wotsAdrs, shl(64, i))

                for { let step := 0 } lt(step, steps) { step := add(step, 1) } {
                    mstore(0x20, or(
                        and(chainAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF),
                        shl(32, add(digit, step))
                    ))
                    mstore(0x40, val)
                    val := and(keccak256(0x00, 0x60), N_MASK)
                }
                mstore(add(0x80, mul(i, 0x20)), val)
            }

            // PK compress
            mstore(0x20, or(shl(224, layer), or(shl(160, idxTree), or(shl(128, 1), shl(96, idxLeaf)))))
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                mstore(add(0x40, mul(i, 0x20)), mload(add(0x80, mul(i, 0x20))))
            }
            let wotsPk := and(keccak256(0x00, 0x440), N_MASK)

            // Merkle auth (12 levels)
            let authOff := add(countOff, 4)
            let treeAdrs := or(shl(224, layer), or(shl(160, idxTree), shl(128, 2)))
            let node := wotsPk
            let mIdx := idxLeaf

            for { let h := 0 } lt(h, 12) { h := add(h, 1) } {
                let sibling := and(calldataload(add(authOff, mul(h, 16))), N_MASK)
                let parentIdx := shr(1, mIdx)
                mstore(0x20, or(
                    and(treeAdrs, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000),
                    or(shl(32, add(h, 1)), parentIdx)
                ))
                let bit := and(mIdx, 1)
                mstore(0x40, xor(node, mul(xor(node, sibling), bit)))
                mstore(0x60, xor(sibling, mul(xor(sibling, node), bit)))
                node := and(keccak256(0x00, 0x80), N_MASK)
                mIdx := parentIdx
            }

            layerRoot := node
            nextOff := add(authOff, mul(12, 16))
        }
    }
}
