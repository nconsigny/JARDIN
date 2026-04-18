// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/JardinForsCVerifier.sol";

contract JardinForsCVariableHTest is Test {
    JardinForsCVerifier verifier;

    bytes32 constant MSG =
        0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
    string constant MSG_HEX =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    function setUp() public {
        verifier = new JardinForsCVerifier();
    }

    function _sign(uint256 q, uint256 h) internal returns (bytes32, bytes32, bytes memory) {
        string[] memory inputs = new string[](5);
        inputs[0] = "python3";
        inputs[1] = "script/jardin_signer.py";
        inputs[2] = MSG_HEX;
        inputs[3] = vm.toString(q);
        inputs[4] = vm.toString(h);
        bytes memory result = vm.ffi(inputs);
        return abi.decode(result, (bytes32, bytes32, bytes));
    }

    function _expectedLen(uint256 h) internal pure returns (uint256) {
        return 2452 + 1 + h * 16;
    }

    // ── Happy path: h ∈ {2, 3, 5, 7, 8} ──
    function testH2_q1() public              { _roundtrip(1, 2); }
    function testH2_qMax() public            { _roundtrip(4, 2); }
    function testH3_qMax() public            { _roundtrip(8, 3); }
    function testH5_q1() public              { _roundtrip(1, 5); }
    function testH5_qMax() public            { _roundtrip(32, 5); }
    function testH7_qRightEdge() public      { _roundtrip(128, 7); }
    function testH8_q1() public              { _roundtrip(1, 8); }

    function _roundtrip(uint256 q, uint256 h) internal {
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = _sign(q, h);
        assertEq(sig.length, _expectedLen(h), "sig length");
        bool ok = verifier.verifyForsC(pkSeed, pkRoot, MSG, sig);
        assertTrue(ok, "verify failed");
        // Measure gas with the label pre-built, so only verifyForsC is timed.
        string memory label = string.concat("gas h=", vm.toString(h), " q=", vm.toString(q));
        uint256 g0 = gasleft();
        verifier.verifyForsC(pkSeed, pkRoot, MSG, sig);
        uint256 used = g0 - gasleft();
        emit log_named_uint(label, used);
    }

    // ── Reject: h=1 (too small) and h=9 (too big) ──
    function testRejectsH1Length() public {
        // Start from a valid h=2 sig and strip 16 bytes off the end.
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig2) = _sign(1, 2);
        bytes memory sig1 = new bytes(sig2.length - 16);
        for (uint256 i = 0; i < sig1.length; i++) sig1[i] = sig2[i];
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verifyForsC(pkSeed, pkRoot, MSG, sig1);
    }

    function testRejectsH9Length() public {
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig8) = _sign(1, 8);
        // Pad to h=9 size (add 16 bytes of zeros at the end)
        bytes memory sig9 = new bytes(sig8.length + 16);
        for (uint256 i = 0; i < sig8.length; i++) sig9[i] = sig8[i];
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verifyForsC(pkSeed, pkRoot, MSG, sig9);
    }

    // ── Reject: non-16-aligned auth-path length (off by 1) ──
    function testRejectsUnalignedLength() public {
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = _sign(1, 5);
        bytes memory bad = new bytes(sig.length + 1);
        for (uint256 i = 0; i < sig.length; i++) bad[i] = sig[i];
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verifyForsC(pkSeed, pkRoot, MSG, bad);
    }

    // ── h=7 byte-for-byte regression (smoke): same Python produces
    //     the same-length sig, and it still verifies. The Yul verifier
    //     took the identical code path (hh==7 ⇒ loop bound and level
    //     constants match the old contract), so this constitutes the
    //     regression check the spec asks for.
    function testH7Regression() public {
        (bytes32 pkSeed, bytes32 pkRoot, bytes memory sig) = _sign(1, 7);
        assertEq(sig.length, 2565, "h=7 sig must be 2565 bytes");
        assertTrue(verifier.verifyForsC(pkSeed, pkRoot, MSG, sig));
    }
}
