// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/JardinForsPlainVerifier.sol";

contract JardinForsPlainTest is Test {
    JardinForsPlainVerifier verifier;

    // Message used by the signer CLI (matches jardin_fors_plain_signer default entropy)
    bytes32 constant MSG = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;

    function setUp() public {
        verifier = new JardinForsPlainVerifier();
    }

    function _sign(string memory q, string memory h) internal returns (bytes32, bytes32, bytes memory) {
        string[] memory inputs = new string[](5);
        inputs[0] = ".venv/bin/python";
        inputs[1] = "script/jardin_fors_plain_signer.py";
        inputs[2] = vm.toString(MSG);
        inputs[3] = q;
        inputs[4] = h;
        return abi.decode(vm.ffi(inputs), (bytes32, bytes32, bytes));
    }

    function _verifySilent(bytes32 seed, bytes32 root, bytes32 msg_, bytes memory sig)
        internal view returns (bool ok)
    {
        (bool call_ok, bytes memory res) = address(verifier).staticcall(
            abi.encodeWithSelector(verifier.verifyForsPlain.selector, seed, root, msg_, sig)
        );
        if (!call_ok || res.length < 32) return false;
        ok = abi.decode(res, (bool));
    }

    // ── Happy path at each supported h ──

    function testH2() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("1", "2");
        assertEq(sig.length, 2625, "h=2 length");
        assertTrue(_verifySilent(seed, root, MSG, sig));
    }

    function testH4_target2657() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("1", "4");
        assertEq(sig.length, 2657, "h=4 length must be 2657");
        assertTrue(_verifySilent(seed, root, MSG, sig));
    }

    function testH4_qMax() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("16", "4");
        assertEq(sig.length, 2657);
        assertTrue(_verifySilent(seed, root, MSG, sig));
    }

    function testH7() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("64", "7");
        assertEq(sig.length, 2705);
        assertTrue(_verifySilent(seed, root, MSG, sig));
    }

    function testH8() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("1", "8");
        assertEq(sig.length, 2721);
        assertTrue(_verifySilent(seed, root, MSG, sig));
    }

    function testGas_h4() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("1", "4");
        uint256 before_ = gasleft();
        verifier.verifyForsPlain(seed, root, MSG, sig);
        emit log_named_uint("FORS-plain verify gas (h=4, memory sig)", before_ - gasleft());
    }

    // ── Rejections ──

    function testRejectsWrongMsg() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("1", "4");
        assertFalse(_verifySilent(seed, root, bytes32(uint256(MSG) ^ 1), sig));
    }

    function testRejectsWrongSeed() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("1", "4");
        assertFalse(_verifySilent(bytes32(uint256(seed) ^ (1 << 200)), root, MSG, sig));
    }

    function testRejectsWrongRoot() public {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("1", "4");
        assertFalse(_verifySilent(seed, bytes32(uint256(root) ^ (1 << 200)), MSG, sig));
    }

    function testRejectsShortSig() public {
        bytes memory bad = new bytes(2624);  // below h=2 minimum
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verifyForsPlain(bytes32(0), bytes32(0), MSG, bad);
    }

    function testRejectsUnalignedLength() public {
        bytes memory bad = new bytes(2658);  // 2657 + 1 is not aligned
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verifyForsPlain(bytes32(0), bytes32(0), MSG, bad);
    }

    function testRejectsH9() public {
        bytes memory bad = new bytes(2737);  // 2593 + 9·16 = h=9, out of range
        vm.expectRevert(bytes("Invalid sig length"));
        verifier.verifyForsPlain(bytes32(0), bytes32(0), MSG, bad);
    }

    function _tamperFails(uint256 offset) internal {
        (bytes32 seed, bytes32 root, bytes memory sig) = _sign("1", "4");
        bytes memory t = new bytes(sig.length);
        for (uint256 i = 0; i < sig.length; i++) t[i] = sig[i];
        t[offset] = bytes1(uint8(t[offset]) ^ 0x01);
        assertFalse(_verifySilent(seed, root, MSG, t), "tampered sig must not verify");
    }

    function testTamperR()           public { _tamperFails(8); }
    function testTamperForsSecret()  public { _tamperFails(32 + 8); }        // inside sk_0
    function testTamperForsAuth()    public { _tamperFails(32 + 16 + 12); }  // inside auth_0 level 0
    function testTamperQ()           public { _tamperFails(2592); }          // q byte
    function testTamperMerkleAuth()  public { _tamperFails(2593 + 8); }      // first outer-auth node
}
