// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/JardineroFrameAccount.sol";
import "../src/JardinAccount.sol";
import "../src/JardinAccountFactory.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

/// Regression suite for the 2026-07-31 account-layer security fixes
/// (Phase 0 drift audit, V2-PHASE01-REPORT.md items #2, #3, #4, and the
/// rotateVerifiers addition). Proves the guards actually block the attacks.
contract JardinAccountAccessControlTest is Test {
    // Canonical 16-byte keys: value in the high 16 bytes, low 128 bits zero.
    bytes32 constant SEED = bytes32(uint256(0xA11CE) << 128);
    bytes32 constant ROOT = bytes32(uint256(0xB0B) << 128);
    // Non-canonical: dirty low bits — must be rejected everywhere.
    bytes32 constant DIRTY = bytes32(uint256(0xDEAD));

    address constant ATTACKER = address(0xBAD);
    address constant SPXV = address(0x5B0);
    address constant FORSV = address(0xF0F);

    JardineroFrameAccount frame;

    function setUp() public {
        frame = new JardineroFrameAccount(SPXV, FORSV, SEED, ROOT, address(this));
    }

    // ── Frame account: SENDER-only guards (items #2, #3) ──

    function testExecuteRejectsNonSelf() public {
        vm.deal(address(frame), 1 ether);
        vm.prank(ATTACKER);
        vm.expectRevert(JardineroFrameAccount.NotSelf.selector);
        frame.execute(ATTACKER, 1 ether, "");
    }

    function testRegisterSlotRejectsNonSelf() public {
        vm.prank(ATTACKER);
        vm.expectRevert(JardineroFrameAccount.NotSelf.selector);
        frame.registerSlot(bytes16(uint128(1)), bytes16(uint128(2)));
    }

    function testExecuteSucceedsFromSelf() public {
        vm.deal(address(frame), 1 ether);
        vm.prank(address(frame));
        frame.execute(ATTACKER, 0.5 ether, "");
        assertEq(ATTACKER.balance, 0.5 ether);
    }

    function testRegisterSlotSucceedsFromSelf() public {
        bytes16 s = bytes16(uint128(1));
        bytes16 r = bytes16(uint128(2));
        vm.prank(address(frame));
        frame.registerSlot(s, r);
        assertEq(frame.slots(keccak256(abi.encodePacked(s, r))), 1);
    }

    // ── Canonical-key enforcement (item #4) ──

    function testFrameConstructorRejectsNonCanonical() public {
        vm.expectRevert(JardineroFrameAccount.NonCanonicalKey.selector);
        new JardineroFrameAccount(SPXV, FORSV, DIRTY, ROOT, address(this));
    }

    function testFrameRotateRejectsNonCanonical() public {
        vm.prank(address(frame));
        vm.expectRevert(JardineroFrameAccount.NonCanonicalKey.selector);
        frame.rotateSpxKeys(SEED, DIRTY);
    }

    // ── 4337 account: canonical enforcement + rotateVerifiers (item #4, risk #1) ──

    function testAccountConstructorRejectsNonCanonical() public {
        JardinAccountFactory factory = new JardinAccountFactory(
            IEntryPoint(address(0xdead)), SPXV, FORSV
        );
        vm.expectRevert(JardinAccount.NonCanonicalKey.selector);
        factory.createAccount(address(this), DIRTY, ROOT);
    }

    function testRotateVerifiersSelfGated() public {
        JardinAccountFactory factory = new JardinAccountFactory(
            IEntryPoint(address(0xdead)), SPXV, FORSV
        );
        JardinAccount acct = factory.createAccount(address(this), SEED, ROOT);

        vm.prank(ATTACKER);
        vm.expectRevert(JardinAccount.NotEntryPoint.selector);
        acct.rotateVerifiers(ATTACKER, ATTACKER);

        vm.prank(address(acct));
        acct.rotateVerifiers(address(0x111), address(0x222));
        assertEq(acct.spxVerifier(), address(0x111));
        assertEq(acct.forsVerifier(), address(0x222));
    }
}
