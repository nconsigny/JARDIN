// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/JardinSpxVerifier.sol";
import "../src/JardinForsPlainVerifier.sol";
import "../src/JardinAccountFactory.sol";

/// @title DeployJardineroSepolia — Deploy JARDINERO stack on Sepolia
/// @notice SPX verifier (primary, plain SPHINCS+) + plain-FORS verifier (compact) + factory.
///         C11 remains available as optional recovery — attached per-account
///         via JardinAccount.attachC11Recovery, not at factory level.
///
/// Run: forge script script/DeployJardineroSepolia.s.sol --rpc-url sepolia --broadcast
contract DeployJardineroSepolia is Script {
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        JardinSpxVerifier spxVerifier = new JardinSpxVerifier();
        console.log("JARDIN SPX Verifier:", address(spxVerifier));

        JardinForsPlainVerifier forsVerifier = new JardinForsPlainVerifier();
        console.log("JARDIN FORS-plain Verifier:", address(forsVerifier));

        JardinAccountFactory factory = new JardinAccountFactory(
            IEntryPoint(ENTRYPOINT_V09),
            address(spxVerifier),
            address(forsVerifier)
        );
        console.log("JARDIN Factory:", address(factory));

        vm.stopBroadcast();
    }
}
