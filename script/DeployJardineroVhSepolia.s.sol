// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/JardinForsCVerifier.sol";
import "../src/JardinAccountFactory.sol";

/// @title DeployJardineroVhSepolia — Deploy variable-h FORS+C verifier + sibling factory
/// @notice Reuses the already-deployed T0 verifier. Emits the new factory address
///         as `factoryVh`. Accounts created through this factory accept Type 2
///         signatures built against slots with any h ∈ [2, 8].
///
/// Existing (fixed-h=7) addresses on Sepolia, kept as historical reference:
///   T0 Verifier      0x188c4Ed44e5e26090D9A46CE2D5c9bD153AD5767
///   FORS+C Verifier  0x4833624a57E59D2f888890ae6B776933c5FF6C68 (fixed h=7)
///   Factory          0xA9a718873E092aAE8170534eeb1ee3615F9E95F0
contract DeployJardineroVhSepolia is Script {
    address constant ENTRYPOINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;
    address constant T0_VERIFIER    = 0x188c4Ed44e5e26090D9A46CE2D5c9bD153AD5767;

    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);

        JardinForsCVerifier forscVh = new JardinForsCVerifier();
        console.log("JARDIN FORS+C Vh Verifier:", address(forscVh));

        JardinAccountFactory factoryVh = new JardinAccountFactory(
            IEntryPoint(ENTRYPOINT_V09),
            T0_VERIFIER,
            address(forscVh)
        );
        console.log("JARDINERO Factory (Vh):", address(factoryVh));

        vm.stopBroadcast();
    }
}
