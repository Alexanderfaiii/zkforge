// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/ShieldedVault.sol";

contract DeployShieldedVault is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);
        
        ShieldedVault shielded = new ShieldedVault();
        
        console.log("Shielded contract deployed at:", address(shielded));
        
        vm.stopBroadcast();
    }
}
