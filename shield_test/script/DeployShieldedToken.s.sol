// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/ShieldedToken.sol";

contract DeployShieldedToken is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerKey);
        
        ShieldedToken shielded = new ShieldedToken();
        
        console.log("Shielded contract deployed at:", address(shielded));
        
        vm.stopBroadcast();
    }
}
