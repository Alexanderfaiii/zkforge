const hre = require("hardhat");

async function main() {
    const Shielded = await hre.ethers.getContractFactory("ShieldedToken");
    const shielded = await Shielded.deploy();
    await shielded.waitForDeployment();
    console.log("Deployed to:", await shielded.getAddress());
}

main().catch(console.error);
