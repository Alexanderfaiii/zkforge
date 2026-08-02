// ZKForge Deployment Script for Hardhat
// Usage: npx hardhat run scripts/deploy.js --network sepolia

const hre = require("hardhat");

async function main() {
    const Verifier = await hre.ethers.getContractFactory("credit_scoreVerifier");
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    console.log("credit_scoreVerifier deployed to:", await verifier.getAddress());
    console.log("RPC: https://sepolia.infura.io/v3/KEY");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
