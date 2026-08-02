// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RecursiveProofVerifier {
    address constant PAIRING = address(0x08);

    function verify(bytes calldata proof, uint256[] calldata pub) external view returns (bool) {
        require(pub.length >= 2, 'too few');
        require(proof.length >= 192, 'short');
        bytes memory inp = new bytes(384);
        for (uint i=0; i<192; i++) inp[i] = proof[i];
        for (uint i=0; i<192; i++) inp[192+i] = proof[192+i];
        (bool ok, bytes memory r) = PAIRING.staticcall(inp);
        require(ok && r.length==32, 'fail');
        return r[31] == 0x01;
    }
    function estGas(uint256) external pure returns (uint256) { return 170000; }
}
