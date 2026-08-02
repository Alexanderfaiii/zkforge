// ZKForge final prove script
const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const dir = process.argv[2] ? path.resolve(process.argv[2]) : __dirname;
const name = process.argv[3] || 'age_verify';

(async () => {
    console.log('\n  ZKForge — Zero-Knowledge Proof Pipeline');
    console.log('  Circuit: ' + name + '\n');

    const circomFile = path.join(dir, name + '.circom');
    const wasmFile = path.join(dir, name + '.wasm');
    const r1csFile = path.join(dir, name + '.r1cs');
    const zkeyFile = path.join(dir, 'circuit.zkey');
    const vkFile = path.join(dir, 'verification_key.json');
    const inputFile = path.join(dir, 'input.json');
    const proofFile = path.join(dir, 'proof.json');
    const publicFile = path.join(dir, 'public.json');

    // 1. Compile circuit
    console.log('  [1/6] Compiling circom circuit...');
    execSync('circom "' + circomFile + '" --r1cs --wasm -o "' + dir + '"', { stdio: 'pipe' });
    const r1csInfo = execSync('snarkjs r1cs info "' + r1csFile + '"', { encoding: 'utf8' });
    const nConstraints = (r1csInfo.match(/# of Constraints: (\d+)/) || [,'?'])[1];
    const nWires = (r1csInfo.match(/# of Wires: (\d+)/) || [,'?'])[1];
    console.log('       R1CS: ' + fs.statSync(r1csFile).size + ' bytes, ' + nWires + ' wires, ' + nConstraints + ' constraints');

    // 2. Powers of Tau
    console.log('  [2/6] Powers of Tau ceremony...');
    const potFile = path.join(dir, 'pot_final.ptau');
    if (!fs.existsSync(potFile)) {
        const p0 = path.join(dir, 'pot_0.ptau');
        const p1 = path.join(dir, 'pot_1.ptau');
        execSync('snarkjs powersoftau new bn128 8 "' + p0 + '"', { stdio: 'pipe' });
        execSync('snarkjs powersoftau contribute "' + p0 + '" "' + p1 + '" -e="ZKForge"', { stdio: 'pipe' });
        execSync('snarkjs powersoftau prepare phase2 "' + p1 + '" "' + potFile + '"', { stdio: 'pipe' });
        console.log('       Generated fresh');
    } else {
        console.log('       Using cached');
    }

    // 3. Groth16 setup
    console.log('  [3/6] Groth16 setup...');
    execSync('snarkjs groth16 setup "' + r1csFile + '" "' + potFile + '" "' + zkeyFile + '"', { stdio: 'pipe' });
    const vk = await snarkjs.zKey.exportVerificationKey(zkeyFile);
    fs.writeFileSync(vkFile, JSON.stringify(vk, null, 2));
    console.log('       VK exported (nPublic=' + vk.nPublic + ')');

    // 4. FullProve
    console.log('  [4/6] Generating proof...');
    if (!fs.existsSync(inputFile)) {
        console.error('  ERROR: input.json not found at ' + inputFile);
        process.exit(1);
    }
    const input = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmFile, zkeyFile);
    fs.writeFileSync(proofFile, JSON.stringify(proof, null, 2));
    fs.writeFileSync(publicFile, JSON.stringify(publicSignals, null, 2));
    const proofSize = Buffer.byteLength(JSON.stringify(proof));
    console.log('       Proof: ' + proofSize + ' bytes');
    console.log('       Public signals: ' + JSON.stringify(publicSignals));

    // 5. Verify
    console.log('  [5/6] Verifying proof...');
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log('       Result: ' + (ok ? 'PASSED ✅' : 'FAILED ❌'));

    // 6. Solidity
    console.log('  [6/6] Exporting Solidity verifier...');
    const solFile = path.join(dir, name + 'Verifier.sol');
    execSync('snarkjs zkey export solidityverifier "' + zkeyFile + '" "' + solFile + '"', { stdio: 'pipe' });
    const solSize = fs.statSync(solFile).size;
    console.log('       ' + name + 'Verifier.sol (' + solSize + ' bytes)');

    // Summary
    console.log('\n  ═══════════════════════════════════════');
    if (ok) {
        console.log('  ✅ PROOF GENERATED AND VERIFIED');
    } else {
        console.log('  ⚠️  PROOF GENERATED BUT NOT VERIFIED');
    }
    console.log('  📁 Output: ' + dir);
    console.log('     • ' + name + '.circom          — Circuit');
    console.log('     • proof.json                 — Zero-knowledge proof');
    console.log('     • public.json                — Public signals');
    console.log('     • verification_key.json      — Verification key');
    console.log('     • ' + name + 'Verifier.sol   — Solidity verifier');
    console.log('  ═══════════════════════════════════════\n');

    process.exit(ok ? 0 : 1);
})().catch(err => { console.error('Fatal:', err.message); process.exit(1); });
