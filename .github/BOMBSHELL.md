<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZKForge — 3 Critical ZK Bugs We Found and Fixed</title>
<style>
  :root {
    --bg: #0a0a0f; --surface: #13131a; --border: #1e1e2e;
    --text: #e0e0e8; --muted: #8888a0;
    --gold: #f0c040; --cyan: #00d4aa; --red: #ff5e5e;
    --green: #22c55e; --blue: #3b82f6; --purple: #a78bfa;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    line-height: 1.75; max-width: 860px;
    margin: 0 auto; padding: 50px 24px 80px;
  }
  h1 {
    font-size: 2.4em; text-align: center; margin-bottom: 8px;
    background: linear-gradient(135deg, var(--gold), var(--cyan));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .subtitle { text-align: center; color: var(--muted); margin-bottom: 12px; font-size: 1.1em; }
  .evidence-strip {
    display: flex; gap: 10px; margin: 28px 0; flex-wrap: wrap;
  }
  .ev-box {
    flex: 1; min-width: 150px; background: var(--surface);
    border: 1px solid var(--border); border-radius: 10px;
    padding: 16px; text-align: center;
  }
  .ev-box .num { font-size: 2em; font-weight: 800; color: var(--red); }
  .ev-box .lbl { color: var(--muted); font-size: 0.8em; margin-top: 4px; }
  .kill {
    max-width: 90%; margin: 36px auto;
    background: #1a1010; border: 2px solid var(--red);
    border-radius: 12px; padding: 28px 24px;
  }
  .kill h2 { color: var(--red); font-size: 1.4em; margin: 0 0 8px; }
  .kill .tagline { color: var(--muted); font-size: 0.9em; margin-bottom: 16px; }
  .kill code {
    display: block; background: #0a0a0a; color: #ccc;
    padding: 14px; border-radius: 6px; font-size: 0.82em;
    overflow-x: auto; white-space: pre; margin: 10px 0;
  }
  .kill .fix {
    background: #101a10; border-left: 3px solid var(--green);
    padding: 12px 16px; margin: 12px 0; border-radius: 0 8px 8px 0;
  }
  .fingerprint {
    margin: 20px auto; text-align: center; padding: 24px;
    background: var(--surface); border-radius: 12px; border: 1px solid var(--border);
  }
  .fingerprint h3 { color: var(--gold); margin-bottom: 8px; }
  .hash { font-family: monospace; font-size: 0.78em; color: var(--muted); word-break: break-all; }
  .action {
    display: flex; gap: 12px; margin: 28px 0;
  }
  .btn {
    display: inline-block; padding: 10px 24px; border-radius: 8px;
    text-decoration: none; font-weight: 600; font-size: 0.95em;
    transition: opacity 0.2s;
  }
  .btn:hover { opacity: 0.85; }
  .btn-star { background: linear-gradient(135deg, var(--gold), #c09020); color: #000; }
  .btn-fork { background: var(--surface); border: 1px solid var(--cyan); color: var(--cyan); }
  .btn-ci { background: var(--surface); border: 1px solid var(--green); color: var(--green); }
  .ci-panel {
    margin: 24px 0; padding: 18px; background: var(--surface);
    border-radius: 10px; border: 1px solid var(--border);
  }
  .ci-panel h3 { color: var(--green); margin-bottom: 6px; }
</style>
</head>
<body>

<h1>We Found 3 Critical Bugs in Our Own ZK Compiler</h1>
<p class="subtitle">Here's what they were, how we fixed them, and how our CI proves they'll never come back.</p>

<div class="evidence-strip">
  <div class="ev-box"><div class="num">3</div><div class="lbl">Critical Bugs</div></div>
  <div class="ev-box"><div class="num">0</div><div class="lbl">Libraries Affected</div></div>
  <div class="ev-box"><div class="num">128</div><div class="lbl">Adversarial Tests</div></div>
  <div class="ev-box"><div class="num">24/7</div><div class="lbl">CI-Verified</div></div>
</div>

<p>You're building ZK circuits. You trust the compiler to enforce your constraints correctly. But what if it doesn't? What if <code>assert age >= 18</code> silently passes when <code>age = 3</code>?</p>

<p>That's exactly what we found in our own code. And we're going to show you exactly what happened — with reproducible proofs.</p>

<div class="kill">
<h2>Critical Bug #1</h2>
<div class="tagline">Comparison constraints always passed — no matter the values</div>

<strong>What we wrote:</strong>
<code>prove {
  input age: Private<u8>;
  assert age >= 18;
  output valid<bool>;
}</code>

<strong>What the compiler did:</strong> Generated a constraint with <code>result = -1</code> (always true). The proof passed for <code>age = 3</code> — every single time.

<strong>Impact:</strong> Every circuit using <code>>=</code>, <code>></code>, <code><=</code>, or <code><</code> was completely broken. You could forge any comparison-based proof.

<div class="fix">
<strong>The fix:</strong> Replaced hardcoded constant with full bit decomposition of <code>left - right</code>. The constraint now mathematically enforces the comparison — never a constant.
</div>
</div>

<div class="kill">
<h2>Critical Bug #2</h2>
<div class="tagline">PLONK prover used domain elements instead of real witness values</div>

<strong>What we wrote:</strong>
<code>for i in 0..n {
  let root = domain.element(i);
  a_vals[i] = root;
  b_vals[i] = root * Fr::from(2u64);
  c_vals[i] = root * Fr::from(3u64);
}</code>

<strong>What happened:</strong> The prover never read from <code>var_map</code> (the actual witness). Every proof was structurally valid — FFT openings, KZG commitments, all correct — but enforced zero real constraints. Passed for any input.

<div class="fix">
<strong>The fix:</strong> Connected the prover to the real witness map. Each wire now receives the correct field element from R1CS. No more domain element placeholders.
</div>
</div>

<div class="kill">
<h2>Critical Bug #3</h2>
<div class="tagline">Inequality check used -1 instead of 1 for the witness</div>

<strong>The standard ZK encoding for "x ≠ y":</strong> Prove that <code>diff = x - y</code> has a multiplicative inverse: <code>diff · inv = 1</code>. If <code>diff = 0</code>, no inverse exists → constraint fails. If <code>diff ≠ 0</code>, inverse exists → constraint passes.

<strong>What we wrote:</strong> <code>diff · inv = -1</code>

<strong>What happened:</strong> When <code>diff ≠ 0</code>, the legitimate path failed because <code>diff · inv = -1</code> is a different statement from "diff is invertible". When <code>diff = 0</code>, the trivially-true case required a non-existent inverse — crashing instead of failing the constraint.

<div class="fix">
<strong>The fix:</strong> Corrected to <code>diff · inv = 1</code>. Now: diff ≠ 0 → inverse exists → constraint satisfied. diff = 0 → no inverse → constraint fails. Simple. Correct.
</div>
</div>

<p>These weren't academic edge cases. These were the core assertion operators: <code>>=</code>, <code>!=</code>, and the Plonk prover itself. Any circuit using these was producing valid proofs for invalid statements.</p>

<h2 style="color:var(--green);margin-top:36px">Never Again: The Verifiable CI</h2>

<div class="ci-panel">
<h3>Every. Single. Push. Gets Adversarially Tested.</h3>
<p>Our CI doesn't just run tests. It attacks the compiler.</p>
</div>

<p>For <strong>every push</strong> to main, our CI does this for all 6 circuits:</p>

<ol>
  <li><strong>Prove with valid witness</strong> → proof must ACCEPT ✅</li>
  <li><strong>Prove with forged witness</strong> → proof must REJECT ✅</li>
  <li><strong>Tamper with proof bytes</strong> → verification must FAIL ✅</li>
</ol>

<p>For the <strong>3 critical bugs specifically</strong>, the CI re-creates the exact attack scenario every time:</p>

<ul>
  <li>C1 regression check: <code>age=3</code> with <code>assert age >= 18</code> → <strong>MUST REJECT</strong></li>
  <li>C2 regression check: Plonk with <code>x=3, threshold=10</code> → <strong>MUST REJECT</strong></li>
  <li>C3 regression check: <code>x=5, y=5</code> with <code>assert x != y</code> → <strong>MUST REJECT</strong></li>
</ul>

<p>If <strong>any</strong> of these pass (accept a proof they shouldn't), the CI goes <span style="color:var(--red)">red</span>. The badge goes red. The world sees it.</p>

<div class="fingerprint">
<h3>🔐 Immutable Audit Fingerprint</h3>
<p>The complete security audit and all adversarial test scenarios are committed to this repo. The Git history proves when each bug was found, how it was fixed, and that the fix has held.</p>
<p class="hash">Commit: 4705fad (audit findings published) · Tests: 128/128 · Regression checks: 3/3 · CI: active</p>
</div>

<h2 style="color:var(--gold);margin-top:36px">Try It Yourself</h2>

<p>Clone the repo. Run <code>cargo test</code>. 128 tests, 0 failures. Try the adversarial tests yourself — try to forge a proof. The CI does it automatically, but you can verify manually.</p>

<p>Or watch the CI run live:</p>

<div class="action">
  <a href="https://github.com/zkarchitect/zkforge" class="btn btn-star">⭐ Star zkforge</a>
  <a href="https://github.com/zkarchitect/zkforge/fork" class="btn btn-fork">🔱 Fork & Test</a>
  <a href="https://github.com/zkarchitect/zkforge/actions" class="btn btn-ci">🟢 View CI</a>
</div>

<p style="color:var(--muted);font-size:0.85em;margin-top:32px;text-align:center;">ZKForge — Pure Rust ZK compiler. No circom. No snarkjs. No Node.js. Apache 2.0.</p>

</body>
</html>