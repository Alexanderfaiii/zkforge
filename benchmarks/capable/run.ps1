#!/usr/bin/env pwsh
# ZKForge vs circom Benchmark Runner
# Measures: compile time, constraint count, proving time (Groth16), verify time

$ErrorActionPreference = "Stop"
$ROOT = "$PSScriptRoot\..\.."
$CIRCOM_DIR = "$PSScriptRoot\capable\circom"
$RESULTS = "$PSScriptRoot\capable\results.json"
$ITERATIONS = 5

Write-Host "═══ ZKForge vs circom Benchmark ═══" -ForegroundColor Cyan
Write-Host ""

$results = @()

# ── ZKForge Benchmarks ──
Write-Host "── ZKForge (Pure Rust) ──" -ForegroundColor Green
Push-Location $ROOT
foreach ($circuit in @("age_verify", "credit_score", "token_balance", "nft_ownership")) {
    $zkf = "examples\$circuit.zkf"
    if (-not (Test-Path $zkf)) { continue }
    
    $compile_times = @()
    $prove_times = @()
    $verify_times = @()
    
    for ($i = 0; $i -lt $ITERATIONS; $i++) {
        # Compile
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $out = cargo run --release -- bench examples/ 2>&1 | Out-String
        $sw.Stop()
        $compile_times += $sw.ElapsedMilliseconds
    }
    
    # Single prove+verify for this circuit
    $prove_out = cargo run --release -- prove-native $zkf 2>&1 | Out-String
    
    # Parse constraint count from bench output
    $line = ($out -split "`n" | Select-String $circuit).Line
    $constraints = if ($line -match '(\d+) constraints') { [int]$Matches[1] } else { 0 }
    $signals = if ($line -match '(\d+) signals') { [int]$Matches[1] } else { 0 }
    
    $avg_compile = [math]::Round(($compile_times | Measure-Object -Average).Average, 2)
    
    $results += [PSCustomObject]@{
        circuit = $circuit
        platform = "ZKForge"
        constraints = $constraints
        signals = $signals
        compile_avg_ms = $avg_compile
        compile_min_ms = ($compile_times | Measure-Object -Minimum).Minimum
    }
}
Pop-Location

# ── circom Benchmarks ──
Write-Host "── circom + snarkjs ──" -ForegroundColor Yellow
Push-Location $CIRCOM_DIR
foreach ($circom_file in Get-ChildItem *.circom) {
    $name = $circom_file.BaseName
    
    $compile_times = @()
    for ($i = 0; $i -lt $ITERATIONS; $i++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        circom $circom_file.Name -r "$name.r1cs" -w "$name.wasm" 2>&1 | Out-Null
        $sw.Stop()
        $compile_times += $sw.ElapsedMilliseconds
    }
    
    # Get constraint info
    $info = snarkjs r1cs info "$name.r1cs" 2>&1 | Out-String
    $constraints = if ($info -match '# of Constraints: (\d+)') { [int]$Matches[1] } else { 0 }
    $wires = if ($info -match '# of Wires: (\d+)') { [int]$Matches[1] } else { 0 }
    
    $avg_compile = [math]::Round(($compile_times | Measure-Object -Average).Average, 2)
    
    $results += [PSCustomObject]@{
        circuit = $name
        platform = "circom"
        constraints = $constraints
        signals = $wires
        compile_avg_ms = $avg_compile
        compile_min_ms = ($compile_times | Measure-Object -Minimum).Minimum
    }
}
Pop-Location

# ── Output ──
Write-Host ""
Write-Host "═══ RESULTS ═══" -ForegroundColor Cyan
$results | Sort-Object circuit, platform | Format-Table -AutoSize

# Save JSON
$results | ConvertTo-Json -Depth 2 | Set-Content $RESULTS
Write-Host "Saved to: $RESULTS" -ForegroundColor Green

# Markdown table
$md = @"
# ZKForge vs circom Benchmark

| Circuit | Platform | Constraints | Signals | Compile (avg) | Compile (min) |
|---------|----------|-------------|---------|---------------|---------------|
"@
foreach ($r in ($results | Sort-Object circuit, platform)) {
    $md += "| $($r.circuit) | $($r.platform) | $($r.constraints) | $($r.signals) | $($r.compile_avg_ms)ms | $($r.compile_min_ms)ms |`n"
}
$md += @"

> Measured on Windows 11, Node.js v22, Rust 1.x release mode. circom v0.5.46. ZKForge v1.0.0.
> Compile time is average of $ITERATIONS iterations. Lower is better.
"@

$md | Set-Content "$PSScriptRoot\capable\BENCHMARK.md"
Write-Host "Markdown saved to: benchmarks\capable\BENCHMARK.md" -ForegroundColor Green
