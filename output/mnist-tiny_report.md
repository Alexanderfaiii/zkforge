=== ZKML Proof Report: mnist-tiny ===

Architecture: 4 → ... → 2
Scale factor: 1000

## R1CS Statistics

Total constraints: 50
Total variables: 46

### Per-Layer Constraints

  Layer 0: 0 constraints
  Layer 1: 24 constraints
  Layer 2: 12 constraints
  Layer 3: 2 constraints
  Layer 4: 4 constraints

## Inference Output

Output dimension: 2
  output[0] = 1000 (raw field element)
  output[1] = 0 (raw field element)

🔮 **Predicted class: 0**

## Privacy Guarantees

- ✅ Model weights: NEVER revealed
- ✅ Input data: NEVER revealed
- ✅ Intermediate activations: NEVER revealed
- ✅ Only the output is public

## Performance

Circuit size: 50 constraints
Est. proving time (Groth16): 0.0s
Est. verification time: ~5ms
Proof size: 128 bytes (constant)
