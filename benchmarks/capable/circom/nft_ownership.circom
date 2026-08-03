template NFTOwnership() {
    signal input merkle_root;
    signal input leaf;
    signal output is_owner;
    signal x2;
    signal x4;
    signal x5;
    signal x10;
    signal x20;
    signal x40;
    signal x80;
    x2 <== leaf * leaf;
    x4 <== x2 * x2;
    x5 <== x4 * leaf;
    x10 <== x5 * x5;
    x20 <== x10 * x10;
    x40 <== x20 * x20;
    x80 <== x40 * x40;
    signal diff;
    diff <== x80 - merkle_root;
    signal match;
    signal inv;
    inv <== 1 - match;
    match * inv === 0;
    diff * match === 0;
    is_owner <== match;
}
component main = NFTOwnership();
