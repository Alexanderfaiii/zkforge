template AgeVerify() {
    signal input age;
    signal input min_age;
    signal output valid;
    signal diff;
    diff <== age - 18;
    signal is_positive;
    signal inv;
    inv <== 1 - is_positive;
    is_positive * inv === 0;
    is_positive * diff === diff;
    valid <== is_positive;
}
component main = AgeVerify();
