template CreditScore() {
    signal input credit_score;
    signal input min_score;
    signal output approved;
    signal diff;
    diff <== credit_score - 700;
    signal is_positive;
    signal inv;
    inv <== 1 - is_positive;
    is_positive * inv === 0;
    is_positive * diff === diff;
    approved <== is_positive;
}
component main = CreditScore();
