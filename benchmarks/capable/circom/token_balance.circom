template TokenBalance() {
    signal input balance;
    signal input required_amount;
    signal input total_supply;
    signal output eligible;

    signal threshold;
    threshold <== required_amount * 2;
    signal diff1;
    diff1 <== balance - threshold;
    signal check1;
    signal inv1;
    inv1 <== 1 - check1;
    check1 * inv1 === 0;
    check1 * diff1 === diff1;

    signal diff2;
    diff2 <== total_supply - balance;
    signal check2;
    signal inv2;
    inv2 <== 1 - check2;
    check2 * inv2 === 0;

    signal both;
    both <== check1 * check2;
    eligible <== both;
}
component main = TokenBalance();
