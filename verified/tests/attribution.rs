use vpma_verified::attribute_by_weight;

fn sum(v: &[u64]) -> u128 {
    v.iter().map(|x| *x as u128).sum()
}

#[test]
fn conserves_on_cpu_tick_weights() {

    let weights = vec![1_234_567, 89, 4_000_000_000, 17, 250_000, 0, 33_333];
    let total = 987_654_321u64;
    let shares = attribute_by_weight(total, &weights).expect("positive weight");
    assert_eq!(shares.len(), weights.len());
    assert_eq!(sum(&shares), total as u128, "energy was created or destroyed");
}

#[test]
fn conserves_across_many_totals_and_weightings() {
    let cases: Vec<Vec<u64>> = vec![
        vec![1],
        vec![1, 1],
        vec![0, 0, 1],
        vec![u64::MAX],
        vec![u64::MAX, u64::MAX],
        vec![u64::MAX, 1],
        vec![1, u64::MAX],
        vec![7; 64],
        vec![100_000_000_000; 8],
        (1..=50u64).collect(),
    ];
    for weights in &cases {
        for total in [0u64, 1, 2, 999, 1_000_000, u64::MAX / 2, u64::MAX] {
            let shares = attribute_by_weight(total, weights)
                .unwrap_or_else(|| panic!("None for weights={weights:?}"));
            assert_eq!(shares.len(), weights.len());
            assert_eq!(
                sum(&shares),
                total as u128,
                "conservation broken: total={total}, weights={weights:?}"
            );
        }
    }
}

#[test]
fn zero_weight_returns_none_rather_than_inventing_a_split() {

    assert!(attribute_by_weight(500, &[]).is_none());
    assert!(attribute_by_weight(500, &[0]).is_none());
    assert!(attribute_by_weight(500, &[0, 0, 0]).is_none());

    let shares = attribute_by_weight(0, &[5, 5]).expect("weights are positive");
    assert_eq!(shares, vec![0, 0]);
}

#[test]
fn zero_weight_buckets_receive_nothing() {
    let weights = vec![0, 10, 0, 90];
    let shares = attribute_by_weight(1000, &weights).unwrap();
    assert_eq!(shares[0], 0);
    assert_eq!(shares[2], 0);
    assert_eq!(sum(&shares), 1000);
}

#[test]
fn remainder_goes_to_the_heaviest_bucket() {

    let shares = attribute_by_weight(10, &[1, 1, 1]).unwrap();
    assert_eq!(sum(&shares), 10);
    assert_eq!(shares, vec![3, 3, 4]);

    let shares = attribute_by_weight(10, &[1, 8, 1]).unwrap();
    assert_eq!(sum(&shares), 10);
    assert_eq!(shares[1], 8);
}

#[test]
fn proportionality_is_respected() {

    let shares = attribute_by_weight(1_000_000, &[1, 3]).unwrap();
    assert_eq!(sum(&shares), 1_000_000);
    assert_eq!(shares[0], 250_000);
    assert_eq!(shares[1], 750_000);
}

#[test]
fn extreme_weights_do_not_panic() {

    let weights = vec![u64::MAX; 1000];
    let shares = attribute_by_weight(u64::MAX, &weights).unwrap();
    assert_eq!(sum(&shares), u64::MAX as u128);
}
