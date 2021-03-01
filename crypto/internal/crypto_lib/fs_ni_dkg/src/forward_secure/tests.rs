use super::*;

// The following test was disabled because the current params are too large for
// this to run
#[test]
#[ignore]
fn should_allow_for_2_pow_lambda_t_updates() {
    let sys = &mk_sys_params();
    // Check that we're not running with a too big lambda_t.
    assert_eq!(32, 2_i32.checked_pow(sys.lambda_t as u32).unwrap());

    let rng = &mut RAND_ChaCha20::new([42; 32]);

    let (_pk, mut sk) = kgen(sys, rng);
    let mut count = 0;
    while sk.current().is_some() {
        sk.update(sys, rng);
        count += 1;
    }
    assert_eq!(32, count);
}

#[test]
fn should_allow_for_32_updates() {
    let sys = &mk_sys_params();

    let rng = &mut RAND_ChaCha20::new([42; 32]);

    let (_pk, mut sk) = kgen(sys, rng);
    assert!(sk.current().is_some());

    for _i in 0..32 {
        sk.update(sys, rng);
        assert!(sk.current().is_some());
    }
}
