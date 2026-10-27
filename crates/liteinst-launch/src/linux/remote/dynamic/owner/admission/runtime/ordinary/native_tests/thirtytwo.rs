//! One fixed acceptance prefix. Any refusal before instruction32 is a failure.
use super::*;

#[test]
fn runtime_ordinary_thirty_two_nops_fit_default_budget_and_retain_exact_history() {
    crate::linux::remote::dynamic::owner::admission::runtime::isolation::run(
        "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::thirtytwo::runtime_ordinary_thirty_two_nops_fit_default_budget_and_retain_exact_history",
        || {
            // Exact architectural NOPs; UD2 must remain unexecuted. No source,
            // register, stack, argv or address preparation changes the fixture.
            let mut code = [0x90; 34];
            code[32] = 0x0f;
            code[33] = 0x0b;
            let fixture = Fixture::code(&code);
            with_owner(
                &fixture,
                &code,
                |owner, initial, until, original| {
                    let limit = DynamicRuntimeOptions::default().limits.source_fact_bytes;
                    assert_eq!(limit, 64 * 1024 * 1024);
                    let mut before = begin(owner, initial, until, original);
                    assert_eq!(before.registers.rip, ENTRY);
                    let initial_census = owner.runtime.as_ref().unwrap().census.as_ref().unwrap();
                    let mut prior_used = initial_census.used().source_fact_bytes;
                    let mut prior_charged = initial_census.charged().source_fact_bytes;
                    for ordinal in 0..32 {
                        // Expected full state is the prior literal expectation,
                        // never the observed successor or a completion seal.
                        let mut expected = before.clone();
                        expected.registers.rip = ENTRY + (ordinal as u64) + 1;
                        one(owner, until);
                        check(owner, &before, &expected, original, ordinal, until);
                        let runtime = owner.runtime.as_ref().unwrap();
                        assert_eq!(runtime.until, until);
                        let census = runtime.census.as_ref().unwrap();
                        let used = census.used().source_fact_bytes;
                        let charged = census.charged().source_fact_bytes;
                        assert!(used > prior_used && charged > prior_charged);
                        assert!(used <= charged && charged <= limit);
                        prior_used = used;
                        prior_charged = charged;
                        before = expected;
                    }
                    assert_eq!(before.registers.rip, ENTRY + 32);
                    assert_eq!(state(owner.pid), before);
                    assert_eq!(memory(owner.pid, ENTRY + 32, 2), [0x0f, 0x0b]);
                    let runtime = owner.runtime.as_ref().unwrap();
                    let census = runtime.census.as_ref().unwrap();
                    assert_eq!(runtime.ordinary_attempts.len(), 32);
                    assert_eq!(census.rows().count(), 33);
                    assert_eq!(census.active().count(), 1);
                    assert_eq!(census.history().len(), 224);
                    assert_eq!(census.used().source_fact_bytes, prior_used);
                    assert_eq!(census.charged().source_fact_bytes, prior_charged);
                    assert!(Instant::now() < until);
                    // Existing complete semantic/native evidence plus separate
                    // actual root/native/archive allocation identities.
                    let snapshot = (retained(owner), runtime.test_ordinary_allocation_snapshot());
                    assert!(Instant::now() < until);
                    snapshot
                },
                |owner, snapshot| {
                    after_cleanup(owner, &snapshot.0);
                    assert_eq!(
                        owner
                            .runtime
                            .as_ref()
                            .unwrap()
                            .test_ordinary_allocation_snapshot(),
                        snapshot.1
                    );
                },
            );
        },
    );
}
