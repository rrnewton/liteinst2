use super::*;

fn config() -> Config {
    Config {
        retained_per_function: 1,
        max_inflight: 8,
        max_invocations: 8,
    }
}
fn make(storage: Storage) -> Epoch {
    storage.into_epoch().map_err(|(error, _)| error).unwrap()
}

#[test]
fn storage_configuration_preserves_legacy_predicates_and_order() {
    let a = FunctionId(11);
    let too_many = vec![a; MAX_FUNCTIONS + 1];
    let cases = [
        (vec![], config(), Some(CreateError::EmptyFunctions)),
        (too_many, config(), Some(CreateError::TooManyFunctions)),
        (vec![a, a], config(), Some(CreateError::DuplicateFunction)),
        (
            vec![a],
            Config {
                retained_per_function: 0,
                ..config()
            },
            Some(CreateError::ZeroRetainedBudget),
        ),
        (
            vec![a],
            Config {
                max_inflight: 0,
                ..config()
            },
            Some(CreateError::InvalidInflightLimit),
        ),
        (
            vec![a],
            Config {
                max_inflight: COUNT_MASK + 1,
                ..config()
            },
            Some(CreateError::InvalidInflightLimit),
        ),
        (
            vec![a],
            Config {
                max_invocations: 0,
                ..config()
            },
            Some(CreateError::InvalidInvocationLimit),
        ),
        (
            vec![a],
            Config {
                max_invocations: MAX_RECORDS + 1,
                ..config()
            },
            Some(CreateError::InvalidInvocationLimit),
        ),
        // K and M above A remain accepted; they are independent limits.
        (
            vec![a],
            Config {
                retained_per_function: 99,
                max_inflight: 99,
                max_invocations: 1,
            },
            None,
        ),
    ];
    for (ids, c, expected) in cases {
        assert_eq!(Storage::prepare(&ids, c).err(), expected);
        assert_eq!(Epoch::new(&ids, c).err(), expected);
    }
    let invalid = Config {
        retained_per_function: 0,
        max_inflight: 0,
        max_invocations: 0,
    };
    assert_eq!(
        Storage::prepare(&[], invalid).err(),
        Some(CreateError::EmptyFunctions)
    );
    assert_eq!(
        Storage::prepare(&[a, a], invalid).err(),
        Some(CreateError::DuplicateFunction)
    );
    assert_eq!(
        Storage::prepare(&[a], invalid).err(),
        Some(CreateError::ZeroRetainedBudget)
    );
}

#[test]
fn storage_allocation_failures_use_real_reservation_seam() {
    for fail in 0..2 {
        let _probe = allocation_probe::start(Some(fail));
        assert_eq!(
            Storage::prepare(&[FunctionId(11)], config()).err(),
            Some(CreateError::Allocation)
        );
        assert_eq!(allocation_probe::calls(), fail + 1);
    }
    let _probe = allocation_probe::start(None);
    let bank = Storage::prepare(&[FunctionId(11)], config()).unwrap();
    assert_eq!(allocation_probe::calls(), 2);
    assert!(bank.clean());
    assert_eq!(bank.geometry()[1].1, config().max_invocations);
}

#[test]
fn storage_reset_keeps_addresses_and_clears_every_terminal_and_tail() {
    let a = FunctionId(11);
    let mut bank = Storage::prepare(&[a], config()).unwrap();
    let geometry = bank.geometry();
    let mut previous = None;
    // First fill all A, then use only a prefix. Old unused tail must remain empty.
    for count in [8, 4, 8] {
        let _probe = allocation_probe::start(Some(0));
        let mut epoch = Arc::new(make(bank));
        assert_ne!(Some(epoch.id()), previous);
        previous = Some(epoch.id());
        let mut tickets: Vec<_> = (0..count)
            .map(|n| epoch.enter_owned(a, n as u64).unwrap())
            .collect();
        assert_eq!(
            tickets.remove(0).complete(100).disposition,
            Disposition::Retained { rank: 0 }
        );
        assert_eq!(
            tickets.remove(0).complete(101).disposition,
            Disposition::DroppedAfterBudget
        );
        tickets.remove(0).cancel();
        drop(tickets); // The remaining records publish DroppedTicket, exactly once.
        assert_eq!(epoch.close(), 0);
        let copied: Vec<_> = epoch.try_drain().unwrap().records().collect();
        assert_eq!(copied.len(), count);
        assert_eq!(copied[2].1, Terminal::Cancelled(CancelReason::Explicit));
        assert!(
            copied[3..]
                .iter()
                .all(|r| r.1 == Terminal::Cancelled(CancelReason::DroppedTicket))
        );
        let retired = extract(Arc::get_mut(&mut epoch).unwrap());
        drop(epoch);
        bank = retired.reset();
        assert_eq!(bank.geometry(), geometry);
        assert!(bank.clean());
        assert_eq!(allocation_probe::calls(), 0);
        assert!(copied.iter().all(|r| Some(r.0.generation) == previous));
    }
}

#[test]
fn storage_exhaustion_keeps_bank_and_never_wraps_local_identity() {
    let bank = Storage::prepare(&[FunctionId(11)], config()).unwrap();
    let geometry = bank.geometry();
    let next = AtomicU64::new(u64::MAX - 1);
    let mut epoch = bank.into_epoch_with(&next).map_err(|(e, _)| e).unwrap();
    assert_eq!(epoch.id().get(), u64::MAX - 1);
    epoch.close();
    let retired = extract(&mut epoch);
    drop(epoch);
    let bank = retired.reset();
    let (error, bank) = match bank.into_epoch_with(&next) {
        Err(pair) => pair,
        Ok(_) => panic!("exhausted identity was accepted"),
    };
    assert_eq!(error, CreateError::GenerationExhausted);
    assert_eq!(next.load(Ordering::Acquire), u64::MAX);
    assert_eq!(bank.geometry(), geometry);
    assert!(bank.clean());
    let zero = AtomicU64::new(0);
    let (error, bank) = match bank.into_epoch_with(&zero) {
        Err(pair) => pair,
        Ok(_) => panic!("zero identity was accepted"),
    };
    assert_eq!(error, CreateError::GenerationExhausted);
    assert_eq!(zero.load(Ordering::Acquire), 0);
    assert_eq!(bank.geometry(), geometry);
    assert!(bank.clean());
}
