// Actual private production router, not a test handler or public live API.
use super::*;
use crate::isolated_native_test as isolated;
// Shared support has intentionally unused legacy entry APIs in this test binary;
// its complete bodies and assertions are retained.
#[allow(dead_code)]
#[path = "../../../tests/support/quiescent_oracle.rs"]
mod oracle;
use oracle::routed_jmp_native::{self as native, Router};

struct ProductionRoutes(RouteRegistration);
impl Router for ProductionRoutes {
    fn prepare() {
        super::prepare().unwrap();
    }
    fn verify() {
        super::verify().unwrap();
    }
    fn stage(routes: &[EntryRoute]) -> Self {
        // SAFETY: the only caller is the private fixed owner after complete
        // artifact admission and RX destination initialization, with no children.
        // It stages before markers and retains all owners until every child is
        // reaped and synchronized source restoration deactivates this batch.
        Self(unsafe { super::stage(routes) }.unwrap())
    }
    fn counter_address(&self) -> u64 {
        core::ptr::from_ref(&self.0.batch.handled) as usize as u64
    }
    fn deactivate(&self) {
        self.0.deactivate();
    }
    fn assert_active(&self) {
        assert!(self.0.batch.active.load(Ordering::Acquire));
    }
}
macro_rules! row {
    ($name:ident, $index:expr) => {
        #[test]
        fn $name() {
            isolated::run(
                concat!(
                    "entry_router::imp::routed_jmp_native_tests::",
                    stringify!($name)
                ),
                "LI2_ROUTED_JMP_NATIVE_ROW_V1",
                || native::run::<ProductionRoutes>($index),
            );
        }
    };
}
row!(row_00, 0);
row!(row_01, 1);
row!(row_02, 2);
row!(row_03, 3);
row!(row_04, 4);
row!(row_05, 5);
row!(row_06, 6);
row!(row_07, 7);
row!(row_08, 8);
row!(row_09, 9);
row!(row_10, 10);
row!(row_11, 11);
row!(row_12, 12);
row!(row_13, 13);
row!(row_14, 14);
row!(row_15, 15);
row!(row_16, 16);
row!(row_17, 17);
row!(row_18, 18);
row!(row_19, 19);
row!(row_20, 20);
row!(row_21, 21);
row!(row_22, 22);
row!(row_23, 23);
row!(row_24, 24);
row!(row_25, 25);
row!(row_26, 26);
row!(row_27, 27);
row!(row_28, 28);
row!(row_29, 29);
row!(row_30, 30);

#[test]
fn actual_f_after_deactivation_uses_default_sigill() {
    isolated::run(
        "entry_router::imp::routed_jmp_native_tests::actual_f_after_deactivation_uses_default_sigill",
        "LI2_ROUTED_JMP_NATIVE_INACTIVE_V1",
        || native::inactive_or_unowned_f::<ProductionRoutes>(true),
    );
}
#[test]
fn actual_f_without_owner_uses_default_sigill() {
    isolated::run(
        "entry_router::imp::routed_jmp_native_tests::actual_f_without_owner_uses_default_sigill",
        "LI2_ROUTED_JMP_NATIVE_UNOWNED_V1",
        || native::inactive_or_unowned_f::<ProductionRoutes>(false),
    );
}

#[test]
fn readiness_disposition_and_duplicate_owner_refuse_before_source_publication() {
    isolated::run(
        "entry_router::imp::routed_jmp_native_tests::readiness_disposition_and_duplicate_owner_refuse_before_source_publication",
        "LI2_ROUTED_JMP_NATIVE_GATES_V1",
        || {
            native::gate_fixture(|routes| {
                assert_eq!(super::verify(), Err(Refusal::SignalContract));
                // SAFETY: the private fixture retains checked RX destinations and
                // has started no executor; missing readiness must refuse first.
                assert!(matches!(
                    unsafe { super::stage(routes) },
                    Err(Refusal::SignalContract)
                ));
                super::prepare().unwrap();
                super::verify().unwrap();
                let original_mask = super::current_mask().unwrap();
                let mut blocked = original_mask;
                // SAFETY: initialized exact thread mask; no subject exists.
                unsafe {
                    assert_eq!(libc::sigaddset(&mut blocked, libc::SIGILL), 0);
                    assert_eq!(
                        libc::pthread_sigmask(libc::SIG_SETMASK, &blocked, ptr::null_mut()),
                        0
                    );
                }
                assert_eq!(super::verify(), Err(Refusal::SignalContract));
                assert!(matches!(
                    unsafe { super::stage(routes) },
                    Err(Refusal::SignalContract)
                ));
                assert_eq!(
                    unsafe {
                        libc::pthread_sigmask(libc::SIG_SETMASK, &original_mask, ptr::null_mut())
                    },
                    0
                );
                super::verify().unwrap();
                let original_action = super::action().unwrap();
                let mut replaced = original_action;
                replaced.sa_sigaction = libc::SIG_IGN;
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGILL, &replaced, ptr::null_mut()) },
                    0
                );
                assert_eq!(super::verify(), Err(Refusal::SignalContract));
                assert!(matches!(
                    unsafe { super::stage(routes) },
                    Err(Refusal::SignalContract)
                ));
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGILL, &original_action, ptr::null_mut()) },
                    0
                );
                super::verify().unwrap();
                let owned = unsafe { super::stage(routes) }.unwrap();
                assert!(owned.batch.active.load(Ordering::Acquire));
                assert!(matches!(
                    unsafe { super::stage(routes) },
                    Err(Refusal::OwnershipConflict)
                ));
                assert!(matches!(
                    unsafe { super::stage(&[routes[0], routes[0]]) },
                    Err(Refusal::InvalidPlan)
                ));
                owned.deactivate();
                assert!(!owned.batch.active.load(Ordering::Acquire));
            })
        },
    );
}
