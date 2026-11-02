//! Own the exact immutable binding whose early-entry profile was checked.
#![forbid(unsafe_code)]

use super::{Arc, Binding, early_binding};
use std::ops::Deref;

// No mutable view or extraction can separate this result from its owner.
// A replacement must construct another envelope, including rejected profiles.
pub(super) struct BindingEnvelope {
    binding: Arc<Binding>,
    matches: bool,
}
impl BindingEnvelope {
    pub(super) fn new(binding: Arc<Binding>) -> Self {
        let matches = early_binding(&binding);
        Self { binding, matches }
    }

    pub(super) fn matches(&self) -> bool {
        self.matches
    }
}
impl Deref for BindingEnvelope {
    type Target = Arc<Binding>;
    fn deref(&self) -> &Self::Target {
        &self.binding
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use liteinst2::contracts::{CodeIdentity, SourceIdentity};

    const IDS: [FunctionId; 2] = [FunctionId(11), FunctionId(29)];

    fn module_site(early: bool) -> Arc<site::ordinary::ModuleSite> {
        let identity = CodeIdentity {
            source: SourceIdentity([231; 32]),
            mapping: 0x1000,
            generation: 1,
        };
        let functions = [
            (0x1000, 0x1020, vec![0x1010, 0x1018]),
            (0x1100, 0x1120, vec![0x1110, 0x1118]),
        ];
        if early {
            site::ordinary::ModuleSite::synthetic_early(identity, functions).0
        } else {
            site::ordinary::ModuleSite::synthetic(identity, functions)
        }
    }

    fn session(limits: Limits, absolute: bool) -> Session {
        let functions = IDS.map(|function| FunctionSpec { function, group: 0 });
        let groups = [GroupSpec { mandatory: true }];
        if absolute {
            Session::new_streaming_history(72, &functions, &groups, limits).unwrap()
        } else {
            Session::new(72, &functions, &groups, limits).unwrap()
        }
    }

    fn raw_binding(k: usize) -> Arc<Binding> {
        let (limits, _) =
            crate::frontend_native::always_on::normal::module::session::fixed(k).unwrap();
        Arc::new(Binding {
            session: session(limits, true),
            profile: BindingProfile::Module {
                site: module_site(true),
                functions: IDS,
            },
            key: Arc::new(()),
            pid: std::process::id(),
            install: 72,
            limits,
            entry_mode: EntryMode::Concurrent,
            native_entry_pause: std::sync::OnceLock::new(),
        })
    }

    // Literal pre-envelope check, evaluated on the same retained binding.
    fn original_check(shared: &Shared) -> Result<(), BridgeError> {
        shared.binding.process()?;
        if shared.failed.load(Ordering::Acquire) || !early_binding(&shared.binding) {
            return Err(error(Cause::Identity));
        }
        Ok(())
    }

    #[test]
    fn binding_envelope_preserves_malformed_profiles_and_fresh_error_order() {
        // Each immutable input has a distinct malformed case. Both supported
        // banks remain accepted, including their actual streaming Sessions.
        let faults: [fn(&mut Binding); 10] = [
            |b| b.limits.epochs = 2,
            |b| b.limits.threads = 2,
            |b| b.limits.depth = 2,
            |b| b.limits.records_per_epoch += 1,
            |b| b.limits.actions = 7,
            |b| {
                b.profile = BindingProfile::Single {
                    site: site::synthetic_site().site,
                    function: IDS[0],
                }
            },
            |b| {
                b.profile = BindingProfile::Module {
                    site: module_site(false),
                    functions: IDS,
                }
            },
            |b| {
                b.profile = BindingProfile::Module {
                    site: module_site(true),
                    functions: [IDS[0]; 2],
                }
            },
            |b| b.entry_mode = EntryMode::NonBlocking,
            |b| b.session = session(b.limits, false),
        ];
        for k in [10, 1000] {
            for fault in std::iter::once(None).chain(faults.into_iter().map(Some)) {
                for wrong_process in [false, true] {
                    let mut raw = raw_binding(k);
                    let b = Arc::get_mut(&mut raw).unwrap();
                    if let Some(mutate) = fault {
                        mutate(b);
                    }
                    if wrong_process {
                        b.pid ^= 1;
                    }
                    let shared = Shared {
                        binding: BindingEnvelope::new(raw),
                        failed: AtomicBool::new(false),
                    };
                    assert_eq!(shared.binding.matches(), fault.is_none());
                    // A bad profile is retained, not rejected at construction.
                    // A process refusal still precedes failure/profile Identity.
                    for failed in [false, true, false] {
                        shared.failed.store(failed, Ordering::Release);
                        let expected = if wrong_process {
                            Err(error(Cause::Process))
                        } else if failed || fault.is_some() {
                            Err(error(Cause::Identity))
                        } else {
                            Ok(())
                        };
                        assert_eq!(shared.check(), expected);
                        assert_eq!(shared.check(), original_check(&shared));
                        assert_eq!(shared.failed.load(Ordering::Acquire), failed);
                    }
                }
            }
        }
    }

    #[test]
    fn binding_envelope_replacement_revalidates_and_retains_exact_arc() {
        let mut raw = raw_binding(10);
        assert_eq!(Arc::strong_count(&raw), 1);
        let mut shared = Shared {
            binding: BindingEnvelope::new(Arc::clone(&raw)),
            failed: AtomicBool::new(false),
        };
        assert_eq!(Arc::strong_count(&raw), 2);
        assert!(Arc::ptr_eq(&shared.binding, &raw));
        assert!(Arc::get_mut(&mut raw).is_none());
        assert_eq!(shared.check(), Ok(()));

        let mut invalid = raw_binding(1000);
        Arc::get_mut(&mut invalid).unwrap().entry_mode = EntryMode::NonBlocking;
        shared.binding = BindingEnvelope::new(Arc::clone(&invalid));
        assert_eq!(Arc::strong_count(&raw), 1);
        assert_eq!(Arc::strong_count(&invalid), 2);
        assert!(Arc::ptr_eq(&shared.binding, &invalid));
        assert!(Arc::get_mut(&mut invalid).is_none());
        assert_eq!(shared.check(), Err(error(Cause::Identity)));
        assert_eq!(shared.check(), original_check(&shared));

        // The old raw owner is mutable only after its envelope is replaced.
        Arc::get_mut(&mut raw).unwrap().entry_mode = EntryMode::NonBlocking;
        shared.binding = BindingEnvelope::new(Arc::clone(&raw));
        assert_eq!(shared.check(), Err(error(Cause::Identity)));
        // Repair another now-exclusive owner and replace: no stale false fact.
        Arc::get_mut(&mut invalid).unwrap().entry_mode = EntryMode::Concurrent;
        shared.binding = BindingEnvelope::new(Arc::clone(&invalid));
        assert_eq!(shared.check(), Ok(()));
        assert_eq!(shared.check(), original_check(&shared));
        assert_eq!(Arc::strong_count(&invalid), 2);

        let weak = Arc::downgrade(&invalid);
        drop(invalid);
        assert_eq!(weak.strong_count(), 1);
        assert_eq!(shared.check(), Ok(()));
        drop(shared);
        assert!(weak.upgrade().is_none());
    }
}
