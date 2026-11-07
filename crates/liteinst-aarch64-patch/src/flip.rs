//! The flip protocol: strategy selection before any write, lease,
//! revalidation, one aligned store, sync, acknowledged resume — plus
//! `complete_sync` recovery and rollback (including direct rollback
//! from `SyncPending`). Post-store failures are custody states, never
//! "not flipped": this module records `Flipped` custody the instant
//! the store lands and only settles it through the named transitions.

use crate::island::Island;
use crate::mapping::MappingFacts;
use crate::site::{
    FallbackPermission, PendingWord, ResumeState, Site, SiteState, StopControl, StrategyPreference,
    TrapRoute,
};
use crate::{PatchError, Patcher};
use liteinst_aarch64::Insn;
use liteinst_aarch64::emit::{Strategy, island_reaches, svc_fallback_word, svc_patch_word};

/// Explicit inputs for one flip. The island (when present) moves into
/// site custody by value before the store; on a pre-store refusal
/// after that transfer the site keeps it (retrievable at teardown),
/// never dropping it under a live branch.
pub struct FlipRequest {
    /// Fresh, unreachable island for the Branch strategy.
    pub island: Option<Island>,
    /// Which strategies may be selected.
    pub strategy: StrategyPreference,
    /// Whether Trap may substitute when Branch is unavailable
    /// (only consulted by `BranchThenTrap`).
    pub fallback: FallbackPermission,
    /// Pre-armed owned trap route (required for any Trap selection);
    /// its generation must match the site's.
    pub trap_route: Option<TrapRoute>,
    /// Fresh mapping facts for foreign sites, when the caller has
    /// re-qualified since construction; a generation mismatch with
    /// the site refuses before the lease.
    pub mapping_facts: Option<MappingFacts>,
}

impl core::fmt::Debug for FlipRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlipRequest")
            .field("has_island", &self.island.is_some())
            .field("strategy", &self.strategy)
            .field("fallback", &self.fallback)
            .field("trap_route", &self.trap_route)
            .field("mapping_facts", &self.mapping_facts)
            .finish()
    }
}

/// Both-directions reach for a payload extent: site -> entry and the
/// payload's last word -> resume (site+4) must both encode. Kept pure
/// so both boundary edges are host-testable with synthetic addresses.
fn return_reach_ok(site_addr: u64, entry: u64, payload_len: u64) -> bool {
    island_reaches(site_addr, entry, payload_len)
}

/// Branch word only when the island serves the site in BOTH
/// directions, validated against the actual payload extent — not the
/// page-rounded mapping length, whose padding would move the nominal
/// return PC and both wrongly accept and wrongly refuse edge sites.
fn branch_word_checked(original: u32, site_addr: u64, island: &Island) -> Option<u32> {
    if !return_reach_ok(site_addr, island.entry_addr(), island.payload_len()) {
        return None;
    }
    svc_patch_word(original, site_addr, island.entry_addr())
}

fn all_acknowledged(states: &[ResumeState]) -> bool {
    !states.is_empty()
        && states
            .iter()
            .all(|s| matches!(s, ResumeState::SyncAcked | ResumeState::Released))
}

impl Patcher {
    fn sync_site(&self, site: &Site) -> Result<(), PatchError> {
        // SAFETY: Site construction guarantees both aliases name the
        // same valid word; the range is exactly that word.
        self.sync_range(site.write_addr() as *mut u8, site.addr() as *mut u8, 4)
    }

    /// Best-effort lease release after a pre-store refusal under the
    /// lease. Returns true only when every executor acknowledged.
    fn release_after_refusal(&self, site: &mut Site, stop: &mut dyn StopControl) -> bool {
        match stop.resume() {
            Ok(states) => {
                let done = all_acknowledged(&states);
                site.set_resume_states(states);
                done
            }
            Err(_) => false,
        }
    }

    /// Resume under the current lease and settle `pending` if every
    /// executor acknowledged. On any shortfall the site stays in its
    /// pending custody state (stop retained for RetainedStop cases is
    /// the StopControl's state; the site records what was observed).
    fn resume_and_settle(
        &self,
        site: &mut Site,
        stop: &mut dyn StopControl,
        pending: PendingWord,
        retained: bool,
    ) -> Result<(), PatchError> {
        match stop.resume() {
            Ok(states) => {
                let done = all_acknowledged(&states);
                site.set_resume_states(states);
                if !done {
                    site.set_state(if retained {
                        SiteState::RetainedStop { pending }
                    } else {
                        SiteState::SyncPending { pending }
                    });
                    return Err(PatchError::ResumeIncomplete);
                }
                match pending {
                    PendingWord::Patch(_) => site.set_state(SiteState::Flipped),
                    PendingWord::Original => {
                        site.set_flipped_word(None);
                        site.set_state(SiteState::Unpatched);
                    }
                }
                Ok(())
            }
            Err(e) => {
                site.set_state(SiteState::RetainedStop { pending });
                Err(e)
            }
        }
    }

    /// Post-store tail shared by flip and rollback: sync the stored
    /// word, then resume-and-settle. The pending state must already be
    /// recorded by the caller before the store lands.
    fn finish_publication(
        &self,
        site: &mut Site,
        stop: &mut dyn StopControl,
        pending: PendingWord,
    ) -> Result<(), PatchError> {
        // Order per design: sync while the store window is open, then
        // restore (finish), then acknowledged resume. Either failure
        // leaves SyncPending custody; completion retries both.
        let sync_result = self.sync_site(site);
        let finish_result = if sync_result.is_ok() {
            site.finish_write()
        } else {
            Ok(())
        };
        if let Err(e) = sync_result.and(finish_result) {
            site.set_state(if matches!(site.state(), SiteState::RetainedStop { .. }) {
                SiteState::RetainedStop { pending }
            } else {
                SiteState::SyncPending { pending }
            });
            return Err(PatchError::SyncFailed {
                source: Box::new(e),
            });
        }
        self.resume_and_settle(site, stop, pending, false)
    }

    /// Flip one `Unpatched` site per `request` under `stop`'s lease.
    /// Pre-store refusals write nothing; post-store failures return an
    /// error with the site in a named custody state.
    pub fn flip(
        &mut self,
        site: &mut Site,
        request: FlipRequest,
        stop: &mut dyn StopControl,
    ) -> Result<Strategy, PatchError> {
        // Capability gate (design): cache maintenance must be
        // established before the first store, for EVERY strategy. An
        // unattested patcher writes nothing, whatever the strategy.
        self.check_fork()?;
        if self.attested_token().is_none() {
            return Err(PatchError::CacheOpsUnavailable);
        }
        if site.state() != SiteState::Unpatched {
            return Err(PatchError::WrongState {
                state: site.state(),
            });
        }
        if !site.addr().is_multiple_of(4) {
            return Err(PatchError::MisalignedSite { addr: site.addr() });
        }
        let original = site.original_word();
        if !matches!(liteinst_aarch64::decode(original), Insn::Svc { .. }) {
            return Err(PatchError::NotSvc { word: original });
        }
        let FlipRequest {
            island,
            strategy,
            fallback,
            trap_route,
            mapping_facts,
        } = request;
        let mut island = island;
        if let Some(facts) = mapping_facts {
            if !facts.contains(site.addr()) {
                return Err(PatchError::MappingRefused(
                    "presented facts do not contain the site",
                ));
            }
            if facts.generation != site.generation() {
                return Err(PatchError::StaleGeneration {
                    site: site.generation(),
                    facts: facts.generation,
                });
            }
        }
        // Strategy selection is fully decided before the lease/store.
        let branch_word = island
            .as_ref()
            .and_then(|i| branch_word_checked(original, site.addr(), i));
        let trap_armed = trap_route.as_ref().is_some_and(|route| {
            route.addr() == site.addr() && route.generation() == site.generation()
        });
        let (selected, patch_word) = match strategy {
            StrategyPreference::BranchOnly => match branch_word {
                Some(w) => (Strategy::Branch, w),
                None => {
                    return Err(PatchError::StrategyUnavailable(
                        "BranchOnly without a reachable island",
                    ));
                }
            },
            StrategyPreference::TrapOnly => {
                if !trap_armed {
                    return Err(PatchError::TrapNotArmed);
                }
                (
                    Strategy::Trap,
                    svc_fallback_word(original, trap_route.expect("armed").brk_imm())
                        .ok_or(PatchError::NotSvc { word: original })?,
                )
            }
            StrategyPreference::BranchThenTrap => match branch_word {
                Some(w) => (Strategy::Branch, w),
                None => {
                    if fallback == FallbackPermission::RefuseTrap {
                        return Err(PatchError::StrategyUnavailable(
                            "no reachable island and trap fallback refused",
                        ));
                    }
                    if !trap_armed {
                        return Err(PatchError::TrapNotArmed);
                    }
                    (
                        Strategy::Trap,
                        svc_fallback_word(original, trap_route.expect("armed").brk_imm())
                            .ok_or(PatchError::NotSvc { word: original })?,
                    )
                }
            },
        };
        // Publish the island while it is still unreachable (Branch).
        if selected == Strategy::Branch {
            let attested = self
                .attested_token()
                .ok_or(PatchError::CacheOpsUnavailable)?;
            island
                .as_mut()
                .expect("branch selected with island")
                .publish(attested)?;
        }
        stop.acquire()?;
        // Everything below runs under the lease; a pre-store exit must
        // release it and surface the cleanup outcome, never discard it.
        let found = site.read_word();
        if found != original {
            return if self.release_after_refusal(site, stop) {
                Err(PatchError::SiteWordChanged {
                    expected: original,
                    found,
                })
            } else {
                Err(PatchError::CleanupFailed {
                    expected: original,
                    found,
                })
            };
        }
        // Custody transfer before the store: from here the site owns
        // the island/route across every later outcome.
        if let Some(island) = island {
            site.retain_island(island);
        }
        if let Some(route) = trap_route {
            site.retain_trap_route(route);
        }
        // Open the store window before the state transition: a begin
        // failure is pre-store and releases the lease cleanly.
        if let Err(e) = site.begin_write() {
            return if self.release_after_refusal(site, stop) {
                Err(e)
            } else {
                Err(PatchError::ResumeIncomplete)
            };
        }
        site.set_flipped_word(Some(patch_word));
        site.set_state(SiteState::SyncPending {
            pending: PendingWord::Patch(patch_word),
        });
        // The design's one aligned store, through the store seam. A
        // store error is post-issuance custody: the word may have
        // landed, so the state stays SyncPending for completion.
        if let Err(e) = site.store_word(patch_word) {
            return Err(PatchError::StoreFailed {
                source: Box::new(e),
            });
        }
        self.finish_publication(site, stop, PendingWord::Patch(patch_word))?;
        Ok(selected)
    }

    /// Complete a pending publication: re-sync the stored word and
    /// resume to settlement. For `RetainedStop` the stop authority is
    /// the retained one (acquire is idempotent-confirming there).
    pub fn complete_sync(
        &mut self,
        site: &mut Site,
        stop: &mut dyn StopControl,
    ) -> Result<(), PatchError> {
        self.check_fork()?;
        let pending = match site.state() {
            SiteState::SyncPending { pending } | SiteState::RetainedStop { pending } => pending,
            state => return Err(PatchError::WrongState { state }),
        };
        stop.acquire()?;
        // Re-read under the lease: syncing a word other than the one
        // publication stored would settle custody on garbage. On
        // mismatch the state is left untouched (still stopped).
        let expected = match pending {
            PendingWord::Patch(word) => word,
            PendingWord::Original => site.original_word(),
        };
        let found = site.read_word();
        if found != expected {
            return Err(PatchError::SiteWordChanged { expected, found });
        }
        self.finish_publication(site, stop, pending)
    }

    /// Roll back to the original word. From `Flipped` under a fresh
    /// lease, or directly from `SyncPending`/`RetainedStop` under the
    /// retained/re-acquired lease — each with its own post-store
    /// custody if the restoring sync or resume then fails. The island
    /// stays retained after a successful rollback (permanent retention
    /// choice in the design); it is never unmapped here.
    pub fn rollback(
        &mut self,
        site: &mut Site,
        stop: &mut dyn StopControl,
    ) -> Result<(), PatchError> {
        // Rollback performs a store, so the same capability gate as
        // flip applies before it.
        self.check_fork()?;
        if self.attested_token().is_none() {
            return Err(PatchError::CacheOpsUnavailable);
        }
        let flipped = match site.state() {
            SiteState::Flipped | SiteState::SyncPending { .. } | SiteState::RetainedStop { .. } => {
                site.flipped_word().ok_or(PatchError::WrongState {
                    state: site.state(),
                })?
            }
            state => return Err(PatchError::WrongState { state }),
        };
        stop.acquire()?;
        let found = site.read_word();
        // In SyncPending the stored word may be either side of an
        // interrupted transition; accept exactly the two known words.
        if found != flipped && found != site.original_word() {
            return if self.release_after_refusal(site, stop) {
                Err(PatchError::SiteWordChanged {
                    expected: flipped,
                    found,
                })
            } else {
                Err(PatchError::CleanupFailed {
                    expected: flipped,
                    found,
                })
            };
        }
        if let Err(e) = site.begin_write() {
            return if self.release_after_refusal(site, stop) {
                Err(e)
            } else {
                Err(PatchError::ResumeIncomplete)
            };
        }
        site.set_state(SiteState::SyncPending {
            pending: PendingWord::Original,
        });
        if let Err(e) = site.store_word(site.original_word()) {
            return Err(PatchError::StoreFailed {
                source: Box::new(e),
            });
        }
        self.finish_publication(site, stop, PendingWord::Original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::SiteRegistry;
    use liteinst_aarch64::svc;

    #[derive(Default)]
    struct FakeStop {
        acquires: u32,
        resumes: u32,
        resume_plan: Vec<Result<Vec<ResumeState>, PatchError>>,
    }

    // SAFETY (test): single-threaded fake; it only records calls and
    // returns scripted acknowledgements. It claims the lease contract
    // for the one-word sites these tests build on the stack.
    unsafe impl StopControl for FakeStop {
        fn acquire(&mut self) -> Result<(), PatchError> {
            self.acquires += 1;
            Ok(())
        }
        fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
            self.resumes += 1;
            if self.resume_plan.is_empty() {
                Ok(vec![ResumeState::Released])
            } else {
                self.resume_plan.remove(0)
            }
        }
    }

    unsafe fn sync_ok(_rw: *mut u8, _rx: *mut u8, _len: usize) -> Result<(), PatchError> {
        Ok(())
    }
    unsafe fn sync_fail(_rw: *mut u8, _rx: *mut u8, _len: usize) -> Result<(), PatchError> {
        Err(PatchError::Unsupported("injected sync failure"))
    }

    fn site_on(word: &mut u32, addr: u64) -> Site {
        // SAFETY (test): the backing word outlives the site in each test.
        unsafe { Site::from_aliases(addr, std::ptr::from_mut(word), *word, 7) }
    }

    fn trap_request() -> FlipRequest {
        trap_request_at(0x1000)
    }

    fn trap_request_at(addr: u64) -> FlipRequest {
        // SAFETY (test): claims a handler for this exact site; the
        // fake stop never executes the word.
        let route = unsafe { TrapRoute::arm(addr, 0x4c00, 7) };
        FlipRequest {
            island: None,
            strategy: StrategyPreference::TrapOnly,
            fallback: FallbackPermission::RefuseTrap,
            trap_route: Some(route),
            mapping_facts: None,
        }
    }

    #[test]
    fn misaligned_and_non_svc_sites_refuse_before_lease() {
        let mut patcher = Patcher::for_test(sync_fail);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1001);
        assert_eq!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Err(PatchError::MisalignedSite { addr: 0x1001 })
        );
        assert_eq!(stop.acquires, 0);
        let mut other = 0xd65f_03c0u32; // RET, not SVC
        let mut site = site_on(&mut other, 0x1000);
        assert_eq!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Err(PatchError::NotSvc { word: 0xd65f_03c0 })
        );
        assert_eq!(stop.acquires, 0);
    }

    #[test]
    fn strategy_refusals_write_nothing() {
        let mut patcher = Patcher::for_test(sync_fail);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let branch_only = FlipRequest {
            island: None,
            strategy: StrategyPreference::BranchOnly,
            fallback: FallbackPermission::AllowTrap,
            trap_route: None,
            mapping_facts: None,
        };
        assert!(matches!(
            patcher.flip(&mut site, branch_only, &mut stop),
            Err(PatchError::StrategyUnavailable(_))
        ));
        let unarmed = FlipRequest {
            island: None,
            strategy: StrategyPreference::TrapOnly,
            fallback: FallbackPermission::AllowTrap,
            trap_route: None,
            mapping_facts: None,
        };
        assert_eq!(
            patcher.flip(&mut site, unarmed, &mut stop),
            Err(PatchError::TrapNotArmed)
        );
        let wrong_gen = FlipRequest {
            island: None,
            strategy: StrategyPreference::TrapOnly,
            fallback: FallbackPermission::AllowTrap,
            // SAFETY (test): claims a route for a wrong generation.
            trap_route: Some(unsafe { TrapRoute::arm(0x1000, 0x4c00, 99) }),
            mapping_facts: None,
        };
        assert_eq!(
            patcher.flip(&mut site, wrong_gen, &mut stop),
            Err(PatchError::TrapNotArmed)
        );
        assert_eq!(word, svc(0));
        assert_eq!(site.state(), SiteState::Unpatched);
        assert_eq!(stop.acquires, 0);
    }

    #[test]
    fn changed_word_under_lease_refuses_and_releases() {
        let mut patcher = Patcher::for_test(sync_fail);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        // Someone changed the immediate after construction (written
        // through the alias the Site holds, as a racing writer would).
        unsafe { std::ptr::addr_of_mut!(word).write_volatile(svc(9)) };
        assert_eq!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Err(PatchError::SiteWordChanged {
                expected: svc(0),
                found: svc(9)
            })
        );
        assert_eq!(site.state(), SiteState::Unpatched);
        assert_eq!((stop.acquires, stop.resumes), (1, 1));
    }

    #[test]
    fn unattested_patcher_refuses_before_any_store() {
        // The reviewer's exact witness shape: Patcher::new() plus a
        // Trap flip must write nothing, whatever the strategy.
        let mut patcher = Patcher::new();
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        assert_eq!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Err(PatchError::CacheOpsUnavailable)
        );
        assert_eq!(word, svc(0));
        assert_eq!(site.state(), SiteState::Unpatched);
        assert_eq!(stop.acquires, 0);
    }

    #[test]
    fn trap_flip_with_failing_sync_lands_in_sync_pending_custody() {
        // Injected sync failure after the store must surface as
        // SyncPending(Patch) with the BRK word stored and the source
        // error preserved — never as "not flipped".
        let mut patcher = Patcher::for_test(sync_fail);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let result = patcher.flip(&mut site, trap_request(), &mut stop);
        assert!(matches!(result, Err(PatchError::SyncFailed { .. })));
        assert_eq!(
            site.state(),
            SiteState::SyncPending {
                pending: PendingWord::Patch(liteinst_aarch64::brk(0x4c00))
            }
        );
        assert_eq!(stop.resumes, 0, "no resume before sync completes");
        assert_eq!(word, liteinst_aarch64::brk(0x4c00));
        assert_eq!(site.flipped_word(), Some(liteinst_aarch64::brk(0x4c00)));
        // Second flip from a post-store state is refused by state.
        assert!(matches!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Err(PatchError::WrongState { .. })
        ));
        let _ = SiteRegistry::new();
    }

    #[test]
    fn rollback_from_sync_pending_restores_original_word() {
        let mut patcher = Patcher::for_test(sync_fail);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let _ = patcher.flip(&mut site, trap_request(), &mut stop);
        assert!(matches!(site.state(), SiteState::SyncPending { .. }));
        // Direct rollback transition: original restored synchronously,
        // settlement stays pending on Original (host sync refuses).
        assert!(matches!(
            patcher.rollback(&mut site, &mut stop),
            Err(PatchError::SyncFailed { .. })
        ));
        assert_eq!(word, svc(0));
        assert_eq!(
            site.state(),
            SiteState::SyncPending {
                pending: PendingWord::Original
            }
        );
    }

    #[test]
    fn complete_sync_keeps_pending_custody_when_sync_still_fails() {
        let mut patcher = Patcher::for_test(sync_fail);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let _ = patcher.flip(&mut site, trap_request(), &mut stop);
        assert!(matches!(
            patcher.complete_sync(&mut site, &mut stop),
            Err(PatchError::SyncFailed { .. })
        ));
        assert!(matches!(
            site.state(),
            SiteState::SyncPending {
                pending: PendingWord::Patch(_)
            }
        ));
    }

    #[test]
    fn trap_flip_settles_and_rolls_back_with_working_sync() {
        let mut patcher = Patcher::for_test(sync_ok);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        assert_eq!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Ok(Strategy::Trap)
        );
        assert_eq!(site.state(), SiteState::Flipped);
        assert_eq!(word, liteinst_aarch64::brk(0x4c00));
        patcher.rollback(&mut site, &mut stop).unwrap();
        assert_eq!(site.state(), SiteState::Unpatched);
        assert_eq!(word, svc(0));
        assert_eq!(site.flipped_word(), None);
    }

    #[test]
    fn route_for_another_address_is_not_armed_for_this_site() {
        let mut patcher = Patcher::for_test(sync_ok);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        // Armed token exists, but for a different site address.
        assert_eq!(
            patcher.flip(&mut site, trap_request_at(0x2000), &mut stop),
            Err(PatchError::TrapNotArmed)
        );
        assert_eq!(word, svc(0));
        assert_eq!(stop.acquires, 0);
    }

    #[test]
    fn incomplete_cleanup_after_changed_word_is_named() {
        let mut patcher = Patcher::for_test(sync_ok);
        let mut stop = FakeStop {
            resume_plan: vec![Ok(vec![ResumeState::Unknown])],
            ..FakeStop::default()
        };
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        unsafe { std::ptr::addr_of_mut!(word).write_volatile(svc(9)) };
        assert_eq!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Err(PatchError::CleanupFailed {
                expected: svc(0),
                found: svc(9)
            })
        );
        assert_eq!(site.state(), SiteState::Unpatched);
        assert_eq!(site.resume_states(), &[ResumeState::Unknown]);
    }

    #[test]
    fn complete_sync_refuses_to_settle_a_changed_word() {
        let mut patcher = Patcher::for_test(sync_fail);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let _ = patcher.flip(&mut site, trap_request(), &mut stop);
        // Corrupt the pending word; completion must not sync garbage.
        unsafe { std::ptr::addr_of_mut!(word).write_volatile(0xdead_beef) };
        assert_eq!(
            patcher.complete_sync(&mut site, &mut stop),
            Err(PatchError::SiteWordChanged {
                expected: liteinst_aarch64::brk(0x4c00),
                found: 0xdead_beef
            })
        );
        assert!(matches!(site.state(), SiteState::SyncPending { .. }));
    }

    struct FakeForeignStore {
        word: *mut u32,
        begins: u32,
        finishes: u32,
    }
    // SAFETY (test): tests never move the store across threads; the
    // pointer names the stack word each test owns for the site's
    // whole lifetime.
    unsafe impl Send for FakeForeignStore {}
    // SAFETY (test): see the Send note; begin/finish model a window
    // that always succeeds.
    unsafe impl crate::store::SiteStore for FakeForeignStore {
        fn read_word(&self) -> u32 {
            unsafe { self.word.read_volatile() }
        }
        fn write_addr(&self) -> u64 {
            self.word as u64
        }
        fn begin_write(&mut self) -> Result<(), PatchError> {
            self.begins += 1;
            Ok(())
        }
        fn store_word(&mut self, word: u32) -> Result<(), PatchError> {
            unsafe { self.word.write_volatile(word) };
            Ok(())
        }
        fn finish_write(&mut self) -> Result<(), PatchError> {
            self.finishes += 1;
            Ok(())
        }
    }

    #[test]
    fn foreign_site_flips_through_store_seam() {
        use crate::mapping::{MappingFacts, Provenance};
        let mut patcher = Patcher::for_test(sync_ok);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let facts = MappingFacts {
            page_span: (0x1000, 0x1000),
            orig_prot: 0,
            provenance: Provenance::PrivateFile,
            generation: 7,
        };
        let store = Box::new(FakeForeignStore {
            word: std::ptr::from_mut(&mut word),
            begins: 0,
            finishes: 0,
        });
        let mut site = unsafe { Site::from_rx(0x1000, svc(0), facts, store) }.unwrap();
        // Unattested-by-construction fork check passes (same process);
        // trap flip exercises begin/store/finish through the seam.
        assert_eq!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Ok(Strategy::Trap)
        );
        assert_eq!(word, liteinst_aarch64::brk(0x4c00));
        assert_eq!(site.state(), SiteState::Flipped);
        // Shared provenance refuses construction by name.
        let shared = MappingFacts {
            provenance: Provenance::Shared,
            ..facts
        };
        let store2 = Box::new(FakeForeignStore {
            word: std::ptr::from_mut(&mut word),
            begins: 0,
            finishes: 0,
        });
        assert!(matches!(
            unsafe { Site::from_rx(0x1000, svc(0), shared, store2) },
            Err(PatchError::MappingRefused(_))
        ));
    }

    #[test]
    fn forked_registry_refuses_before_lease() {
        let mut patcher = Patcher::for_test(sync_ok);
        patcher.set_owner_pid_for_test(std::process::id() + 99999);
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        assert_eq!(
            patcher.flip(&mut site, trap_request(), &mut stop),
            Err(PatchError::ForkedRegistry)
        );
        assert_eq!(word, svc(0));
        assert_eq!(stop.acquires, 0);
    }

    #[test]
    fn branch_word_requires_return_direction_reach() {
        // Both reviewer edges, through the actual selection helper the
        // flip calls: at the forward limit an 8-byte payload's return
        // branch is 4 bytes out of range (refuse), while the padded
        // mapping length would wrongly accept it — and conversely
        // wrongly refuse the in-range payload at the other edge.
        let site = 0x4000_0000u64;
        for mapped in [4096u64, 16384, 65536] {
            assert!(
                !return_reach_ok(site, site - (1 << 27), 8),
                "payload return out of range must refuse (mapped {mapped})"
            );
            assert!(
                liteinst_aarch64::emit::island_reaches(site, site - (1 << 27), mapped),
                "padded predicate documents the old wrong-accept (mapped {mapped})"
            );
            assert!(
                return_reach_ok(site, site + (1 << 27) - 4, 8),
                "payload return in range must accept (mapped {mapped})"
            );
            assert!(
                !liteinst_aarch64::emit::island_reaches(site, site + (1 << 27) - 4, mapped),
                "padded predicate documents the old wrong-refuse (mapped {mapped})"
            );
        }
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        {
            let island = Island::build(&[0; 4]).unwrap();
            let here = island.entry_addr();
            assert!(branch_word_checked(svc(0), here, &island).is_some());
        }
    }
}
