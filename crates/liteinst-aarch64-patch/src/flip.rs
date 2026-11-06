//! The flip protocol: strategy selection before any write, lease,
//! revalidation, one aligned store, sync, acknowledged resume — plus
//! `complete_sync` recovery and rollback (including direct rollback
//! from `SyncPending`). Post-store failures are custody states, never
//! "not flipped": this module records `Flipped` custody the instant
//! the store lands and only settles it through the named transitions.

use crate::island::Island;
use crate::site::{
    FallbackPermission, PendingWord, ResumeState, Site, SiteState, StopControl, StrategyPreference,
    TrapRoute,
};
use crate::{PatchError, Patcher, cache};
use liteinst_aarch64::Insn;
use liteinst_aarch64::emit::{Strategy, svc_fallback_word, svc_patch_word};

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
}

impl core::fmt::Debug for FlipRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FlipRequest")
            .field("has_island", &self.island.is_some())
            .field("strategy", &self.strategy)
            .field("fallback", &self.fallback)
            .field("trap_route", &self.trap_route)
            .finish()
    }
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
        unsafe { cache::sync_icache(site.rw_word_const() as *mut u8, site.addr() as *mut u8, 4) }
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
        if let Err(e) = self.sync_site(site) {
            site.set_state(if matches!(site.state(), SiteState::RetainedStop { .. }) {
                SiteState::RetainedStop { pending }
            } else {
                SiteState::SyncPending { pending }
            });
            let _ = e;
            return Err(PatchError::SyncFailed);
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
        } = request;
        // Strategy selection is fully decided before the lease/store.
        let branch_word = island
            .as_ref()
            .and_then(|i| svc_patch_word(original, site.addr(), i.entry_addr()));
        let trap_armed = trap_route
            .as_ref()
            .is_some_and(|route| route.generation == site.generation());
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
                    svc_fallback_word(original, trap_route.expect("armed").brk_imm)
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
                        svc_fallback_word(original, trap_route.expect("armed").brk_imm)
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
                .as_ref()
                .expect("branch selected with island")
                .publish(attested)?;
        }
        stop.acquire()?;
        // Everything below runs under the lease; pre-store exits must
        // release it (best-effort resume, outcome recorded if visible).
        let found = site.read_word();
        if found != original {
            if let Ok(states) = stop.resume() {
                site.set_resume_states(states);
            }
            return Err(PatchError::SiteWordChanged {
                expected: original,
                found,
            });
        }
        // Custody transfer before the store: from here the site owns
        // the island/route across every later outcome.
        if let Some(island) = island {
            site.retain_island(island);
        }
        if let Some(route) = trap_route {
            site.retain_trap_route(route);
        }
        site.set_flipped_word(Some(patch_word));
        site.set_state(SiteState::SyncPending {
            pending: PendingWord::Patch(patch_word),
        });
        // The design's one aligned store.
        // SAFETY: lease held, word revalidated, alias per Site contract.
        unsafe { site.rw_word().write_volatile(patch_word) };
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
        let pending = match site.state() {
            SiteState::SyncPending { pending } | SiteState::RetainedStop { pending } => pending,
            state => return Err(PatchError::WrongState { state }),
        };
        stop.acquire()?;
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
            if let Ok(states) = stop.resume() {
                site.set_resume_states(states);
            }
            return Err(PatchError::SiteWordChanged {
                expected: flipped,
                found,
            });
        }
        site.set_state(SiteState::SyncPending {
            pending: PendingWord::Original,
        });
        // SAFETY: lease held, word revalidated, alias per Site contract.
        unsafe { site.rw_word().write_volatile(site.original_word()) };
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

    fn site_on(word: &mut u32, addr: u64) -> Site {
        // SAFETY (test): the backing word outlives the site in each test.
        unsafe { Site::from_aliases(addr, std::ptr::from_mut(word), *word, 7) }
    }

    fn trap_request() -> FlipRequest {
        FlipRequest {
            island: None,
            strategy: StrategyPreference::TrapOnly,
            fallback: FallbackPermission::RefuseTrap,
            trap_route: Some(TrapRoute {
                brk_imm: 0x4c00,
                generation: 7,
            }),
        }
    }

    #[test]
    fn misaligned_and_non_svc_sites_refuse_before_lease() {
        let mut patcher = Patcher::new();
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
        let mut patcher = Patcher::new();
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let branch_only = FlipRequest {
            island: None,
            strategy: StrategyPreference::BranchOnly,
            fallback: FallbackPermission::AllowTrap,
            trap_route: None,
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
        };
        assert_eq!(
            patcher.flip(&mut site, unarmed, &mut stop),
            Err(PatchError::TrapNotArmed)
        );
        let wrong_gen = FlipRequest {
            island: None,
            strategy: StrategyPreference::TrapOnly,
            fallback: FallbackPermission::AllowTrap,
            trap_route: Some(TrapRoute {
                brk_imm: 0x4c00,
                generation: 99,
            }),
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
        let mut patcher = Patcher::new();
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
    fn trap_flip_on_this_host_lands_in_sync_pending_custody() {
        // On non-AArch64 hosts the sync step returns Unsupported, which
        // the protocol must surface as SyncPending(Patch) with the BRK
        // word stored — never as "not flipped". (On AArch64 the same
        // path settles Flipped; that leg is the exec proof's job.)
        let mut patcher = Patcher::new();
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let result = patcher.flip(&mut site, trap_request(), &mut stop);
        if cfg!(target_arch = "aarch64") {
            assert_eq!(result, Ok(Strategy::Trap));
            assert_eq!(site.state(), SiteState::Flipped);
        } else {
            assert_eq!(result, Err(PatchError::SyncFailed));
            assert_eq!(
                site.state(),
                SiteState::SyncPending {
                    pending: PendingWord::Patch(liteinst_aarch64::brk(0x4c00))
                }
            );
            assert_eq!(stop.resumes, 0, "no resume before sync completes");
        }
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
        if cfg!(target_arch = "aarch64") {
            return; // host path settles Flipped; rollback-from-Flipped
            // is covered by the AArch64 execution proofs.
        }
        let mut patcher = Patcher::new();
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let _ = patcher.flip(&mut site, trap_request(), &mut stop);
        assert!(matches!(site.state(), SiteState::SyncPending { .. }));
        // Direct rollback transition: original restored synchronously,
        // settlement stays pending on Original (host sync refuses).
        assert_eq!(
            patcher.rollback(&mut site, &mut stop),
            Err(PatchError::SyncFailed)
        );
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
        if cfg!(target_arch = "aarch64") {
            return; // sync succeeds there; settlement is exec-proof scope
        }
        let mut patcher = Patcher::new();
        let mut stop = FakeStop::default();
        let mut word = svc(0);
        let mut site = site_on(&mut word, 0x1000);
        let _ = patcher.flip(&mut site, trap_request(), &mut stop);
        assert_eq!(
            patcher.complete_sync(&mut site, &mut stop),
            Err(PatchError::SyncFailed)
        );
        assert!(matches!(
            site.state(),
            SiteState::SyncPending {
                pending: PendingWord::Patch(_)
            }
        ));
    }
}
