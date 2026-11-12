//! Patch-site identity, custody state, and the stop contract.
//! The flip protocol moves sites between the states defined here,
//! exactly as named in the design note.

use crate::PatchError;
use crate::island::Island;
use crate::mapping::MappingFacts;
use crate::store::{DualAliasStore, SiteStore};
use liteinst_aarch64::Reg;

/// Which stored word a pending sync will settle on completion. After a
/// rollback store lands but its sync fails, completion must settle
/// `Unpatched`, not `Flipped` — hence the payload (review P3 at
/// the design re-confirmation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingWord {
    /// The patch word was stored; completion settles `Flipped`.
    Patch(u32),
    /// The original word was re-stored by rollback; completion settles
    /// `Unpatched`.
    Original,
}

/// Lifecycle of one site. Transitions are the design's named graph:
/// `Unpatched -> Flipped -> SyncPending -> Flipped`, with rollbacks
/// from either post-store state back to `Unpatched`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteState {
    /// Original word in place; no island is referenced.
    Unpatched,
    /// Patch word stored and synced; island/handler custody retained.
    Flipped,
    /// A word was stored but sync or resume acknowledgement is
    /// incomplete; custody retained, recovery only via explicit
    /// completion toward `pending`.
    SyncPending {
        /// The word whose publication is being completed.
        pending: PendingWord,
    },
    /// Like `SyncPending`, with stop authority that must persist until
    /// the full executor set is re-stopped or acknowledged.
    RetainedStop {
        /// The word whose publication is being completed.
        pending: PendingWord,
    },
}

/// Per-executor resume bookkeeping under a publication lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeState {
    /// Stopped at an admitted point, not yet released.
    Parked,
    /// Context-synchronization rendezvous observed for this executor.
    SyncAcked,
    /// Released after its acknowledgement.
    Released,
    /// Acknowledgement lost or executor state unproven; retained
    /// custody applies and resume must not be blindly retried.
    Unknown,
}

/// Proof token inside [`TrapRoute`], constructible only by the
/// unsafe [`TrapRoute::arm`] constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapArmed(());

/// Owned trap-route registration for one exact site. A plain
/// `{brk_imm, generation}` pair proves nothing — it could be
/// fabricated in safe code with no handler installed — so the only
/// constructor is unsafe and binds address + immediate + generation
/// to a handler the caller guarantees is installed and remains owned
/// for as long as any site retains this route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapRoute {
    addr: u64,
    brk_imm: u16,
    generation: u64,
    armed: TrapArmed,
}

impl TrapRoute {
    /// Arm a route for exactly one site.
    ///
    /// # Safety
    /// A handler for `BRK #brk_imm` at `addr` (site `generation`) must
    /// already be installed, must preserve guest state apart from its
    /// documented result/continuation, and must remain installed and
    /// owned **until the published BRK word itself is retired**
    /// (rollback/rewrite has landed and possible delivery is
    /// discharged) or the session ends. That obligation is tied to the
    /// published word, not to any Rust value's lifetime: dropping this
    /// token, the retaining `Site`, or a registry discharges nothing,
    /// and deregistering while the BRK remains reachable leaves it
    /// trapping into an unowned handler.
    pub unsafe fn arm(addr: u64, brk_imm: u16, generation: u64) -> Self {
        Self {
            addr,
            brk_imm,
            generation,
            armed: TrapArmed(()),
        }
    }

    /// The exact site address this route was armed for.
    pub fn addr(&self) -> u64 {
        self.addr
    }

    /// The reserved `BRK` immediate for this site.
    pub fn brk_imm(&self) -> u16 {
        self.brk_imm
    }

    /// Site generation the registration was armed for.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// One patchable site: identity, retained original word, state, and —
/// once flipped — custody of the island and trap route it references.
///
/// Fields are private. Construction is the unsafe
/// [`Site::from_aliases`]; there is no safe constructor from integers.
pub struct Site {
    rx_addr: u64,
    store: Box<dyn SiteStore>,
    facts: Option<MappingFacts>,
    original_word: u32,
    generation: u64,
    state: SiteState,
    flipped_word: Option<u32>,
    resume_states: Vec<ResumeState>,
    island: Option<Island>,
    trap_route: Option<TrapRoute>,
}

impl core::fmt::Debug for Site {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Site")
            .field("rx_addr", &self.rx_addr)
            .field("original_word", &self.original_word)
            .field("generation", &self.generation)
            .field("state", &self.state)
            .field("has_island", &self.island.is_some())
            .field("trap_route", &self.trap_route)
            .finish()
    }
}

impl Site {
    /// Construct a site from its dual aliases.
    ///
    /// # Safety
    /// `rx_addr` and `rw_alias` must name the same physical word in one
    /// shared backing that outlives this site and any flip; the word at
    /// `rx_addr` must currently equal `original_word`; `generation`
    /// must identify the mapping generation both aliases belong to; and
    /// no other live `Site` or writer may name this address. Violating
    /// any of these can publish a branch into unrelated memory.
    pub unsafe fn from_aliases(
        rx_addr: u64,
        rw_alias: *mut u32,
        original_word: u32,
        generation: u64,
    ) -> Self {
        Self {
            rx_addr,
            store: Box::new(DualAliasStore::new(rw_alias)),
            facts: None,
            original_word,
            generation,
            state: SiteState::Unpatched,
            flipped_word: None,
            resume_states: Vec::new(),
            island: None,
            trap_route: None,
        }
    }

    /// Construct a foreign-text site from its RX address, qualified
    /// mapping facts, and the downstream store that will write it.
    /// Refuses facts that do not contain the address or are not
    /// windowable; the generation is taken from the facts.
    ///
    /// # Safety
    /// `store` must name the same physical word the CPU executes at
    /// `rx_addr` for `facts.generation`; the word at `rx_addr` must
    /// currently equal `original_word`; and no other live `Site` or
    /// writer may name this address (see [`SiteStore`]).
    pub unsafe fn from_rx(
        rx_addr: u64,
        original_word: u32,
        facts: MappingFacts,
        store: Box<dyn SiteStore>,
    ) -> Result<Self, PatchError> {
        if !facts.contains(rx_addr) {
            return Err(PatchError::MappingRefused(
                "site address outside qualified page span",
            ));
        }
        if !facts.windowable() {
            return Err(PatchError::MappingRefused(
                "shared or indeterminate mapping provenance",
            ));
        }
        Ok(Self {
            rx_addr,
            store,
            generation: facts.generation,
            facts: Some(facts),
            original_word,
            state: SiteState::Unpatched,
            flipped_word: None,
            resume_states: Vec::new(),
            island: None,
            trap_route: None,
        })
    }

    /// The qualified mapping facts, when constructed via `from_rx`.
    pub fn mapping_facts(&self) -> Option<MappingFacts> {
        self.facts
    }

    /// Executable address of the site word.
    pub fn addr(&self) -> u64 {
        self.rx_addr
    }

    /// The exact original word retained for revalidation and rollback.
    pub fn original_word(&self) -> u32 {
        self.original_word
    }

    /// Mapping generation recorded at construction.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Current custody state.
    pub fn state(&self) -> SiteState {
        self.state
    }

    /// Protocol-internal state transition (flip slice). Wired by the
    /// flip/rollback slice; the custody tests already drive it.
    #[allow(dead_code)]
    pub(crate) fn set_state(&mut self, state: SiteState) {
        self.state = state;
    }

    /// Protocol-internal: take island custody before a store.
    #[allow(dead_code)]
    pub(crate) fn retain_island(&mut self, island: Island) {
        self.island = Some(island);
    }

    /// Protocol-internal: retain the armed trap route.
    #[allow(dead_code)]
    pub(crate) fn retain_trap_route(&mut self, route: TrapRoute) {
        self.trap_route = Some(route);
    }

    /// The armed trap route, if custody holds one.
    pub fn trap_route(&self) -> Option<TrapRoute> {
        self.trap_route
    }

    /// The patch word stored by the in-flight or completed flip.
    pub fn flipped_word(&self) -> Option<u32> {
        self.flipped_word
    }

    /// Per-executor resume states from the latest resume attempt.
    pub fn resume_states(&self) -> &[ResumeState] {
        &self.resume_states
    }

    /// Protocol-internal: record the word about to be stored.
    pub(crate) fn set_flipped_word(&mut self, word: Option<u32>) {
        self.flipped_word = word;
    }

    /// Protocol-internal: record per-executor resume outcomes.
    pub(crate) fn set_resume_states(&mut self, states: Vec<ResumeState>) {
        self.resume_states = states;
    }

    /// Protocol-internal: read the current site word through the
    /// store's RX view of the same physical word.
    pub(crate) fn read_word(&self) -> u32 {
        self.store.read_word()
    }

    /// Protocol-internal: the store's write address for sync ranges.
    pub(crate) fn write_addr(&self) -> u64 {
        self.store.write_addr()
    }

    pub(crate) fn begin_write(&mut self) -> Result<(), PatchError> {
        self.store.begin_write()
    }

    pub(crate) fn store_word(&mut self, word: u32) -> Result<(), PatchError> {
        self.store.store_word(word)
    }

    pub(crate) fn finish_write(&mut self) -> Result<(), PatchError> {
        self.store.finish_write()
    }
}

/// Strategy inputs for one flip, chosen before any write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyPreference {
    /// Only the near-island branch; refuse without a reachable island.
    BranchOnly,
    /// Only the trap word; refuse without an armed owned route.
    TrapOnly,
    /// Branch when reachable, else trap (each only if permitted).
    BranchThenTrap,
}

/// Explicit permission for `patch_svc`'s fallback leg, kept distinct
/// from preference so "no island" cannot silently become "trap".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackPermission {
    /// Trap fallback may be selected when armed.
    AllowTrap,
    /// Refuse rather than trap.
    RefuseTrap,
}

/// The stop/lease authority a flip runs under. `acquire` must be
/// idempotent-confirming: calling it while a stop from an earlier
/// flip attempt is still retained (post-store custody) succeeds
/// without releasing anyone.
///
/// # Safety
/// Implementors guarantee the exclusive publication lease: every
/// thread that may execute the site or island is accounted and stopped
/// at admitted points (never at the site word, never inside the island
/// during rollback/retirement), thread membership and both mapping
/// generations are frozen with no other writer, and resume releases
/// each executor only after its context-synchronization rendezvous
/// (see `ResumeState`). The patcher treats these guarantees as axioms;
/// a lying implementation makes every flip unsound.
pub unsafe trait StopControl {
    /// Acquire the lease and stop the full executor set.
    fn acquire(&mut self) -> Result<(), PatchError>;
    /// Resume all executors, returning each one's tracked state. An
    /// `Unknown` entry is retained custody, not a retry invitation.
    fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError>;
}

impl Drop for Site {
    fn drop(&mut self) {
        // Retention-on-Drop (design): while any published word may
        // still reference the island, unmapping it would leave a live
        // branch into unmapped memory. Leak the island deliberately
        // (bounded by the session) instead. This also covers unwind
        // paths, which run the same destructor. The trap-route token
        // needs no code here precisely because its handler obligation
        // is tied to the published BRK word's lifetime, not to this
        // value: dropping the token deregisters nothing, and the
        // caller must keep the handler installed until the BRK is
        // retired (see TrapRoute::arm).
        let published = !matches!(self.state, SiteState::Unpatched);
        if published && let Some(island) = self.island.take() {
            island.disarm();
        }
    }
}

/// Site-owning registry: a second live [`Site`] for one address is
/// refused. (This detects duplicates built through the patcher; the
/// unsafe construction contract remains the primary guarantee.)
#[derive(Debug, Default)]
pub struct SiteRegistry {
    sites: Vec<Site>,
}

impl SiteRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `site`, refusing a second live site at its address.
    pub fn register(&mut self, site: Site) -> Result<&mut Site, PatchError> {
        if self.sites.iter().any(|s| s.addr() == site.addr()) {
            return Err(PatchError::DuplicateSite { addr: site.addr() });
        }
        self.sites.push(site);
        Ok(self.sites.last_mut().expect("just pushed"))
    }

    /// Look up a registered site by address.
    pub fn site_mut(&mut self, addr: u64) -> Option<&mut Site> {
        self.sites.iter_mut().find(|s| s.addr() == addr)
    }

    /// Number of registered sites.
    pub fn len(&self) -> usize {
        self.sites.len()
    }

    /// Whether no sites are registered.
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }
}

/// Register-number re-export for request builders (checked encoders in
/// the fact crate own refusal of out-of-range values).
pub type PatchReg = Reg;

#[cfg(test)]
mod tests {
    use super::*;

    fn site_at(word: &mut u32, addr: u64) -> Site {
        // SAFETY (test): word outlives the Site within each test and no
        // second writer exists; the pointer is never dereferenced here.
        unsafe { Site::from_aliases(addr, std::ptr::from_mut(word), *word, 1) }
    }

    #[test]
    fn registry_refuses_duplicate_site_addresses() {
        let mut a = 0xd400_0001u32;
        let mut b = 0xd400_0001u32;
        let mut reg = SiteRegistry::new();
        reg.register(site_at(&mut a, 0x4000)).unwrap();
        assert_eq!(
            reg.register(site_at(&mut b, 0x4000)).unwrap_err(),
            PatchError::DuplicateSite { addr: 0x4000 }
        );
        assert_eq!(reg.len(), 1);
        reg.register(site_at(&mut b, 0x4004)).unwrap();
        assert_eq!(reg.len(), 2);
        let site = reg.site_mut(0x4000).unwrap();
        assert_eq!(site.state(), SiteState::Unpatched);
        assert_eq!(site.original_word(), 0xd400_0001);
        assert_eq!(site.generation(), 1);
    }

    #[test]
    fn custody_skeleton_holds_state_route_and_alias() {
        // Slice-2 custody shapes the flip protocol will drive: state
        // transitions, retained trap route, and the writable alias.
        let mut word = 0xd400_0001u32;
        let mut site = site_at(&mut word, 0x8000);
        // SAFETY (test): claims an armed route for this stack site.
        site.retain_trap_route(unsafe { TrapRoute::arm(0x8000, 0x4c00, 1) });
        let route = site.trap_route().unwrap();
        assert_eq!(route.addr(), 0x8000);
        assert_eq!(route.brk_imm(), 0x4c00);
        assert_eq!(route.generation(), 1);
        for state in [
            SiteState::Flipped,
            SiteState::SyncPending {
                pending: PendingWord::Patch(0x1400_0000),
            },
            SiteState::SyncPending {
                pending: PendingWord::Original,
            },
            SiteState::RetainedStop {
                pending: PendingWord::Original,
            },
            SiteState::Unpatched,
        ] {
            site.set_state(state);
            assert_eq!(site.state(), state);
        }
        // SAFETY (test): alias names `word`, which outlives the site.
        assert_eq!(site.read_word(), 0xd400_0001);
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        {
            let island = crate::island::Island::build(&[0xd503_24df]).unwrap();
            site.retain_island(island);
            site.set_state(SiteState::Flipped);
        }
    }
}
