//! Typed syscall-interception strategy vocabulary for the x86-64
//! zpoline/lazypoline series.
//!
//! This module is intentionally selection-only in slice 1: constructing or
//! parsing a config does not install a handler, map a low page, enable a
//! discovery substrate, or patch a syscall site. Runtime slices consume these
//! names without inventing a second vocabulary.

use std::ffi::OsStr;
use std::fmt;

/// Concrete in-process syscall interception mechanism selected for one run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallStrategy {
    /// Leave syscall instructions in place and use a host-supplied trap
    /// substrate for every intercepted call.
    Trap,
    /// Eagerly rewrite eligible native `syscall` instructions to `call *%rax`
    /// and dispatch through the low-page sled.
    Zpoline,
    /// Discover each syscall site through a first-use trap, then rewrite that
    /// proven site to the zpoline form.
    Lazypoline,
}

impl SyscallStrategy {
    /// Returns the canonical liteinst config token.
    pub const fn token(self) -> &'static str {
        match self {
            Self::Trap => "trap",
            Self::Zpoline => "zpoline",
            Self::Lazypoline => "lazypoline",
        }
    }

    /// Parses one canonical liteinst config token.
    pub fn from_token(value: &str) -> Result<Self, SyscallRefusal> {
        match value {
            "trap" => Ok(Self::Trap),
            "zpoline" => Ok(Self::Zpoline),
            "lazypoline" => Ok(Self::Lazypoline),
            _ => Err(SyscallRefusal::UnknownStrategy),
        }
    }

    /// Parses an environment-style value. `None` means the value was absent;
    /// the caller derives and reports its default, rather than this parser
    /// silently choosing one.
    pub fn from_env_value(value: Option<&OsStr>) -> Result<Option<Self>, SyscallRefusal> {
        let Some(value) = value else {
            return Ok(None);
        };
        let value = value.to_str().ok_or(SyscallRefusal::NonUtf8Strategy)?;
        Self::from_token(value).map(Some)
    }

    /// Returns the coarse S4 `REVERIE_INTERCEPT` token refined by this
    /// mechanism and, for the trap baseline, its discovery substrate.
    pub const fn reverie_token(self, discovery: DiscoverySubstrate) -> &'static str {
        match (self, discovery) {
            (Self::Trap, DiscoverySubstrate::Sud) => "sud-trap",
            (Self::Trap, DiscoverySubstrate::SeccompRetTrap) => "trap",
            (Self::Zpoline, _) => "patch-eager",
            (Self::Lazypoline, _) => "trap-and-patch",
        }
    }
}

/// What happens when one otherwise selected site cannot use the fast path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FallbackPolicy {
    /// Serve that site through the trap substrate and count it as `Trap`.
    #[default]
    Trap,
    /// Refuse rather than downgrade that site.
    Refuse,
}

impl FallbackPolicy {
    /// Returns the canonical liteinst config token.
    pub const fn token(self) -> &'static str {
        match self {
            Self::Trap => "trap",
            Self::Refuse => "refuse",
        }
    }

    /// Parses one canonical liteinst config token.
    pub fn from_token(value: &str) -> Result<Self, SyscallRefusal> {
        match value {
            "trap" => Ok(Self::Trap),
            "refuse" => Ok(Self::Refuse),
            _ => Err(SyscallRefusal::UnknownFallbackPolicy),
        }
    }

    /// Parses an environment-style value; absence returns `None`.
    pub fn from_env_value(value: Option<&OsStr>) -> Result<Option<Self>, SyscallRefusal> {
        let Some(value) = value else {
            return Ok(None);
        };
        let value = value
            .to_str()
            .ok_or(SyscallRefusal::NonUtf8FallbackPolicy)?;
        Self::from_token(value).map(Some)
    }
}

/// Pluggable first-use discovery substrate for lazypoline.
///
/// The substrate reports a genuine syscall instruction boundary to the
/// runtime; it does not by itself authorize rewriting that site.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DiscoverySubstrate {
    /// Linux Syscall User Dispatch. This is a runtime-probed x86-64-only
    /// option, retained for its selector-allow fast path; it is not the
    /// default because only one owner can enable it per thread.
    Sud,
    /// Seccomp `RET_TRAP`, with an instruction-pointer allow range for the
    /// private gateway. This is the default portable substrate shared with
    /// the W3 trap runtime in a later slice.
    #[default]
    SeccompRetTrap,
}

impl DiscoverySubstrate {
    /// Returns the canonical liteinst config token.
    pub const fn token(self) -> &'static str {
        match self {
            Self::Sud => "sud",
            Self::SeccompRetTrap => "seccomp-ret-trap",
        }
    }

    /// Parses one canonical liteinst config token.
    pub fn from_token(value: &str) -> Result<Self, SyscallRefusal> {
        match value {
            "sud" => Ok(Self::Sud),
            "seccomp-ret-trap" => Ok(Self::SeccompRetTrap),
            _ => Err(SyscallRefusal::UnknownDiscoverySubstrate),
        }
    }

    /// Parses an environment-style value; absence returns `None`.
    pub fn from_env_value(value: Option<&OsStr>) -> Result<Option<Self>, SyscallRefusal> {
        let Some(value) = value else {
            return Ok(None);
        };
        let value = value
            .to_str()
            .ok_or(SyscallRefusal::NonUtf8DiscoverySubstrate)?;
        Self::from_token(value).map(Some)
    }
}

/// One bounded family in the trampoline placement ladder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementFamily {
    /// Probe free pages near mapped executable objects.
    NearAllocation,
    /// Build through a writable memfd alias and execute through a separate
    /// read/execute alias.
    MemfdDualMap,
    /// Map the zpoline sled page at virtual address zero.
    LowPage,
    /// Reach a farther handler body through a nearby entry veneer.
    TwoHopVeneer,
    /// Leave the site unpatched and use the trap substrate.
    Trap,
}

impl PlacementFamily {
    /// Returns the canonical diagnostic token.
    pub const fn token(self) -> &'static str {
        match self {
            Self::NearAllocation => "near-allocation",
            Self::MemfdDualMap => "memfd-dual-map",
            Self::LowPage => "low-page",
            Self::TwoHopVeneer => "two-hop-veneer",
            Self::Trap => "trap",
        }
    }
}

/// The complete bounded placement ladder. Low-page availability is a
/// run-level prerequisite for both fast paths; the other families place the
/// sled backing or handler and cannot substitute for virtual address zero.
pub const PLACEMENT_LADDER: [PlacementFamily; 5] = [
    PlacementFamily::NearAllocation,
    PlacementFamily::MemfdDualMap,
    PlacementFamily::LowPage,
    PlacementFamily::TwoHopVeneer,
    PlacementFamily::Trap,
];

/// Explicit resource bounds for sled, handler, and veneer placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlacementBudget {
    max_candidates: usize,
    max_mappings: usize,
    max_mapped_bytes: usize,
}

impl PlacementBudget {
    /// Default bounded search used by the first x86-64 profile. The mapped
    /// byte bound covers two host pages at either 4 KiB or 64 KiB page size.
    pub const DEFAULT: Self = Self {
        max_candidates: 256,
        max_mappings: 2,
        max_mapped_bytes: 131_072,
    };

    /// Creates a validated placement budget.
    pub fn new(
        max_candidates: usize,
        max_mappings: usize,
        max_mapped_bytes: usize,
    ) -> Result<Self, SyscallRefusal> {
        let budget = Self {
            max_candidates,
            max_mappings,
            max_mapped_bytes,
        };
        budget.validate()?;
        Ok(budget)
    }

    /// Maximum placement candidates considered across the bounded ladder.
    pub const fn max_candidates(self) -> usize {
        self.max_candidates
    }

    /// Maximum new mappings retained for sled and handler placement.
    pub const fn max_mappings(self) -> usize {
        self.max_mappings
    }

    /// Maximum newly mapped placement bytes retained.
    pub const fn max_mapped_bytes(self) -> usize {
        self.max_mapped_bytes
    }

    fn validate(self) -> Result<(), SyscallRefusal> {
        if self.max_candidates == 0 {
            return Err(SyscallRefusal::InvalidConfig {
                field: "placement.max_candidates",
                reason: "must be nonzero",
            });
        }
        if self.max_mappings == 0 {
            return Err(SyscallRefusal::InvalidConfig {
                field: "placement.max_mappings",
                reason: "must be nonzero",
            });
        }
        if self.max_mapped_bytes == 0 {
            return Err(SyscallRefusal::InvalidConfig {
                field: "placement.max_mapped_bytes",
                reason: "must be nonzero",
            });
        }
        Ok(())
    }
}

impl Default for PlacementBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Native x86-64 syscall numbers admitted by the first forwarding profile.
pub const FIRST_PROFILE_SYSCALLS: [u32; 4] = [
    libc::SYS_read as u32,
    libc::SYS_write as u32,
    libc::SYS_getpid as u32,
    libc::SYS_gettid as u32,
];

/// Returns true when `number` is in the first forwarding profile. Callers
/// pass the low 32 bits used by Linux native dispatch; range proof for the
/// full RAX value remains a separate site-admission obligation.
pub const fn first_profile_supports(number: u32) -> bool {
    matches!(
        number,
        x if x == FIRST_PROFILE_SYSCALLS[0]
            || x == FIRST_PROFILE_SYSCALLS[1]
            || x == FIRST_PROFILE_SYSCALLS[2]
            || x == FIRST_PROFILE_SYSCALLS[3]
    )
}

/// One frozen, validated syscall-strategy selection for a process/run.
///
/// The discovery substrate is meaningful to lazypoline and to a trap
/// baseline; zpoline retains the value so one complete selection can be
/// reported without a second config shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SyscallStrategyConfig {
    strategy: SyscallStrategy,
    fallback: FallbackPolicy,
    discovery: DiscoverySubstrate,
    max_sites: usize,
    max_syscall_nr: u32,
    placement: PlacementBudget,
}

impl SyscallStrategyConfig {
    /// Largest site-registry bound accepted by this vocabulary.
    pub const MAX_SITES_LIMIT: usize = 262_144;
    /// Largest inclusive syscall number that can land before a common stub
    /// in the smallest supported host page.
    pub const MAX_SYSCALL_NR_LIMIT: u32 = 4_079;

    /// Creates the approved first-profile defaults for `strategy`:
    /// per-site trap fallback, seccomp discovery, at most 16,384 sites, and
    /// an inclusive sled syscall-number bound of 1,023.
    pub const fn new(strategy: SyscallStrategy) -> Self {
        Self {
            strategy,
            fallback: FallbackPolicy::Trap,
            discovery: DiscoverySubstrate::SeccompRetTrap,
            max_sites: 16_384,
            max_syscall_nr: 1_023,
            placement: PlacementBudget::DEFAULT,
        }
    }

    /// Selected concrete mechanism.
    pub const fn strategy(self) -> SyscallStrategy {
        self.strategy
    }

    /// Per-site fallback policy.
    pub const fn fallback(self) -> FallbackPolicy {
        self.fallback
    }

    /// Selected first-use discovery substrate.
    pub const fn discovery(self) -> DiscoverySubstrate {
        self.discovery
    }

    /// Maximum distinct sites retained by a runtime registry/census.
    pub const fn max_sites(self) -> usize {
        self.max_sites
    }

    /// Inclusive largest canonical syscall number admitted to the sled.
    pub const fn max_syscall_nr(self) -> u32 {
        self.max_syscall_nr
    }

    /// Bounded placement resources.
    pub const fn placement(self) -> PlacementBudget {
        self.placement
    }

    /// Returns a copy with a different per-site fallback policy.
    pub fn with_fallback(mut self, fallback: FallbackPolicy) -> Result<Self, SyscallRefusal> {
        self.fallback = fallback;
        self.validate()?;
        Ok(self)
    }

    /// Returns a copy with a different discovery substrate.
    pub fn with_discovery(mut self, discovery: DiscoverySubstrate) -> Result<Self, SyscallRefusal> {
        self.discovery = discovery;
        self.validate()?;
        Ok(self)
    }

    /// Returns a copy with a different site-registry bound.
    pub fn with_max_sites(mut self, max_sites: usize) -> Result<Self, SyscallRefusal> {
        self.max_sites = max_sites;
        self.validate()?;
        Ok(self)
    }

    /// Returns a copy with a different inclusive sled syscall-number bound.
    pub fn with_max_syscall_nr(mut self, max_syscall_nr: u32) -> Result<Self, SyscallRefusal> {
        self.max_syscall_nr = max_syscall_nr;
        self.validate()?;
        Ok(self)
    }

    /// Returns a copy with different placement bounds.
    pub fn with_placement(mut self, placement: PlacementBudget) -> Result<Self, SyscallRefusal> {
        self.placement = placement;
        self.validate()?;
        Ok(self)
    }

    /// Validates structural bounds. This does not probe the host, modify
    /// process state, or claim that the selected strategy can be installed.
    pub fn validate(self) -> Result<(), SyscallRefusal> {
        if self.max_sites == 0 || self.max_sites > Self::MAX_SITES_LIMIT {
            return Err(SyscallRefusal::InvalidConfig {
                field: "max_sites",
                reason: "must be within 1..=262144",
            });
        }
        let first_profile_max = FIRST_PROFILE_SYSCALLS[0]
            .max(FIRST_PROFILE_SYSCALLS[1])
            .max(FIRST_PROFILE_SYSCALLS[2])
            .max(FIRST_PROFILE_SYSCALLS[3]);
        if self.max_syscall_nr < first_profile_max
            || self.max_syscall_nr > Self::MAX_SYSCALL_NR_LIMIT
        {
            return Err(SyscallRefusal::InvalidConfig {
                field: "max_syscall_nr",
                reason: "must cover the first profile and fit before the sled stub",
            });
        }
        self.placement.validate()
    }
}

/// Current disposition of one candidate syscall site. Trap is complete
/// interception only when a substrate actually serves the site; it is never
/// reported as a rewrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteOutcome {
    /// The site was eagerly rewritten by zpoline.
    RewrittenZpoline,
    /// The site was discovered by a trap and then rewritten by lazypoline.
    RewrittenLazypoline,
    /// The original syscall remains in place for the trap substrate.
    Trap,
    /// The site was not admitted, with the exact named cause retained.
    Refused(SyscallRefusal),
}

/// Named fail-closed cause for strategy selection, installation, placement,
/// or one candidate site. A refusal never means a fallback was installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallRefusal {
    /// A structural configuration bound is invalid.
    InvalidConfig {
        /// Configuration field that failed validation.
        field: &'static str,
        /// Stable validation rule for that field.
        reason: &'static str,
    },
    /// Strategy token is not trap, zpoline, or lazypoline.
    UnknownStrategy,
    /// Strategy environment value is not valid UTF-8.
    NonUtf8Strategy,
    /// Fallback token is not trap or refuse.
    UnknownFallbackPolicy,
    /// Fallback environment value is not valid UTF-8.
    NonUtf8FallbackPolicy,
    /// Discovery token is not sud or seccomp-ret-trap.
    UnknownDiscoverySubstrate,
    /// Discovery environment value is not valid UTF-8.
    NonUtf8DiscoverySubstrate,
    /// The selected mechanism has no implementation on this architecture.
    StrategyUnavailableOnArch,
    /// The selected mechanism has no implementation in this backend yet.
    StrategyUnavailableOnBackend,
    /// A process-lifetime strategy owner is already installed.
    StrategyAlreadyInstalled,
    /// A different process-lifetime strategy config is already installed.
    ConflictingStrategyInstalled,
    /// The target process cannot map the sled at virtual address zero.
    LowPageUnavailable {
        /// Exact operating-system error from the mapping probe.
        errno: i32,
    },
    /// A mapping already occupies part of the required low page.
    LowPageOccupied,
    /// Runtime probing or installation of Syscall User Dispatch failed.
    SudUnavailable {
        /// Exact operating-system error from the probe or installation.
        errno: i32,
    },
    /// Runtime probing or installation of the seccomp trap failed.
    SeccompUnavailable {
        /// Exact operating-system error from the probe or installation.
        errno: i32,
    },
    /// Private expedited sync-core is unavailable.
    SyncCoreUnavailable,
    /// Existing signal action, mask, altstack, or restorer ownership cannot
    /// be composed with the selected runtime contract.
    SignalContract,
    /// Active CET state is outside the qualified profile.
    CetUnsupported,
    /// A thread attempted discovery without substrate registration.
    ThreadNotRegistered,
    /// The candidate PC is not a verified instruction head.
    NotInstructionHead,
    /// The verified instruction is not native `syscall`.
    NotSyscallSite,
    /// Sysenter, int 0x80, vDSO/vsyscall, or another entry ABI was supplied.
    UnsupportedSyscallEntry,
    /// An overlapping entry or stream would observe different bytes.
    OverlappingEntry,
    /// Control flow can enter the second byte of the two-byte site.
    InteriorBranchTarget,
    /// Live bytes differ from the authenticated snapshot.
    ExpectedBytesChanged,
    /// Mapping identity or generation is no longer current.
    StaleGeneration,
    /// The caller's lease does not hold every source/generated dependency.
    DependencyNotHeld,
    /// Another installed patch owns overlapping bytes or mappings.
    OwnershipConflict,
    /// Every execution's RAX range has not been proved for the sled.
    SyscallNumberRangeUnproven,
    /// The dynamic syscall's semantics are outside the admitted profile.
    UnsupportedSyscallSemantics {
        /// Low 32-bit Linux syscall number.
        nr: u32,
    },
    /// No retained mapping satisfies the placement budget.
    AllocationUnavailable,
    /// Every bounded near-allocation candidate was occupied or unusable.
    NearAllocationExhausted,
    /// Creating or mapping the dual memfd aliases failed.
    MemfdDualMapFailed {
        /// Exact operating-system error.
        errno: i32,
    },
    /// No two-hop veneer fits the handler reachability and size bounds.
    VeneerUnavailable,
    /// Instruction-stream synchronization did not complete.
    SynchronizationFailed,
    /// A publication may have written bytes and must remain gated.
    PublicationPoisoned,
    /// No configured trap substrate can serve a trap outcome.
    TrapSubstrateUnavailable,
    /// Strict fallback policy forbids the otherwise available trap outcome.
    TrapFallbackDeniedByPolicy,
    /// The bounded site registry has no free entry.
    RegistryExhausted,
    /// A discovery trap recurred inside its own handler/gateway.
    NestedDiscoveryTrap,
    /// Handler or callback code attempted recursive interception.
    GatewayRecursion,
    /// Control reached the sled without an authenticated rewritten site.
    UnregisteredSledEntry,
    /// A SIGSYS was not authenticated as this runtime's discovery trap.
    ForeignSigsys,
}

impl fmt::Display for SyscallRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "syscall strategy refused: {self:?}")
    }
}

impl std::error::Error for SyscallRefusal {}

impl From<SyscallRefusal> for liteinst::contracts::Refusal {
    fn from(value: SyscallRefusal) -> Self {
        use liteinst::contracts::Refusal as Core;
        match value {
            SyscallRefusal::ExpectedBytesChanged => Core::ExpectedBytesChanged,
            SyscallRefusal::StaleGeneration => Core::StaleGeneration,
            SyscallRefusal::DependencyNotHeld => Core::DependencyNotHeld,
            SyscallRefusal::NotInstructionHead => Core::NotInstructionHead,
            SyscallRefusal::AllocationUnavailable
            | SyscallRefusal::NearAllocationExhausted
            | SyscallRefusal::MemfdDualMapFailed { .. }
            | SyscallRefusal::VeneerUnavailable => Core::AllocationUnavailable,
            SyscallRefusal::OwnershipConflict => Core::OwnershipConflict,
            SyscallRefusal::SignalContract => Core::SignalContract,
            SyscallRefusal::SynchronizationFailed | SyscallRefusal::SyncCoreUnavailable => {
                Core::Synchronization
            }
            SyscallRefusal::InvalidConfig { .. } => Core::InvalidPlan,
            SyscallRefusal::UnsupportedSyscallEntry
            | SyscallRefusal::UnsupportedSyscallSemantics { .. }
            | SyscallRefusal::CetUnsupported => {
                Core::UnsupportedSemantics(std::format!("{value:?}"))
            }
            other => Core::Backend(std::format!("{other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn strategy_tokens_and_coarse_mapping_are_canonical() {
        for (strategy, token) in [
            (SyscallStrategy::Trap, "trap"),
            (SyscallStrategy::Zpoline, "zpoline"),
            (SyscallStrategy::Lazypoline, "lazypoline"),
        ] {
            assert_eq!(strategy.token(), token);
            assert_eq!(SyscallStrategy::from_token(token), Ok(strategy));
            assert_eq!(
                SyscallStrategy::from_env_value(Some(OsStr::new(token))),
                Ok(Some(strategy))
            );
        }
        assert_eq!(SyscallStrategy::from_env_value(None), Ok(None));
        assert_eq!(
            SyscallStrategy::from_token("patch-eager"),
            Err(SyscallRefusal::UnknownStrategy)
        );
        let invalid = OsString::from_vec(vec![0xff]);
        assert_eq!(
            SyscallStrategy::from_env_value(Some(invalid.as_os_str())),
            Err(SyscallRefusal::NonUtf8Strategy)
        );

        assert_eq!(
            SyscallStrategy::Trap.reverie_token(DiscoverySubstrate::Sud),
            "sud-trap"
        );
        assert_eq!(
            SyscallStrategy::Trap.reverie_token(DiscoverySubstrate::SeccompRetTrap),
            "trap"
        );
        assert_eq!(
            SyscallStrategy::Zpoline.reverie_token(DiscoverySubstrate::Sud),
            "patch-eager"
        );
        assert_eq!(
            SyscallStrategy::Lazypoline.reverie_token(DiscoverySubstrate::SeccompRetTrap),
            "trap-and-patch"
        );
    }

    #[test]
    fn fallback_and_discovery_tokens_refuse_unknown_or_non_utf8() {
        assert_eq!(
            FallbackPolicy::from_token(FallbackPolicy::Trap.token()),
            Ok(FallbackPolicy::Trap)
        );
        assert_eq!(
            FallbackPolicy::from_token(FallbackPolicy::Refuse.token()),
            Ok(FallbackPolicy::Refuse)
        );
        assert_eq!(
            FallbackPolicy::from_token("auto"),
            Err(SyscallRefusal::UnknownFallbackPolicy)
        );
        assert_eq!(
            DiscoverySubstrate::from_token(DiscoverySubstrate::Sud.token()),
            Ok(DiscoverySubstrate::Sud)
        );
        assert_eq!(
            DiscoverySubstrate::from_token(DiscoverySubstrate::SeccompRetTrap.token()),
            Ok(DiscoverySubstrate::SeccompRetTrap)
        );
        assert_eq!(
            DiscoverySubstrate::from_token("ptrace"),
            Err(SyscallRefusal::UnknownDiscoverySubstrate)
        );

        let invalid = OsString::from_vec(vec![0xfe]);
        assert_eq!(
            FallbackPolicy::from_env_value(Some(invalid.as_os_str())),
            Err(SyscallRefusal::NonUtf8FallbackPolicy)
        );
        assert_eq!(
            DiscoverySubstrate::from_env_value(Some(invalid.as_os_str())),
            Err(SyscallRefusal::NonUtf8DiscoverySubstrate)
        );
        assert_eq!(FallbackPolicy::from_env_value(None), Ok(None));
        assert_eq!(DiscoverySubstrate::from_env_value(None), Ok(None));
    }

    #[test]
    fn config_defaults_and_bounds_are_the_approved_first_profile() {
        let config = SyscallStrategyConfig::new(SyscallStrategy::Lazypoline);
        assert_eq!(config.strategy(), SyscallStrategy::Lazypoline);
        assert_eq!(config.fallback(), FallbackPolicy::Trap);
        assert_eq!(config.discovery(), DiscoverySubstrate::SeccompRetTrap);
        assert_eq!(
            DiscoverySubstrate::default(),
            DiscoverySubstrate::SeccompRetTrap
        );
        assert_eq!(config.max_sites(), 16_384);
        assert_eq!(config.max_syscall_nr(), 1_023);
        assert_eq!(config.placement(), PlacementBudget::DEFAULT);
        config.validate().unwrap();

        let strict = config
            .with_fallback(FallbackPolicy::Refuse)
            .unwrap()
            .with_discovery(DiscoverySubstrate::Sud)
            .unwrap();
        assert_eq!(strict.fallback(), FallbackPolicy::Refuse);
        assert_eq!(strict.discovery(), DiscoverySubstrate::Sud);

        assert_eq!(
            config.with_max_sites(0),
            Err(SyscallRefusal::InvalidConfig {
                field: "max_sites",
                reason: "must be within 1..=262144",
            })
        );
        assert_eq!(
            config.with_max_sites(SyscallStrategyConfig::MAX_SITES_LIMIT + 1),
            Err(SyscallRefusal::InvalidConfig {
                field: "max_sites",
                reason: "must be within 1..=262144",
            })
        );
        assert_eq!(
            config.with_max_syscall_nr(0),
            Err(SyscallRefusal::InvalidConfig {
                field: "max_syscall_nr",
                reason: "must cover the first profile and fit before the sled stub",
            })
        );
        assert_eq!(
            PlacementBudget::new(0, 1, 1),
            Err(SyscallRefusal::InvalidConfig {
                field: "placement.max_candidates",
                reason: "must be nonzero",
            })
        );

        for number in FIRST_PROFILE_SYSCALLS {
            assert!(first_profile_supports(number), "{number}");
        }
        for number in [libc::SYS_execve as u32, libc::SYS_clone3 as u32, 512] {
            assert!(!first_profile_supports(number), "{number}");
        }
        assert_eq!(
            PLACEMENT_LADDER.map(PlacementFamily::token),
            [
                "near-allocation",
                "memfd-dual-map",
                "low-page",
                "two-hop-veneer",
                "trap"
            ]
        );
    }

    #[test]
    fn core_conversion_preserves_exact_common_refusals() {
        use liteinst::contracts::Refusal as Core;

        assert_eq!(
            Core::from(SyscallRefusal::ExpectedBytesChanged),
            Core::ExpectedBytesChanged
        );
        assert_eq!(
            Core::from(SyscallRefusal::MemfdDualMapFailed { errno: 13 }),
            Core::AllocationUnavailable
        );
        assert_eq!(
            Core::from(SyscallRefusal::SignalContract),
            Core::SignalContract
        );
        assert_eq!(
            Core::from(SyscallRefusal::LowPageUnavailable { errno: 1 }),
            Core::Backend("LowPageUnavailable { errno: 1 }".to_string())
        );
    }
}
