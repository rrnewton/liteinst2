//! Named refusals. Every unsupported case in this crate returns one of
//! these values; an unnamed "unsupported" is a bug.

/// A named refusal to translate or continue. The guest is always left
/// stopped at (or before) the named source PC, never mid-block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Refuse {
    /// An indirect jump or call whose target lies outside the admitted
    /// source region (P1b.1 resolves in-region targets through the
    /// dispatcher), or an indirect form P1b.1 does not resolve (far,
    /// segment-override). The guest is left at the instruction with
    /// the state before it: no push, no memory write.
    IndirectUnresolved { src_pc: u64 },
    /// An in-region indirect call whose return-address slot
    /// `[rsp-8, rsp)` crosses a page boundary (`slot & 0xfff > 0xff8`).
    /// Pushing it could write the part of the slot on the first page
    /// and then fault on the second, which a native `call` never does.
    /// Refused before any retranslation, push or memory write; the
    /// guest is left at the call with the state before it.
    IndirectPushCrossesPage { src_pc: u64, slot: u64 },
    /// An indirect jump or call whose memory operand has a 32-bit
    /// address size in absolute form (`67 ff /4|/2` with `[disp32]`).
    /// The resolver claims 64-bit addressing only, so this is a policy
    /// refusal, not an unresolved target. `bytes` are the
    /// instruction's encoding. Refused before any retranslation, push
    /// or memory write; the guest is left at the instruction with the
    /// state before it.
    IndirectAddressSize32 { src_pc: u64, bytes: Vec<u8> },
    /// Source code is writable, shared, or its write ownership is
    /// unknown; P1a refuses self-modifying code instead of tracking it.
    SelfModifyingOrWritableCode { src: u64 },
    /// A syscall-class or nondeterministic instruction exited its block
    /// but no handler was registered to serve it.
    NoHandler { src_pc: u64 },
    /// The instruction cannot be copied with proven equivalence.
    Unrelocatable { src_pc: u64, reason: &'static str },
    /// A control target lands mid-instruction in the decoded stream.
    /// Raised at an INDIRECT exit in a plain run, it names the
    /// interior target while the guest is stopped at the jmp; only a
    /// budget handoff's `at` names the jmp itself.
    InteriorEntry { target: u64 },
    /// A block or cache budget was exceeded.
    BudgetExceeded { what: &'static str },
    /// Required signal-handler ownership is unavailable, or a
    /// signal-custody observation/dequeue failed. `taken` lists
    /// distinct async signal numbers already dequeued into
    /// executor custody before the failure, in ascending order;
    /// it is empty when no dequeue had succeeded.
    SignalOwnership { signum: i32, taken: Vec<i32> },
    /// The OS mapping policy forbids the cache allocation shape.
    MappingPolicy { operation: &'static str, errno: i32 },
    /// `execve` successor images are not re-armed in P1a.
    ExecSuccessor,
    /// Thread lifecycle beyond the single-threaded P1a envelope.
    ThreadLifecycle { what: &'static str },
    /// Not Linux x86-64, or an execution mode outside the envelope.
    Arch { what: &'static str },
    /// Invalid or truncated instruction bytes at the source PC.
    Decode { src_pc: u64 },
    /// A cache entry, or a mapping event, was offered under a
    /// superseded generation: `expected` is the oldest generation that
    /// would have been accepted when it was offered, `found` the one
    /// offered. A refused event batch still moves the executable on
    /// (its ranges become holes), so afterwards even `expected` is
    /// no longer accepted.
    StaleGeneration { expected: u64, found: u64 },
    /// Control reached, or a direct edge leads into, a range the
    /// caller reported unmapped (a `MappingEvent` without a region),
    /// under the executable's `generation`. Nothing in the range runs.
    ///
    /// `src_pc` names what reaches the hole, which need not be where
    /// the guest stopped:
    /// - at a dispatcher entry, the entry PC itself;
    /// - while a translation is rebuilt, the branch, root or instruction
    ///   in its reach that leads into the hole, anywhere in that reach;
    /// - for a resolved indirect jump or call, its in-hole target.
    ///
    /// The guest is left with the state before the dispatcher entry or
    /// the stopping instruction (its own `rip`), never past it.
    UnmappedCode { src_pc: u64, generation: u64 },
    /// The remote (ptrace) substrate could not complete the named
    /// operation; the guest was left stopped or terminated, never
    /// resumed on partial state.
    RemoteSubstrate { operation: &'static str, errno: i32 },
    /// A remaining-RCB budget run (test-seams experiment) met a
    /// shape it does not claim: a budgeted translation run
    /// without a budget, a budget run on a translation without
    /// budget stubs, or a signal delivery inside the stretch.
    RcbBudget { what: &'static str },
    /// Installing a retranslated code image (P1b.1) failed or was not
    /// allowed: a live signal frame holds a generated PC (remote), the
    /// `/proc/<pid>/mem` write failed (`errno`), or an earlier failed
    /// install left the arena possibly torn and the executable
    /// poisoned. `errno` is 0 when no system call failed. The guest is
    /// left at `src_pc` with the state before the instruction.
    CodeInstall {
        src_pc: u64,
        reason: &'static str,
        errno: i32,
    },
}

impl Refuse {
    /// Proposed mapping onto the architecture `R-*` taxonomy. The
    /// taxonomy itself is proposed API; this mapping is unratified and
    /// exists so refusal logs already carry the eventual name.
    pub fn proposed_r_name(&self) -> &'static str {
        match self {
            Refuse::IndirectUnresolved { .. }
            | Refuse::IndirectPushCrossesPage { .. }
            | Refuse::IndirectAddressSize32 { .. }
            | Refuse::SelfModifyingOrWritableCode { .. }
            | Refuse::Unrelocatable { .. }
            | Refuse::InteriorEntry { .. }
            | Refuse::BudgetExceeded { .. }
            | Refuse::Decode { .. }
            | Refuse::StaleGeneration { .. }
            | Refuse::UnmappedCode { .. }
            | Refuse::RcbBudget { .. }
            | Refuse::CodeInstall { .. } => "R-CODE",
            Refuse::NoHandler { .. } => "R-INSTR",
            Refuse::SignalOwnership { .. } => "R-SIGNAL",
            Refuse::MappingPolicy { .. } => "R-WX",
            Refuse::ExecSuccessor => "R-EXEC",
            Refuse::ThreadLifecycle { .. } => "R-LIFECYCLE",
            Refuse::Arch { .. } => "R-ARCH",
            Refuse::RemoteSubstrate { .. } => "R-REMOTE",
        }
    }
}

impl core::fmt::Display for Refuse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "liteinst-jit refused ({}): {self:?}",
            self.proposed_r_name()
        )
    }
}
impl std::error::Error for Refuse {}
