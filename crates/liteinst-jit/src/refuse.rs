//! Named refusals. Every unsupported case in this crate returns one of
//! these values; an unnamed "unsupported" is a bug.

/// A named refusal to translate or continue. The guest is always left
/// stopped at (or before) the named source PC, never mid-block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Refuse {
    /// Indirect jump/call reached the dispatcher; P1a resolves direct
    /// control flow only.
    IndirectUnresolved { src_pc: u64 },
    /// Source code is writable, shared, or its write ownership is
    /// unknown; P1a refuses self-modifying code instead of tracking it.
    SelfModifyingOrWritableCode { src: u64 },
    /// A syscall-class or nondeterministic instruction exited its block
    /// but no handler was registered to serve it.
    NoHandler { src_pc: u64 },
    /// The instruction cannot be copied with proven equivalence.
    Unrelocatable { src_pc: u64, reason: &'static str },
    /// A control target lands mid-instruction in the decoded stream.
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
    /// A cache entry was offered under a superseded generation.
    StaleGeneration { expected: u64, found: u64 },
}

impl Refuse {
    /// Proposed mapping onto the architecture `R-*` taxonomy. The
    /// taxonomy itself is proposed API; this mapping is unratified and
    /// exists so refusal logs already carry the eventual name.
    pub fn proposed_r_name(&self) -> &'static str {
        match self {
            Refuse::IndirectUnresolved { .. }
            | Refuse::SelfModifyingOrWritableCode { .. }
            | Refuse::Unrelocatable { .. }
            | Refuse::InteriorEntry { .. }
            | Refuse::BudgetExceeded { .. }
            | Refuse::Decode { .. }
            | Refuse::StaleGeneration { .. } => "R-CODE",
            Refuse::NoHandler { .. } => "R-INSTR",
            Refuse::SignalOwnership { .. } => "R-SIGNAL",
            Refuse::MappingPolicy { .. } => "R-WX",
            Refuse::ExecSuccessor => "R-EXEC",
            Refuse::ThreadLifecycle { .. } => "R-LIFECYCLE",
            Refuse::Arch { .. } => "R-ARCH",
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
