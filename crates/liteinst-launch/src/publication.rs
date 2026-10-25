//! Sealed access to execution that remains held during remote publication.
//!
//! These interfaces let the publisher use a real stopped-task owner without
//! gaining an application resume, single-step, or register-write capability.
//! The owner supplies the exclusion guard; the interfaces do not manufacture
//! quiescence from mapping metadata or a Boolean witness.

use std::ops::Range;
use std::time::Duration;

use liteinst2::contracts::{AddressRange, CodeIdentity, QuiescenceLease};

use crate::{
    LaunchError, MemoryMapping, RegisterSnapshot, RemoteLeaseOps, SignalStop, SingleThreadStop,
};

/// Implementations are restricted to this crate's actual stopped-process owners.
pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Narrow operations available while actual execution exclusion is borrowed.
///
/// Trusted island instructions may execute on the selected worker; application
/// instructions and every other owned task remain excluded. Mutations preserve
/// the selected worker's complete GPR/XSTATE and terminate the owner whenever
/// execution or a partially applied mutation becomes uncertain. This trait is
/// sealed so an external implementation cannot substitute a simulated stop.
pub trait PublicationOperations: sealed::Sealed {
    /// Process/thread-group identity, stable across selected workers.
    fn pid(&self) -> libc::pid_t;

    /// Target kernel page size.
    fn page_size(&self) -> usize;

    /// Most recently checked mapping snapshot for the shared address space.
    fn mappings(&self) -> Vec<MemoryMapping>;

    /// Bounded memory read while execution remains excluded.
    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError>;

    /// Complete general-register snapshot of the selected stopped worker.
    fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError>;

    /// Complete kernel extended-state image of the selected stopped worker.
    fn read_xstate(&self) -> Result<Vec<u8>, LaunchError>;

    /// Allocates a whole-page private code image at an exact unused address,
    /// initializes it while RW/NX, then verifies RX permissions and sync-core.
    fn map_private_code(
        &mut self,
        address: u64,
        image: &[u8],
        timeout: Duration,
    ) -> Result<Range<u64>, LaunchError>;

    /// Executes one exact-width native MOV after checking its expected bytes
    /// and private RW/NX envelope; verifies adjacent bytes and restored state.
    fn exact_store_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
        timeout: Duration,
    ) -> Result<(), LaunchError>;

    /// Changes and verifies private page permissions, refusing RWX and island
    /// overlap. This operation does not itself certify code admission.
    fn mprotect(
        &mut self,
        address: u64,
        len: usize,
        protection: i32,
        timeout: Duration,
    ) -> Result<(), LaunchError>;

    /// Completes instruction-stream synchronization in the target process.
    fn sync_core(&mut self, timeout: Duration) -> Result<(), LaunchError>;
}

/// A real held execution owner with one selected worker for observations.
///
/// The process identity is the TGID, while register reads and signal
/// acknowledgments refer to the selected stopped worker. Acknowledgment must
/// authenticate that worker's exact pending event, including its task identity
/// and stop sequence. Implementations are sealed within this crate.
pub trait PublicationStop: sealed::Sealed + Sized {
    /// Process/thread-group identity, rather than the selected worker's TID.
    fn pid(&self) -> libc::pid_t;

    /// Target kernel page size.
    fn page_size(&self) -> usize;

    /// Most recently checked shared-address-space mapping snapshot.
    fn mappings(&self) -> Vec<MemoryMapping>;

    /// Bounded memory read under the held execution owner.
    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError>;

    /// Complete general-register snapshot of the selected stopped worker.
    fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError>;

    /// Complete extended state of the selected stopped worker.
    fn read_xstate(&self) -> Result<Vec<u8>, LaunchError>;

    /// Acknowledges exactly the selected worker's current authenticated signal.
    fn acknowledge_owned_signal(&mut self, event: &SignalStop) -> Result<(), LaunchError>;

    /// Lends a core lease that borrows this owner's actual execution-exclusion
    /// guard and only the narrow operations above. The owner remains held on
    /// success. Errors, poisoned results (including a panicking destructor),
    /// and unwinding terminate and reap the owned process before exclusion can
    /// be released. Neither the lease nor operation view may escape the scope.
    ///
    /// # Safety
    /// The caller must authenticate the source identity and every dependency
    /// range, and maintain the complete `QuiescenceLease::new` contract for the
    /// callback: external readers/writers and aliases are excluded, all legal
    /// entries and saved resumes are accounted for, and mapping/content identity
    /// remains stable. A real stopped owner proves execution exclusion only;
    /// private mappings do not prove these additional facts. No independent
    /// tracer, reaper, or process may access the certified ownership envelope.
    unsafe fn with_publication_lease<T>(
        &mut self,
        identity: CodeIdentity,
        ranges: Vec<AddressRange>,
        action: impl FnOnce(
            &mut dyn PublicationOperations,
            &mut QuiescenceLease<'_>,
        ) -> Result<T, LaunchError>,
    ) -> Result<T, LaunchError>;
}

impl sealed::Sealed for RemoteLeaseOps<'_, '_> {}

impl PublicationOperations for RemoteLeaseOps<'_, '_> {
    fn pid(&self) -> libc::pid_t {
        RemoteLeaseOps::pid(self)
    }

    fn page_size(&self) -> usize {
        RemoteLeaseOps::page_size(self)
    }

    fn mappings(&self) -> Vec<MemoryMapping> {
        RemoteLeaseOps::mappings(self)
    }

    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        RemoteLeaseOps::read_memory(self, address, len)
    }

    fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        RemoteLeaseOps::read_registers(self)
    }

    fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        RemoteLeaseOps::read_xstate(self)
    }

    fn map_private_code(
        &mut self,
        address: u64,
        image: &[u8],
        timeout: Duration,
    ) -> Result<Range<u64>, LaunchError> {
        RemoteLeaseOps::map_private_code(self, address, image, timeout)
    }

    fn exact_store_checked(
        &mut self,
        address: u64,
        expected: &[u8],
        replacement: &[u8],
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        RemoteLeaseOps::exact_store_checked(self, address, expected, replacement, timeout)
    }

    fn mprotect(
        &mut self,
        address: u64,
        len: usize,
        protection: i32,
        timeout: Duration,
    ) -> Result<(), LaunchError> {
        RemoteLeaseOps::mprotect(self, address, len, protection, timeout)
    }

    fn sync_core(&mut self, timeout: Duration) -> Result<(), LaunchError> {
        RemoteLeaseOps::sync_core(self, timeout)
    }
}

impl sealed::Sealed for SingleThreadStop<'_> {}

impl PublicationStop for SingleThreadStop<'_> {
    fn pid(&self) -> libc::pid_t {
        SingleThreadStop::pid(self)
    }

    fn page_size(&self) -> usize {
        SingleThreadStop::page_size(self)
    }

    fn mappings(&self) -> Vec<MemoryMapping> {
        SingleThreadStop::mappings(self)
    }

    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, LaunchError> {
        SingleThreadStop::read_memory(self, address, len)
    }

    fn read_registers(&self) -> Result<RegisterSnapshot, LaunchError> {
        SingleThreadStop::read_registers(self)
    }

    fn read_xstate(&self) -> Result<Vec<u8>, LaunchError> {
        SingleThreadStop::read_xstate(self)
    }

    fn acknowledge_owned_signal(&mut self, event: &SignalStop) -> Result<(), LaunchError> {
        SingleThreadStop::acknowledge_owned_signal(self, event)
    }

    unsafe fn with_publication_lease<T>(
        &mut self,
        identity: CodeIdentity,
        ranges: Vec<AddressRange>,
        action: impl FnOnce(
            &mut dyn PublicationOperations,
            &mut QuiescenceLease<'_>,
        ) -> Result<T, LaunchError>,
    ) -> Result<T, LaunchError> {
        // SAFETY: the caller supplies the unchanged complete owner contract.
        // Forwarding keeps the actual held-stop guard, strict single-task
        // checks, panic handling, and kill/reap behavior in with_core_lease.
        unsafe {
            self.with_core_lease(identity, ranges, |operations, lease| {
                action(operations, lease)
            })
        }
    }
}
