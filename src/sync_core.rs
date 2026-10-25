//! Process-scoped instruction-stream synchronization on Linux x86-64.
//!
//! This capability does not publish code, preserve saved PCs, drain callbacks,
//! or establish quiescence. It supplies a completion boundary for a separately
//! validated publication protocol. Preparation performs all capability checks
//! before that protocol changes bytes. Later synchronization may still fail;
//! a publisher must retain its incomplete transaction and routing on failure.

use core::fmt;

const QUERY: libc::c_int = 0;
const SYNC_CORE: libc::c_int = 1 << 5;
const REGISTER_SYNC_CORE: libc::c_int = 1 << 6;

/// The syscall operation that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncCoreOperation {
    /// Query supported membarrier commands.
    Query,
    /// Register this process for expedited sync-core barriers.
    Register,
    /// Complete an expedited sync-core barrier.
    Synchronize,
}

/// A capability or synchronization failure, with no timing fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncCoreError {
    /// This target has no implemented synchronization backend.
    UnsupportedPlatform,
    /// The kernel did not advertise both required commands.
    MissingCapability {
        /// Command bitmask returned by the query.
        available: libc::c_long,
    },
    /// A command failed with the recorded operating-system error.
    SystemCall {
        /// Command that failed.
        operation: SyncCoreOperation,
        /// Exact positive errno reported by libc.
        errno: i32,
    },
    /// A command that requires zero returned a different value.
    UnexpectedResult {
        /// Command with the unexpected result.
        operation: SyncCoreOperation,
        /// Exact returned value.
        value: libc::c_long,
    },
    /// The handle was prepared in a different process, such as a fork parent.
    DifferentProcess {
        /// Process that prepared the handle.
        prepared: libc::pid_t,
        /// Process attempting synchronization.
        current: libc::pid_t,
    },
}

impl fmt::Display for SyncCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "instruction-stream synchronization failed: {self:?}")
    }
}

impl std::error::Error for SyncCoreError {}

/// A prepared Linux private expedited sync-core registration.
///
/// The capability belongs to the process that prepared it. A fork child must
/// prepare its own capability. Preparation does not promise that future calls
/// will succeed: a later syscall restriction can still reject synchronization.
#[derive(Clone, Copy, Debug)]
pub struct SyncCore {
    process: libc::pid_t,
}

trait Backend {
    fn process(&self) -> libc::pid_t;
    fn command(&mut self, command: libc::c_int) -> Result<libc::c_long, i32>;
    fn serialize_caller(&mut self);
}

impl SyncCore {
    /// Queries support, registers the process, and performs a first barrier.
    ///
    /// No code is modified. Unsupported or denied operations return an error;
    /// there is no staleness-delay fallback.
    pub fn prepare() -> Result<Self, SyncCoreError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            Self::prepare_with(&mut Native)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            Err(SyncCoreError::UnsupportedPlatform)
        }
    }

    /// Completes process-wide instruction-stream synchronization.
    ///
    /// On success, Linux has serialized the sibling threads' instruction
    /// streams (including before a sleeping thread resumes), and the calling
    /// thread has executed CPUID. This does not translate existing saved PCs
    /// or prove that a particular patch transition is safe to execute.
    pub fn synchronize(&self) -> Result<(), SyncCoreError> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            self.synchronize_with(&mut Native)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            Err(SyncCoreError::UnsupportedPlatform)
        }
    }

    fn prepare_with(backend: &mut impl Backend) -> Result<Self, SyncCoreError> {
        let available = invoke(backend, QUERY, SyncCoreOperation::Query)?;
        let required = libc::c_long::from(SYNC_CORE | REGISTER_SYNC_CORE);
        if available < 0 || available & required != required {
            return Err(SyncCoreError::MissingCapability { available });
        }
        zero(backend, REGISTER_SYNC_CORE, SyncCoreOperation::Register)?;
        let capability = Self {
            process: backend.process(),
        };
        capability.synchronize_with(backend)?;
        Ok(capability)
    }

    fn synchronize_with(&self, backend: &mut impl Backend) -> Result<(), SyncCoreError> {
        let current = backend.process();
        if current != self.process {
            return Err(SyncCoreError::DifferentProcess {
                prepared: self.process,
                current,
            });
        }
        // Order prior publication stores before the kernel's global completion
        // operation. An error leaves the publisher responsible for its state.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        zero(backend, SYNC_CORE, SyncCoreOperation::Synchronize)?;
        backend.serialize_caller();
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

fn invoke(
    backend: &mut impl Backend,
    command: libc::c_int,
    operation: SyncCoreOperation,
) -> Result<libc::c_long, SyncCoreError> {
    backend
        .command(command)
        .map_err(|errno| SyncCoreError::SystemCall { operation, errno })
}

fn zero(
    backend: &mut impl Backend,
    command: libc::c_int,
    operation: SyncCoreOperation,
) -> Result<(), SyncCoreError> {
    match invoke(backend, command, operation)? {
        0 => Ok(()),
        value => Err(SyncCoreError::UnexpectedResult { operation, value }),
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct Native;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Backend for Native {
    fn process(&self) -> libc::pid_t {
        // SAFETY: getpid has no pointer arguments or caller preconditions.
        unsafe { libc::getpid() }
    }

    fn command(&mut self, command: libc::c_int) -> Result<libc::c_long, i32> {
        // SAFETY: membarrier takes an integer command and zero flags/cpu_id;
        // no pointer is passed. Commands are limited to the three above.
        let result = unsafe { libc::syscall(libc::SYS_membarrier, command, 0, 0) };
        if result == -1 {
            // SAFETY: Linux libc exposes this thread's valid errno location.
            Err(unsafe { *libc::__errno_location() })
        } else {
            Ok(result)
        }
    }

    #[allow(unused_unsafe)] // CPUID is unsafe on the minimum supported Rust.
    fn serialize_caller(&mut self) {
        // SAFETY: CPUID leaf zero is available on x86-64 and serializes local
        // execution. No feature-specific instruction is required.
        unsafe { core::arch::x86_64::__cpuid(0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Mock {
        process: libc::pid_t,
        commands: Vec<libc::c_int>,
        replies: VecDeque<Result<libc::c_long, i32>>,
        serialized: usize,
    }

    impl Mock {
        fn new(replies: impl IntoIterator<Item = Result<libc::c_long, i32>>) -> Self {
            Self {
                process: 101,
                commands: Vec::new(),
                replies: replies.into_iter().collect(),
                serialized: 0,
            }
        }
    }

    impl Backend for Mock {
        fn process(&self) -> libc::pid_t {
            self.process
        }
        fn command(&mut self, command: libc::c_int) -> Result<libc::c_long, i32> {
            self.commands.push(command);
            self.replies.pop_front().expect("unexpected syscall")
        }
        fn serialize_caller(&mut self) {
            self.serialized += 1;
        }
    }

    const SUPPORTED: libc::c_long = (SYNC_CORE | REGISTER_SYNC_CORE) as libc::c_long;

    #[test]
    fn preparation_queries_registers_and_synchronizes_in_order() {
        let mut backend = Mock::new([Ok(SUPPORTED), Ok(0), Ok(0), Ok(0)]);
        let capability = SyncCore::prepare_with(&mut backend).unwrap();
        assert_eq!(backend.commands, [QUERY, REGISTER_SYNC_CORE, SYNC_CORE]);
        assert_eq!(backend.serialized, 1);
        capability.synchronize_with(&mut backend).unwrap();
        assert_eq!(
            backend.commands,
            [QUERY, REGISTER_SYNC_CORE, SYNC_CORE, SYNC_CORE]
        );
        assert_eq!(backend.serialized, 2);
        assert!(backend.replies.is_empty());
    }

    #[test]
    fn either_missing_capability_stops_before_registration() {
        for available in [
            0,
            libc::c_long::from(SYNC_CORE),
            libc::c_long::from(REGISTER_SYNC_CORE),
        ] {
            let mut backend = Mock::new([Ok(available)]);
            assert_eq!(
                SyncCore::prepare_with(&mut backend).unwrap_err(),
                SyncCoreError::MissingCapability { available }
            );
            assert_eq!(backend.commands, [QUERY]);
            assert_eq!(backend.serialized, 0);
        }
    }

    #[test]
    fn each_system_call_error_retains_exact_operation_and_errno() {
        for (operation, replies, commands) in [
            (
                SyncCoreOperation::Query,
                vec![Err(libc::ENOSYS)],
                vec![QUERY],
            ),
            (
                SyncCoreOperation::Register,
                vec![Ok(SUPPORTED), Err(libc::EPERM)],
                vec![QUERY, REGISTER_SYNC_CORE],
            ),
            (
                SyncCoreOperation::Synchronize,
                vec![Ok(SUPPORTED), Ok(0), Err(libc::EINVAL)],
                vec![QUERY, REGISTER_SYNC_CORE, SYNC_CORE],
            ),
        ] {
            let errno = *replies.last().unwrap().as_ref().unwrap_err();
            let mut backend = Mock::new(replies);
            assert_eq!(
                SyncCore::prepare_with(&mut backend).unwrap_err(),
                SyncCoreError::SystemCall { operation, errno }
            );
            assert_eq!(backend.commands, commands);
            assert_eq!(backend.serialized, 0);
            assert!(backend.replies.is_empty());
        }
    }

    #[test]
    fn nonzero_completion_is_not_success() {
        for (operation, replies) in [
            (SyncCoreOperation::Register, vec![Ok(SUPPORTED), Ok(7)]),
            (
                SyncCoreOperation::Synchronize,
                vec![Ok(SUPPORTED), Ok(0), Ok(7)],
            ),
        ] {
            let mut backend = Mock::new(replies);
            assert_eq!(
                SyncCore::prepare_with(&mut backend).unwrap_err(),
                SyncCoreError::UnexpectedResult {
                    operation,
                    value: 7
                }
            );
            assert_eq!(backend.serialized, 0);
            assert!(backend.replies.is_empty());
        }
    }

    #[test]
    fn fork_identity_is_refused_before_syscall() {
        let mut backend = Mock::new([Ok(SUPPORTED), Ok(0), Ok(0)]);
        let capability = SyncCore::prepare_with(&mut backend).unwrap();
        backend.process = 102;
        assert_eq!(
            capability.synchronize_with(&mut backend),
            Err(SyncCoreError::DifferentProcess {
                prepared: 101,
                current: 102
            })
        );
        assert_eq!(backend.commands, [QUERY, REGISTER_SYNC_CORE, SYNC_CORE]);
        assert_eq!(backend.serialized, 1);
    }

    #[test]
    fn later_restriction_is_reported_after_successful_preparation() {
        let mut backend = Mock::new([Ok(SUPPORTED), Ok(0), Ok(0), Err(libc::EPERM)]);
        let capability = SyncCore::prepare_with(&mut backend).unwrap();
        assert_eq!(
            capability.synchronize_with(&mut backend),
            Err(SyncCoreError::SystemCall {
                operation: SyncCoreOperation::Synchronize,
                errno: libc::EPERM
            })
        );
        assert_eq!(
            backend.commands,
            [QUERY, REGISTER_SYNC_CORE, SYNC_CORE, SYNC_CORE]
        );
        assert_eq!(backend.serialized, 1);
    }
}
