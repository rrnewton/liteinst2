//! Kernel rseq reset before any copied private helper can execute.
//!
//! This object belongs to Owner before clone. Its cleanup uses only H's exact
//! natural-parent wait domain; it never relies on a missing handoff as absence.
use super::super::super::broker;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

mod discovery;
mod machine;
#[cfg(test)]
mod tests;

const STACK: usize = 128 * 1024;
const PAGE: usize = 4096;
const HANDOFF_MAGIC: u64 = 0x4c49_3252_5345_5431;
const WAIT_FLAGS: i32 = libc::WEXITED
    | libc::WSTOPPED
    | libc::WNOHANG
    | libc::WNOWAIT
    | libc::__WALL
    | libc::__WNOTHREAD;

/// Diagnostic reset-launch stage; none of these rows grants native authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorResetPhase {
    /// Original owner is about to invoke the raw reset clone.
    CloneAttempt,
    /// Actual returned clone result, before interpreting success or errno.
    CloneReturn,
    /// Initialized handoff bytes and actual recvmsg result, before validation.
    HandoffReceive,
    /// Actual consumed direct-parent wait status.
    WaitConsumed,
    /// Credentials, exact parent domain and transferred pidfd agreed.
    HandoffAuthenticated,
    /// S was reaped and the stopped R is authenticated for Broker transfer.
    BrokerTransferReady,
}

/// One fixed reset-launch diagnostic fact, including failed observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorResetObservation {
    /// Closed capture stage.
    pub phase: AnchorResetPhase,
    /// Observed task, zero if no task identity was available.
    pub pid: i32,
    /// Native result or zero for a bookkeeping-only stage.
    pub result: i64,
    /// Native errno for a failed libc recvmsg, if applicable.
    pub errno: Option<i32>,
    /// Actual consumed wait status, never synthesized.
    pub wait_status: Option<i32>,
    /// Initialized fixed packet buffer; only HandoffReceive interprets it.
    pub packet: [u8; 64],
}
impl AnchorResetObservation {
    fn new(phase: AnchorResetPhase, pid: i32, result: i64) -> Self {
        Self {
            phase,
            pid,
            result,
            errno: None,
            wait_status: None,
            packet: [0; 64],
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Packet {
    magic: u64,
    session: u64,
    sequence: u64,
    pid: i32,
    reserved: [u32; 9],
}
const _: () = assert!(std::mem::size_of::<Packet>() == 64);

#[repr(C)]
struct Context {
    stack: u64,
    channels: [i32; 2],
    descriptor: i32,
    _padding: i32,
    test_fault: u32,
    _test_padding: u32,
    // S writes these immediately after its actual sendmsg return. H reads
    // them only after vfork completion and an actual S terminal witness.
    send_result: i64,
    send_observed: u64,
    packet: Packet,
    control: [usize; 4],
    iov: libc::iovec,
    message: libc::msghdr,
    broker: broker::AnchorRaw,
}

struct Mapping {
    base: *mut libc::c_void,
    length: usize,
}
impl Mapping {
    fn new() -> Result<Self, LaunchError> {
        let length = STACK + 3 * PAGE;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(system("reserve reset lineage storage"));
        }
        let value = Self { base, length };
        if std::mem::size_of::<Context>() > PAGE
            || unsafe { libc::mprotect(base, PAGE, libc::PROT_READ | libc::PROT_WRITE) } != 0
            || unsafe {
                libc::mprotect(
                    base.cast::<u8>().add(2 * PAGE).cast(),
                    STACK,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
        {
            return Err(system("initialize reset lineage storage"));
        }
        Ok(value)
    }
    fn context(&self) -> *mut Context {
        self.base.cast()
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base, self.length);
        }
    }
}

struct Child {
    pid: i32,
    pin: Option<OwnedFd>,
    terminal: Option<i32>,
    stopped: Option<i32>,
}
impl Child {
    fn new(pid: i32, pin: Option<OwnedFd>) -> Self {
        Self {
            pid,
            pin,
            terminal: None,
            stopped: None,
        }
    }
    fn physical(&self) -> bool {
        self.terminal.is_some() && self.pin.as_ref().is_none_or(broker::hup)
    }
}

/// Private incomplete startup ownership. Never moved into AdmissionOwner.
pub(in crate::linux::remote::dynamic) struct ResetLaunch {
    mapping: Mapping,
    channels: [OwnedFd; 2],
    prepared: Option<broker::AnchorBroker>,
    discovery: discovery::Discovery,
    // S, expected R, one unexpected eligible child. The extra slot is drained
    // before reuse; it is never discarded for exceeding the topology bound.
    children: [Option<Child>; 3],
    session: u64,
    host: libc::ucred,
    owner_tid: i32,
    spawned: bool,
    handed_off: bool,
    failed: bool,
    packet_received: bool,
    archive: AnchorArchive,
    #[cfg(test)]
    deny_pin: bool,
}

impl ResetLaunch {
    pub(in crate::linux::remote::dynamic) fn prepare(
        session: u64,
        bootstrap: Bootstrap,
        archive: AnchorArchive,
    ) -> Result<Self, LaunchError> {
        if archive.session() != session {
            return Err(LaunchError::Invalid("reset archive session differs"));
        }
        let mapping = Mapping::new()?;
        let prepared = broker::AnchorBroker::prepare(session, bootstrap)?;
        let mut sockets = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                sockets.as_mut_ptr(),
            )
        } != 0
        {
            return Err(system("create reset lineage handoff"));
        }
        let channels = unsafe {
            [
                OwnedFd::from_raw_fd(sockets[0]),
                OwnedFd::from_raw_fd(sockets[1]),
            ]
        };
        let enable = 1_i32;
        if unsafe {
            libc::setsockopt(
                sockets[0],
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&raw const enable).cast(),
                std::mem::size_of_val(&enable) as _,
            )
        } != 0
        {
            return Err(system("authenticate reset lineage handoff"));
        }
        let owner_tid = unsafe { libc::syscall(libc::SYS_gettid) as i32 };
        let discovery = discovery::Discovery::new(owner_tid)?;
        let host = libc::ucred {
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let context = mapping.context();
        unsafe {
            context.write(Context {
                stack: mapping.base as u64 + (2 * PAGE + STACK) as u64,
                channels: sockets,
                descriptor: -1,
                _padding: 0,
                test_fault: 0,
                _test_padding: 0,
                send_result: i64::MIN,
                send_observed: 0,
                packet: Packet {
                    magic: HANDOFF_MAGIC,
                    session,
                    sequence: 1,
                    pid: 0,
                    reserved: [0; 9],
                },
                control: [0; 4],
                iov: std::mem::zeroed(),
                message: std::mem::zeroed(),
                broker: prepared.raw(),
            });
            (*context).iov = libc::iovec {
                iov_base: (&raw mut (*context).packet).cast(),
                iov_len: 64,
            };
            (*context).message.msg_iov = &raw mut (*context).iov;
            (*context).message.msg_iovlen = 1;
            (*context).message.msg_control = (*context).control.as_mut_ptr().cast();
            (*context).message.msg_controllen = libc::CMSG_SPACE(4) as usize;
            let header = libc::CMSG_FIRSTHDR(&(*context).message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(4) as usize;
        }
        Ok(Self {
            mapping,
            channels,
            prepared: Some(prepared),
            discovery,
            children: [None, None, None],
            session,
            host,
            owner_tid,
            spawned: false,
            handed_off: false,
            failed: false,
            packet_received: false,
            archive,
            #[cfg(test)]
            deny_pin: false,
        })
    }

    fn thread(&self) -> Result<(), LaunchError> {
        if unsafe { libc::syscall(libc::SYS_gettid) as i32 } != self.owner_tid {
            return Err(LaunchError::Invalid(
                "reset lineage moved away from its natural-parent thread",
            ));
        }
        Ok(())
    }
    fn time(until: Instant, cancel: &AtomicBool) -> Result<(), LaunchError> {
        if cancel.load(Ordering::Acquire) {
            return Err(LaunchError::Invalid("dynamic session cancelled"));
        }
        if Instant::now() >= until {
            return Err(LaunchError::Timeout("initial reset lineage"));
        }
        Ok(())
    }

    pub(in crate::linux::remote::dynamic) fn launch(
        &mut self,
        until: Instant,
        cancel: &AtomicBool,
    ) -> Result<broker::Broker, LaunchError> {
        self.thread()?;
        Self::time(until, cancel)?;
        if self.spawned || self.handed_off || current_mask()? != BLOCKED {
            return Err(LaunchError::Invalid("invalid reset lineage start"));
        }
        self.start_clone()?;
        self.await_handoff(until, cancel)
    }

    // Continue the same launch transaction with its original absolute deadline.
    // Separating this phase also lets the native control establish real held
    // ownership before deliberately expiring the unchanged handoff deadline.
    fn await_handoff(
        &mut self,
        until: Instant,
        cancel: &AtomicBool,
    ) -> Result<broker::Broker, LaunchError> {
        loop {
            Self::time(until, cancel)?;
            self.receive()?;
            self.wait_one(false)?;
            let ready = self.children[0].as_ref().is_some_and(|s| {
                s.physical()
                    && s.terminal.is_some_and(|status| {
                        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
                    })
            });
            let stopped = self.children[1].as_ref().is_some_and(|r| {
                r.terminal.is_none()
                    && r.stopped.is_some_and(|status| {
                        libc::WIFSTOPPED(status)
                            && libc::WSTOPSIG(status) == libc::SIGSTOP
                            && status >> 16 == 0
                    })
            });
            if self.packet_received && ready && stopped {
                Self::time(until, cancel)?;
                if self.children[1].as_ref().is_none_or(|r| r.pin.is_none())
                    || self.prepared.is_none()
                {
                    return Err(LaunchError::Invalid(
                        "reset broker transfer ownership differs",
                    ));
                }
                self.record(AnchorResetObservation::new(
                    AnchorResetPhase::BrokerTransferReady,
                    self.children[1].as_ref().unwrap().pid,
                    0,
                ))?;
                let mut r = self.children[1].take().unwrap();
                let handle = r.pin.take().unwrap();
                let prepared = self.prepared.take().unwrap();
                // Adoption allocates no children or effects; R remains stopped.
                let broker = prepared.adopt(r.pid, handle);
                self.handed_off = true;
                return Ok(broker);
            }
            if self.children[0]
                .as_ref()
                .is_some_and(|s| s.terminal.is_some() && !ready)
                || self.children[1]
                    .as_ref()
                    .is_some_and(|r| r.terminal.is_some())
                || self.failed
            {
                return Err(LaunchError::Invalid(
                    "reset lineage did not reach the exact handoff",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn start_clone(&mut self) -> Result<(), LaunchError> {
        let mut fd = -1;
        self.record(AnchorResetObservation::new(
            AnchorResetPhase::CloneAttempt,
            0,
            0,
        ))?;
        // S shares only memory, not descriptors/dispositions/thread group. H
        // cannot return from this call until S exits; S executes assembly only.
        let pid = unsafe { machine::spawn(self.mapping.context(), &raw mut fd) };
        if pid < 0 {
            self.record(AnchorResetObservation::new(
                AnchorResetPhase::CloneReturn,
                0,
                pid,
            ))?;
            return Err(io_error(
                "clone reset lineage",
                io::Error::from_raw_os_error((-pid) as i32),
            ));
        }
        // No fallible operation or allocation between committed atomic clone
        // return and retaining the real-child identity and original pidfd.
        self.children[0] = Some(Child::new(
            pid as i32,
            Some(unsafe { OwnedFd::from_raw_fd(fd) }),
        ));
        self.spawned = true;
        self.record(AnchorResetObservation::new(
            AnchorResetPhase::CloneReturn,
            pid as i32,
            pid,
        ))?;
        Ok(())
    }

    fn receive(&mut self) -> Result<(), LaunchError> {
        if self.packet_received {
            return Ok(());
        }
        let mut packet: Packet = unsafe { std::mem::zeroed() };
        let mut control = [0_usize; 16];
        let mut iov = libc::iovec {
            iov_base: (&raw mut packet).cast(),
            iov_len: 64,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let count = unsafe {
            libc::recvmsg(
                self.channels[0].as_raw_fd(),
                &raw mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count < 0
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN | libc::EINTR)
            )
        {
            return Ok(());
        }
        let mut observed =
            AnchorResetObservation::new(AnchorResetPhase::HandoffReceive, packet.pid, count as i64);
        if count < 0 {
            observed.errno = io::Error::last_os_error().raw_os_error();
        }
        observed.packet.copy_from_slice(unsafe {
            std::slice::from_raw_parts((&raw const packet).cast::<u8>(), 64)
        });
        let mut descriptor = None;
        let mut credentials = None;
        let mut rights = 0;
        let mut credential_count = 0;
        let mut valid =
            count == 64 && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0;
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            let c = unsafe { &*header };
            let base = unsafe { libc::CMSG_LEN(0) as usize };
            if c.cmsg_len < base {
                valid = false;
                break;
            }
            let length = c.cmsg_len - base;
            if c.cmsg_level == libc::SOL_SOCKET
                && c.cmsg_type == libc::SCM_RIGHTS
                && length % 4 == 0
            {
                for index in 0..length / 4 {
                    let fd = unsafe {
                        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(index))
                    };
                    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                    rights += 1;
                    if descriptor.is_none() {
                        descriptor = Some(owned);
                    }
                }
            } else if c.cmsg_level == libc::SOL_SOCKET
                && c.cmsg_type == libc::SCM_CREDENTIALS
                && length == std::mem::size_of::<libc::ucred>()
            {
                credential_count += 1;
                credentials = Some(unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
                });
            } else {
                valid = false;
            }
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }
        // Adopt/close every delivered descriptor before any fallible archive or
        // protocol check, including truncation and failed message interpretation.
        self.record(observed)?;
        let expected_s = self.children[0].as_ref().map(|s| s.pid);
        if !valid
            || rights != 1
            || credential_count != 1
            || !credentials.is_some_and(|c| {
                Some(c.pid) == expected_s && c.uid == self.host.uid && c.gid == self.host.gid
            })
            || packet.magic != HANDOFF_MAGIC
            || packet.session != self.session
            || packet.sequence != 1
            || packet.pid <= 0
            || packet.reserved != [0; 9]
        {
            return Err(LaunchError::Invalid(
                "unauthenticated reset lineage handoff",
            ));
        }
        if !eligible(packet.pid)? {
            return Err(LaunchError::Invalid(
                "reset reaper is outside exact parent wait domain",
            ));
        }
        let index = self.register(packet.pid)?;
        let handle = descriptor.ok_or(LaunchError::Invalid("reset handoff omitted pidfd"))?;
        // Exact real-parent, exit-signal-zero ownership keeps PID stable while
        // checking the transferred fd association. No post-terminal reopening.
        if discovery::pin_identity(&handle)? != packet.pid {
            return Err(LaunchError::Invalid("reset transferred pidfd differs"));
        }
        self.children[index].as_mut().unwrap().pin = Some(handle);
        if index != 1 {
            return Err(LaunchError::Invalid(
                "reset handoff exceeded exact topology",
            ));
        }
        self.packet_received = true;
        self.record(AnchorResetObservation::new(
            AnchorResetPhase::HandoffAuthenticated,
            packet.pid,
            0,
        ))?;
        Ok(())
    }

    fn register(&mut self, pid: i32) -> Result<usize, LaunchError> {
        if let Some(index) = self
            .children
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.pid == pid))
        {
            return Ok(index);
        }
        let index = (1..self.children.len())
            .find(|&i| self.children[i].is_none())
            .ok_or(LaunchError::Invalid(
                "reset cleanup records temporarily full",
            ))?;
        self.children[index] = Some(Child::new(pid, None));
        if index != 1 {
            self.failed = true;
        }
        // Registration precedes this fallible pin; WNOWAIT/eligibility already
        // establishes exact natural-parent numeric authority for cleanup.
        #[cfg(test)]
        if self.deny_pin {
            self.failed = true;
            return Ok(index);
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            self.failed = true;
        } else {
            self.children[index].as_mut().unwrap().pin =
                Some(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        Ok(index)
    }

    fn wait_one(&mut self, cleanup: bool) -> Result<bool, LaunchError> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::waitid(libc::P_ALL, 0, &raw mut info, WAIT_FLAGS) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(true);
            }
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(io_error("wait reset lineage domain", error));
        }
        let pid = unsafe { info.si_pid() };
        if pid == 0 {
            return Ok(false);
        }
        let index = self.register(pid)?;
        let mut status = 0;
        if unsafe {
            libc::waitpid(
                pid,
                &raw mut status,
                libc::WNOHANG | libc::WUNTRACED | libc::__WALL | libc::__WNOTHREAD,
            )
        } != pid
        {
            return Err(system("consume reset lineage wait"));
        }
        let child = self.children[index].as_mut().unwrap();
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            child.terminal = Some(status);
            child.stopped = None;
        } else if libc::WIFSTOPPED(status) {
            child.stopped = Some(status);
        } else {
            self.failed = true;
        }
        let mut observed =
            AnchorResetObservation::new(AnchorResetPhase::WaitConsumed, pid, i64::from(pid));
        observed.wait_status = Some(status);
        if let Err(error) = self.record(observed) {
            self.failed = true;
            if !cleanup {
                return Err(error);
            }
        }
        if cleanup {
            self.kill_known();
        }
        Ok(false)
    }

    fn record(&self, value: AnchorResetObservation) -> Result<(), LaunchError> {
        let mut data = self.archive.data();
        if data.reset_length == data.reset.len() {
            data.reset_overflow = true;
            return Err(LaunchError::Invalid(
                "reset diagnostic prefix capacity exhausted",
            ));
        }
        let index = data.reset_length;
        data.reset[index] = Some(value);
        data.reset_length += 1;
        Ok(())
    }

    fn kill_known(&mut self) {
        for child in self.children.iter_mut().flatten() {
            if child.terminal.is_some() {
                continue;
            }
            if let Some(pin) = &child.pin {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pin.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
            } else {
                // True direct-parent wait ownership, not mere numeric discovery.
                unsafe {
                    libc::syscall(libc::SYS_kill, child.pid, libc::SIGKILL);
                }
            }
        }
    }

    /// Retains the original owner until every pre-A child is physically reaped.
    /// The caller's deadline is not extended; caller cancellation stays bounded.
    pub(in crate::linux::remote::dynamic) fn cleanup(&mut self) -> Result<(), LaunchError> {
        self.thread()?;
        if !self.spawned || self.handed_off {
            return Ok(());
        }
        loop {
            self.kill_known();
            let mut empty = false;
            for _ in 0..8 {
                match self.wait_one(true) {
                    Ok(true) => {
                        empty = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(_) => {
                        self.failed = true;
                        break;
                    }
                }
            }
            // S's terminal is mandatory before treating ECHILD as final: only
            // then is further CLONE_PARENT creation by S impossible.
            if empty
                && self.children[0].as_ref().is_some_and(Child::physical)
                && self.children.iter().flatten().all(Child::physical)
            {
                return if self.failed {
                    Err(LaunchError::Invalid(
                        "reset lineage cleanup evidence failed",
                    ))
                } else {
                    Ok(())
                };
            }
            // Drain one unexpected owned child before reusing the fixed slot.
            if self.children[2].as_ref().is_some_and(Child::physical) {
                self.children[2] = None;
            }
            // If R has not run its self-stop, P_ALL can be live-but-empty.
            // Enumerate bounded candidates and authenticate each exact parent.
            for _ in 0..128 {
                match self.discovery.next() {
                    Ok(Some(pid)) => match eligible(pid) {
                        Ok(true) => {
                            if self.register(pid).is_err() {
                                self.failed = true;
                                break;
                            }
                            self.kill_known();
                        }
                        Ok(false) => {}
                        Err(_) => {
                            self.failed = true;
                            break;
                        }
                    },
                    Ok(None) => break,
                    Err(_) => {
                        self.failed = true;
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn eligible(pid: i32) -> Result<bool, LaunchError> {
    if pid <= 0 {
        return Ok(false);
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::waitid(libc::P_PID, pid as u32, &raw mut info, WAIT_FLAGS) } == 0 {
        // An empty siginfo is positive eligible-live-child evidence, not absence.
        let observed = unsafe { info.si_pid() };
        return if observed == 0 || observed == pid {
            Ok(true)
        } else {
            Err(LaunchError::Invalid(
                "reset wait eligibility identity differs",
            ))
        };
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ECHILD) {
        Ok(false)
    } else {
        Err(io_error("authenticate reset natural-parent child", error))
    }
}

impl Drop for ResetLaunch {
    fn drop(&mut self) {
        // Owner normally drains explicitly. This guard also keeps the same
        // thread alive on unwinding before a broker was installed.
        if self.spawned && !self.handed_off {
            let _ = self.cleanup();
        }
    }
}
