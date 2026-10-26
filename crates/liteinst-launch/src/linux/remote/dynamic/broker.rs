//! Private real-ancestor reaper. Ptrace terminal waits and natural-parent waits
//! are separate receipts; only the latter plus pidfd HUP prove physical removal.
use super::*;

mod raw;

const MAGIC: u64 = 0x4c49_3244_5241_494e;
const READY: u32 = 1;
const REAPED: u32 = 2;
const DONE: u32 = 3;
const FAILED: u32 = 4;
const SEIZED: u32 = 5;
const ABORT: u32 = 6;
const ANCHOR_START: u32 = 7;

#[derive(Clone, Copy)]
#[repr(C)]
struct Packet {
    magic: u64,
    session: u64,
    sequence: u64,
    kind: u32,
    pid: i32,
    status: i32,
    error: i32,
    count: u64,
    reserved: [u64; 2],
}
const _: () = assert!(std::mem::size_of::<Packet>() == 64);
impl Packet {
    fn new(session: u64, sequence: u64, kind: u32) -> Self {
        Self {
            magic: MAGIC,
            session,
            sequence,
            kind,
            pid: 0,
            status: 0,
            error: 0,
            count: 0,
            reserved: [0; 2],
        }
    }
}

pub(super) struct Broker {
    pub(super) pid: libc::pid_t,
    handle: OwnedFd,
    channel: OwnedFd,
    session: u64,
    credentials: libc::ucred,
    next_sequence: u64,
    acknowledged: bool,
    abort_sent: bool,
    pub(super) root: Option<(libc::pid_t, OwnedFd)>,
    pub(super) physical: std::collections::BTreeMap<libc::pid_t, i32>,
    pub(super) done: bool,
    terminal: Option<i32>,
    failed: bool,
    ready_seen: bool,
    anchor_start_pending: bool,
    anchor_grant_sent: bool,
    #[cfg(test)]
    pub(super) failure_root: Option<i32>,
}

impl Broker {
    pub(super) fn spawn(session: u64, bootstrap: launch::Bootstrap) -> Result<Self, LaunchError> {
        let mut sockets = [-1; 2];
        // SAFETY: writable descriptor slots; no endpoint is shared with clients.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                sockets.as_mut_ptr(),
            )
        } != 0
        {
            return Err(system("create reaper protocol"));
        }
        // SAFETY: each returned descriptor is newly owned.
        let channel = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
        let child_channel = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
        let enable = 1_i32;
        for socket in [channel.as_raw_fd(), child_channel.as_raw_fd()] {
            // SAFETY: exact initialized option and native option size.
            if unsafe {
                libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&raw const enable).cast(),
                    std::mem::size_of_val(&enable) as libc::socklen_t,
                )
            } != 0
            {
                return Err(system("authenticate reaper messages"));
            }
        }
        // Capture real IDs: these are the credentials the kernel attaches to
        // SCM_CREDENTIALS, not a socketpair's pre-clone SO_PEERCRED identity.
        let host = libc::ucred {
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        // Other pre-exec applications may temporarily hold inherited CLOEXEC
        // socket copies. Host death must not depend on observing channel EOF.
        let host_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, host.pid, 0) };
        if host_fd < 0 {
            return Err(system("pin reaper host identity"));
        }
        let host_handle = unsafe { OwnedFd::from_raw_fd(host_fd as i32) };
        let mut descriptor = -1;
        // SAFETY: no CLONE_VM, null stack, atomic pidfd, exit signal zero. The
        // child enters a raw-syscall-only function which never returns to Rust.
        let pid = unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::CLONE_PIDFD,
                std::ptr::null::<u8>(),
                &raw mut descriptor,
                std::ptr::null::<u8>(),
                0,
            )
        };
        if pid == 0 {
            unsafe { raw::run(sockets, session, host, host_handle.as_raw_fd(), bootstrap) }
        }
        if pid < 0 {
            return Err(system("clone private reaper"));
        }
        // CLONE_PIDFD success atomically supplies this descriptor; establish
        // ownership without another fallible operation after the clone.
        let handle = unsafe { OwnedFd::from_raw_fd(descriptor) };
        Ok(Self {
            pid: pid as i32,
            handle,
            channel,
            session,
            credentials: libc::ucred {
                pid: pid as i32,
                ..host
            },
            next_sequence: 1,
            acknowledged: false,
            abort_sent: false,
            root: None,
            physical: Default::default(),
            done: false,
            terminal: None,
            failed: false,
            ready_seen: false,
            anchor_start_pending: false,
            anchor_grant_sent: false,
            #[cfg(test)]
            failure_root: None,
        })
    }

    pub(super) fn acknowledge(&mut self, seized: bool) -> Result<(), LaunchError> {
        if self.acknowledged {
            return Err(LaunchError::Invalid(
                "duplicate reaper attachment acknowledgement",
            ));
        }
        self.send(if seized { SEIZED } else { ABORT })?;
        self.acknowledged = true;
        self.abort_sent = !seized;
        Ok(())
    }
    fn send(&self, kind: u32) -> Result<(), LaunchError> {
        let packet = Packet::new(self.session, if self.acknowledged { 2 } else { 1 }, kind);
        // SAFETY: fixed initialized packet and an owned private channel.
        if unsafe { raw::send(self.channel.as_raw_fd(), &packet, -1) } == 1 {
            Ok(())
        } else {
            Err(system("send private reaper command"))
        }
    }
    // The reset launcher installs this Broker before START can allow A to exist.
    pub(super) fn anchor_start_pending(&self) -> bool {
        self.anchor_start_pending
    }
    pub(super) fn anchor_no_application_possible(&self) -> bool {
        self.anchor_start_pending && !self.anchor_grant_sent
    }
    pub(super) fn release_anchor(&mut self) -> Result<(), LaunchError> {
        if !self.anchor_start_pending || self.acknowledged {
            return Err(LaunchError::Invalid(
                "anchor broker is not awaiting its start grant",
            ));
        }
        let packet = Packet::new(self.session, 0, ANCHOR_START);
        if unsafe { raw::send(self.channel.as_raw_fd(), &packet, -1) } != 1 {
            return Err(system("grant anchored reaper start"));
        }
        self.anchor_grant_sent = true;
        self.continue_anchor()
    }
    fn continue_anchor(&self) -> Result<(), LaunchError> {
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.handle.as_raw_fd(),
                libc::SIGCONT,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } != 0
        {
            return Err(system("continue anchored reaper barrier"));
        }
        Ok(())
    }
    pub(super) fn cancel(&mut self) {
        // Before READY, R may still be held at its genuine pre-A SIGSTOP.
        // Continuing only R enters the private authenticated command barrier.
        if self.anchor_start_pending {
            let _ = self.continue_anchor();
        }
        if self.abort_sent || self.done {
            return;
        }
        if self.send(ABORT).is_ok() {
            self.acknowledged = true;
            self.abort_sent = true;
        }
    }
    pub(super) fn poll(&mut self) -> Result<(), LaunchError> {
        loop {
            let mut received = raw::Received::empty();
            // SAFETY: fixed initialized storage, descriptor adopted before any
            // validation that can fail. raw::receive closes duplicate rights.
            let result = unsafe { raw::receive(self.channel.as_raw_fd(), &mut received) };
            let descriptor = (received.descriptor >= 0)
                .then(|| unsafe { OwnedFd::from_raw_fd(received.descriptor) });
            if result == 0 {
                return if self.failed {
                    Err(LaunchError::Invalid("private reaper protocol failed"))
                } else {
                    Ok(())
                };
            }
            if result < 0 {
                if self.done {
                    return Ok(());
                }
                self.failed = true;
                return Err(LaunchError::Invalid(
                    "private reaper protocol ended without drain receipt",
                ));
            }
            let packet = received.packet;
            if !received.valid
                || received.credentials.pid != self.credentials.pid
                || received.credentials.uid != self.credentials.uid
                || received.credentials.gid != self.credentials.gid
                || packet.magic != MAGIC
                || packet.session != self.session
                || packet.sequence != self.next_sequence
                || packet.reserved != [0; 2]
                || self.done
            {
                self.failed = true;
                return Err(LaunchError::Invalid(
                    "unauthenticated private reaper packet",
                ));
            }
            // Any fallible validation below must leave cancellation enabled,
            // including missing rights or fdinfo failure before Ready adoption.
            let prior_failure = self.failed;
            self.failed = true;
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or(LaunchError::Invalid("reaper sequence exhausted"))?;
            match packet.kind {
                READY
                    if !self.ready_seen
                        && packet.pid > 0
                        && packet.status == 0
                        && packet.error == 0
                        && packet.count == 0 =>
                {
                    let descriptor = descriptor
                        .ok_or(LaunchError::Invalid("reaper omitted atomic child pidfd"))?;
                    // The real parent does not consume this child's terminal
                    // status before Seized/Abort. Thus fdinfo and numeric SEIZE
                    // refer to the same unreaped incarnation without a reuse gap.
                    let info = std::fs::read_to_string(format!(
                        "/proc/self/fdinfo/{}",
                        descriptor.as_raw_fd()
                    ))
                    .map_err(|e| io_error("read transferred pidfd identity", e))?;
                    let identity = info
                        .lines()
                        .find_map(|line| line.strip_prefix("Pid:\t"))
                        .and_then(|value| value.parse::<i32>().ok());
                    if identity != Some(packet.pid) {
                        self.failed = true;
                        return Err(LaunchError::Invalid("transferred pidfd identity mismatch"));
                    }
                    self.root = Some((packet.pid, descriptor));
                    self.ready_seen = true;
                    self.anchor_start_pending = false;
                }
                REAPED
                    if descriptor.is_none()
                        && packet.pid > 0
                        && packet.error == 0
                        && (libc::WIFEXITED(packet.status) || libc::WIFSIGNALED(packet.status))
                        && packet.count == self.physical.len() as u64 + 1 =>
                {
                    if self.physical.insert(packet.pid, packet.status).is_some() {
                        self.failed = true;
                        return Err(LaunchError::Invalid("duplicate physical reap receipt"));
                    }
                }
                DONE if descriptor.is_none()
                    && packet.pid == 0
                    && packet.status == 0
                    && packet.error == 0
                    && packet.count == self.physical.len() as u64 =>
                {
                    self.done = true;
                    self.anchor_start_pending = false;
                }
                FAILED
                    if descriptor.is_none()
                        && !self.ready_seen
                        && packet.pid >= 0
                        && packet.status == 0
                        && packet.error > 0
                        && packet.count == 0 =>
                {
                    #[cfg(test)]
                    {
                        self.failure_root = (packet.pid > 0).then_some(packet.pid);
                    }
                    self.failed = true;
                    return Err(LaunchError::Invalid("private reaper bootstrap failed"));
                }
                _ => {
                    self.failed = true;
                    return Err(LaunchError::Invalid(
                        "invalid private reaper packet ordering",
                    ));
                }
            }
            self.failed = prior_failure;
        }
    }
    #[cfg(test)]
    pub(super) fn disconnect_for_test(&self) {
        // The live helper sees EOF; the host must still collect actual waits.
        assert_eq!(
            unsafe { libc::shutdown(self.channel.as_raw_fd(), libc::SHUT_RDWR) },
            0
        );
    }
    pub(super) fn terminal(&mut self, status: i32) {
        if self.terminal.replace(status).is_some()
            || !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 0
        {
            self.failed = true;
        }
    }
    pub(super) fn finished(&self) -> Result<bool, LaunchError> {
        // A protocol error never retires the helper's real-child wait ownership.
        // Even FAILED/EOF must be followed by harvesting its actual terminal.
        if self.terminal.is_none() || !hup(&self.handle) {
            return Ok(false);
        }
        if self.failed || !self.done {
            return Err(LaunchError::Invalid(
                "private physical reaper ownership failed",
            ));
        }
        Ok(true)
    }
}

pub(super) fn hup(handle: &OwnedFd) -> bool {
    let mut event = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: initialized entry and stable original process identity. Linux
    // pidfd_poll returns HUP only after PIDTYPE_PID has no remaining task.
    unsafe { libc::poll(&raw mut event, 1, 0) == 1 && event.revents & libc::POLLHUP != 0 }
}

/// Prepared descriptor ownership for the opt-in reset lineage; no child exists.
pub(super) struct AnchorBroker {
    channel: OwnedFd,
    child_channel: OwnedFd,
    host_handle: OwnedFd,
    raw: AnchorRaw,
}
#[derive(Clone, Copy)]
pub(super) struct AnchorRaw {
    sockets: [i32; 2],
    session: u64,
    host: libc::ucred,
    host_fd: i32,
    bootstrap: launch::Bootstrap,
    #[cfg(test)]
    hold_before_stop: bool,
}
impl AnchorBroker {
    pub(super) fn prepare(session: u64, bootstrap: launch::Bootstrap) -> Result<Self, LaunchError> {
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
            return Err(system("create anchored reaper protocol"));
        }
        let channel = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
        let child_channel = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
        let enable = 1_i32;
        for fd in sockets {
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&raw const enable).cast(),
                    std::mem::size_of_val(&enable) as _,
                )
            } != 0
            {
                return Err(system("authenticate anchored reaper protocol"));
            }
        }
        let host = libc::ucred {
            pid: unsafe { libc::getpid() },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, host.pid, 0) };
        if fd < 0 {
            return Err(system("pin anchored reaper host"));
        }
        let host_handle = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let raw = AnchorRaw {
            sockets,
            session,
            host,
            host_fd: host_handle.as_raw_fd(),
            bootstrap,
            #[cfg(test)]
            hold_before_stop: false,
        };
        Ok(Self {
            channel,
            child_channel,
            host_handle,
            raw,
        })
    }
    pub(super) fn raw(&self) -> AnchorRaw {
        self.raw
    }
    pub(super) fn adopt(self, pid: i32, handle: OwnedFd) -> Broker {
        // Drop only H's private copies; R already inherited its own table.
        drop(self.child_channel);
        drop(self.host_handle);
        Broker {
            pid,
            handle,
            channel: self.channel,
            session: self.raw.session,
            credentials: libc::ucred {
                pid,
                ..self.raw.host
            },
            next_sequence: 1,
            acknowledged: false,
            abort_sent: false,
            root: None,
            physical: Default::default(),
            done: false,
            terminal: None,
            failed: false,
            ready_seen: false,
            anchor_start_pending: true,
            anchor_grant_sent: false,
            #[cfg(test)]
            failure_root: None,
        }
    }
}
pub(super) unsafe fn anchor_child(input: AnchorRaw, reset_channels: [i32; 2]) -> ! {
    unsafe {
        for fd in reset_channels {
            libc::syscall(libc::SYS_close, fd);
        }
        raw::anchor_prelude(input)
    }
}

#[cfg(test)]
impl AnchorRaw {
    pub(super) fn hold_before_stop(mut self) -> Self {
        self.hold_before_stop = true;
        self
    }
}
