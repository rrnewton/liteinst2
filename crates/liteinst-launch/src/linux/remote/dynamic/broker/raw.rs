//! No allocation, locks, Rust unwinding or callbacks are permitted after clone.
//! Every helper branch ends in raw _exit; all protocol storage is fixed-size.
use super::*;

pub(super) struct Received {
    pub(super) packet: Packet,
    pub(super) descriptor: i32,
    pub(super) credentials: libc::ucred,
    pub(super) valid: bool,
}
impl Received {
    pub(super) fn empty() -> Self {
        Self {
            packet: Packet::new(0, 0, 0),
            descriptor: -1,
            credentials: libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            },
            valid: false,
        }
    }
}

/// 1 packet, 0 would-block/interrupted, -1 EOF/malformed/io error. Every received
/// right is either returned once or closed, even when ancillary data is invalid.
pub(super) unsafe fn receive(fd: i32, output: &mut Received) -> i32 {
    unsafe {
        let mut control = [0_usize; 16];
        let mut iov = libc::iovec {
            iov_base: (&raw mut output.packet).cast(),
            iov_len: 64,
        };
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        let size = libc::syscall(
            libc::SYS_recvmsg,
            fd,
            &raw mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        );
        if size < 0 {
            return if matches!(*libc::__errno_location(), libc::EAGAIN | libc::EINTR) {
                0
            } else {
                -1
            };
        }
        let mut credentials = 0;
        let mut rights = 0;
        let mut valid = size == 64 && message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0;
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let length = (*header).cmsg_len;
            if length < libc::CMSG_LEN(0) as usize {
                valid = false;
                break;
            }
            let payload = length - libc::CMSG_LEN(0) as usize;
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_CREDENTIALS
                && payload == std::mem::size_of::<libc::ucred>()
            {
                credentials += 1;
                output.credentials =
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>());
            } else if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && payload.is_multiple_of(std::mem::size_of::<i32>())
            {
                let count = payload / std::mem::size_of::<i32>();
                let mut index = 0;
                while index < count {
                    let descriptor =
                        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(index));
                    rights += 1;
                    if rights == 1 {
                        output.descriptor = descriptor;
                    } else {
                        libc::syscall(libc::SYS_close, descriptor);
                    }
                    index += 1;
                }
            } else {
                valid = false;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        output.valid = valid && credentials == 1 && rights <= 1;
        if size == 0 { -1 } else { 1 }
    }
}

pub(super) unsafe fn send(fd: i32, packet: &Packet, descriptor: i32) -> i32 {
    unsafe {
        let mut control = [0_usize; 4];
        let mut iov = libc::iovec {
            iov_base: (packet as *const Packet).cast_mut().cast(),
            iov_len: 64,
        };
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &raw mut iov;
        message.msg_iovlen = 1;
        if descriptor >= 0 {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), descriptor);
        }
        let result = libc::syscall(
            libc::SYS_sendmsg,
            fd,
            &raw const message,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        );
        if result == 64 {
            1
        } else if result < 0 && matches!(*libc::__errno_location(), libc::EAGAIN | libc::EINTR) {
            0
        } else {
            -1
        }
    }
}

#[repr(C)]
struct KernelAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

unsafe fn keep_only(channel: i32, pidfd: i32, host_fd: i32) -> bool {
    unsafe {
        let mut low = channel.min(pidfd) as u32;
        let mut high = channel.max(pidfd) as u32;
        let mut middle = host_fd as u32;
        if middle < low {
            std::mem::swap(&mut middle, &mut low);
        }
        if middle > high {
            std::mem::swap(&mut middle, &mut high);
        }
        // A already inherited the intended descriptor table. R retains only
        // its private protocol, application pidfd and original host pidfd.
        let first = low == 0 || libc::syscall(libc::SYS_close_range, 0_u32, low - 1, 0) == 0;
        let second =
            middle <= low + 1 || libc::syscall(libc::SYS_close_range, low + 1, middle - 1, 0) == 0;
        let third = high <= middle + 1
            || libc::syscall(libc::SYS_close_range, middle + 1, high - 1, 0) == 0;
        let last = libc::syscall(libc::SYS_close_range, high + 1, u32::MAX, 0) == 0;
        first && second && third && last
    }
}

pub(super) unsafe fn run(
    sockets: [i32; 2],
    session: u64,
    host: libc::ucred,
    host_fd: i32,
    bootstrap: launch::Bootstrap,
) -> ! {
    unsafe {
        libc::syscall(libc::SYS_close, sockets[0]);
        let channel = sockets[1];
        let mut root_fd = -1_i32;
        let mut root = -1_i32;
        let mut failure = 0;
        if libc::syscall(libc::SYS_prctl, libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0 {
            failure = *libc::__errno_location();
        } else {
            let result = libc::syscall(
                libc::SYS_clone,
                libc::CLONE_PIDFD,
                std::ptr::null::<u8>(),
                &raw mut root_fd,
                std::ptr::null::<u8>(),
                0,
            );
            if result == 0 {
                libc::syscall(libc::SYS_close, channel);
                libc::syscall(libc::SYS_close, host_fd);
                launch::child_bootstrap(bootstrap)
            }
            if result < 0 {
                failure = *libc::__errno_location();
            } else {
                root = result as i32;
            }
        }
        if root > 0 {
            // A still holds the release barrier and its copy of the original
            // dispositions/session. Alter only R after that copy was made.
            let action = KernelAction {
                handler: 0,
                flags: 0,
                restorer: 0,
                mask: 0,
            };
            if libc::syscall(
                libc::SYS_rt_sigaction,
                libc::SIGCHLD,
                &raw const action,
                std::ptr::null::<u8>(),
                KERNEL_SIGSET_BYTES,
            ) < 0
                || libc::syscall(libc::SYS_setsid) < 0
                || !keep_only(channel, root_fd, host_fd)
            {
                failure = *libc::__errno_location();
            }
        } else {
            // No application exists, but inherited launch/error descriptors
            // still must close while the failure packet is being delivered.
            bootstrap.close_all();
        }
        #[cfg(test)]
        if bootstrap.fail_before_ready && root > 0 {
            failure = libc::ECANCELED;
        }
        let mut sequence = 1_u64;
        let mut pending = Packet::new(session, sequence, if failure == 0 { READY } else { FAILED });
        pending.pid = root.max(0);
        pending.error = failure;
        let mut pending_fd = if failure == 0 { root_fd } else { -1 };
        let mut have_pending = true;
        let mut client_alive = true;
        let mut acknowledged = root <= 0;
        let mut command_sequence = 1_u64;
        let mut cancel = failure != 0;
        let mut count = 0_u64;
        let mut done = false;
        loop {
            let mut host_event = libc::pollfd {
                fd: host_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::syscall(libc::SYS_poll, &raw mut host_event, 1, 0) == 1
                && host_event.revents & (libc::POLLIN | libc::POLLHUP) != 0
            {
                client_alive = false;
                acknowledged = true;
                cancel = true;
            }
            let mut command = Received::empty();
            let read = if client_alive {
                receive(channel, &mut command)
            } else {
                0
            };
            if command.descriptor >= 0 {
                libc::syscall(libc::SYS_close, command.descriptor);
                command.valid = false;
            }
            if read < 0 {
                client_alive = false;
                acknowledged = true;
                cancel = true;
            } else if read == 1 {
                let packet = command.packet;
                if !command.valid
                    || command.credentials.pid != host.pid
                    || command.credentials.uid != host.uid
                    || command.credentials.gid != host.gid
                    || packet.magic != MAGIC
                    || packet.session != session
                    || packet.sequence != command_sequence
                    || packet.reserved != [0; 2]
                    || packet.pid != 0
                    || packet.status != 0
                    || packet.error != 0
                    || packet.count != 0
                    || !matches!(packet.kind, SEIZED | ABORT)
                    || (acknowledged && packet.kind != ABORT)
                {
                    client_alive = false;
                    cancel = true;
                    acknowledged = true;
                } else {
                    acknowledged = true;
                    cancel |= packet.kind == ABORT;
                    command_sequence = command_sequence.saturating_add(1);
                }
            }
            if cancel && root_fd >= 0 {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    root_fd,
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            if have_pending && client_alive {
                let sent = send(channel, &pending, pending_fd);
                if sent == 1 {
                    have_pending = false;
                } else if sent < 0 {
                    client_alive = false;
                    cancel = true;
                    acknowledged = true;
                }
            }
            if !client_alive {
                have_pending = false;
            }
            if done && !have_pending {
                libc::_exit(if failure == 0 { 0 } else { 125 });
            }
            // This barrier is also a numeric-PID non-reuse guarantee for H's
            // SEIZE: even an early dead A remains unreaped until Seized/Abort.
            if acknowledged && !have_pending {
                let mut status = 0;
                let pid = libc::syscall(
                    libc::SYS_wait4,
                    -1,
                    &raw mut status,
                    libc::WNOHANG | libc::__WALL,
                    std::ptr::null::<libc::rusage>(),
                );
                if pid > 0 {
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        count = count.saturating_add(1);
                        sequence = sequence.saturating_add(1);
                        pending = Packet::new(session, sequence, REAPED);
                        pending.pid = pid as i32;
                        pending.status = status;
                        pending.count = count;
                        pending_fd = -1;
                        have_pending = true;
                    }
                } else if pid < 0 && *libc::__errno_location() == libc::ECHILD {
                    sequence = sequence.saturating_add(1);
                    pending = Packet::new(session, sequence, DONE);
                    pending.count = count;
                    pending_fd = -1;
                    have_pending = true;
                    done = true;
                }
            }
            let mut event = libc::pollfd {
                fd: channel,
                events: libc::POLLIN | if have_pending { libc::POLLOUT } else { 0 },
                revents: 0,
            };
            // Bounded nonblocking waits keep EOF/Abort observable under queue
            // pressure and while tracee stops still require H's continuation.
            libc::syscall(
                libc::SYS_poll,
                &raw mut event,
                if client_alive { 1 } else { 0 },
                1,
            );
        }
    }
}
