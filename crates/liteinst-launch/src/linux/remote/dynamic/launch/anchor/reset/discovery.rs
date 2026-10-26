//! Bounded candidate enumeration. Only waitid grants parent ownership.
use super::*;

const PROC_MAGIC: libc::c_long = 0x9fa0;

fn genuine(fd: i32) -> Result<(), LaunchError> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd, &raw mut stat) } != 0 {
        return Err(system("authenticate reset procfs"));
    }
    if stat.f_type != PROC_MAGIC {
        return Err(LaunchError::Invalid(
            "reset discovery is not genuine procfs",
        ));
    }
    Ok(())
}

pub(super) struct Discovery {
    directory: OwnedFd,
    children: Option<OwnedFd>,
    buffer: [u8; 8192],
    length: usize,
    cursor: usize,
    reload_children: bool,
}
impl Discovery {
    #[cfg(test)]
    pub(super) fn use_proc_candidates(&mut self) {
        self.children = None;
        self.length = 0;
        self.cursor = 0;
    }
    pub(super) fn new(tid: i32) -> Result<Self, LaunchError> {
        let fd = unsafe {
            libc::open(
                c"/proc".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(system("open reset discovery procfs"));
        }
        let directory = unsafe { OwnedFd::from_raw_fd(fd) };
        genuine(fd)?;
        let path = CString::new(format!("self/task/{tid}/children"))
            .map_err(|_| LaunchError::Invalid("invalid reset children path"))?;
        let child_fd = unsafe { libc::openat(fd, path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        let children = if child_fd >= 0 {
            let handle = unsafe { OwnedFd::from_raw_fd(child_fd) };
            genuine(child_fd)?;
            Some(handle)
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            None
        } else {
            return Err(system("open exact reset children interface"));
        };
        Ok(Self {
            directory,
            children,
            buffer: [0; 8192],
            length: 0,
            cursor: 0,
            reload_children: true,
        })
    }

    pub(super) fn next(&mut self) -> Result<Option<i32>, LaunchError> {
        if let Some(children) = &self.children {
            if self.reload_children {
                let count = unsafe {
                    libc::pread(
                        children.as_raw_fd(),
                        self.buffer.as_mut_ptr().cast(),
                        self.buffer.len(),
                        0,
                    )
                };
                if count < 0 || count as usize == self.buffer.len() {
                    // The optional interface cannot strand an already owned R.
                    self.children = None;
                    self.length = 0;
                    self.cursor = 0;
                    return Err(LaunchError::Invalid(
                        "reset children census could not be read completely",
                    ));
                }
                self.length = count as usize;
                self.cursor = 0;
                self.reload_children = false;
            }
            while self.cursor < self.length && self.buffer[self.cursor].is_ascii_whitespace() {
                self.cursor += 1;
            }
            if self.cursor == self.length {
                self.reload_children = true;
                return Ok(None);
            }
            let begin = self.cursor;
            while self.cursor < self.length && !self.buffer[self.cursor].is_ascii_whitespace() {
                self.cursor += 1;
            }
            if let Some(pid) = number(&self.buffer[begin..self.cursor]) {
                return Ok(Some(pid));
            }
            self.children = None;
            self.length = 0;
            self.cursor = 0;
            return Err(LaunchError::Invalid(
                "malformed exact reset children census",
            ));
        }
        // Even nonnumeric procfs entries consume this fixed pass budget.
        for _ in 0..128 {
            if self.cursor == self.length {
                let count = unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        self.directory.as_raw_fd(),
                        self.buffer.as_mut_ptr(),
                        self.buffer.len(),
                    )
                };
                if count < 0 {
                    return Err(system("read reset procfs candidates"));
                }
                self.cursor = 0;
                self.length = count as usize;
                if self.length == 0 {
                    if unsafe { libc::lseek(self.directory.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
                        return Err(system("rewind reset procfs candidates"));
                    }
                    return Ok(None);
                }
            }
            let available = &self.buffer[self.cursor..self.length];
            if available.len() < 20 {
                return Err(LaunchError::Invalid("short procfs directory entry"));
            }
            let length = u16::from_ne_bytes([available[16], available[17]]) as usize;
            if length < 20 || length > available.len() {
                return Err(LaunchError::Invalid("invalid procfs directory entry"));
            }
            let name = &available[19..length];
            let end = name
                .iter()
                .position(|&b| b == 0)
                .ok_or(LaunchError::Invalid("unterminated procfs candidate"))?;
            let pid = number(&name[..end]);
            self.cursor += length;
            if pid.is_some() {
                return Ok(pid);
            }
        }
        Ok(None)
    }
}

fn number(bytes: &[u8]) -> Option<i32> {
    if bytes.is_empty() || bytes.len() > 10 {
        return None;
    }
    let mut value = 0_i32;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
    }
    (value > 0).then_some(value)
}

pub(super) fn pin_identity(handle: &OwnedFd) -> Result<i32, LaunchError> {
    // Fixed local path and output storage; no source-controlled allocation.
    let mut path = [0_u8; 64];
    let prefix = b"/proc/self/fdinfo/";
    path[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0_u8; 10];
    let mut n = handle.as_raw_fd() as u32;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (n % 10) as u8;
        count += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for i in 0..count {
        path[prefix.len() + i] = digits[count - i - 1];
    }
    let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(system("open reset pidfd identity"));
    }
    let file = unsafe { OwnedFd::from_raw_fd(fd) };
    genuine(file.as_raw_fd())?;
    let mut bytes = [0_u8; 4096];
    let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    if count <= 0 || count as usize == bytes.len() {
        return Err(LaunchError::Invalid("incomplete reset pidfd identity"));
    }
    let bytes = &bytes[..count as usize];
    if bytes.last() != Some(&b'\n') || bytes.contains(&0) {
        return Err(LaunchError::Invalid("malformed reset pidfd identity"));
    }
    let mut identity = None;
    for line in bytes.split(|&b| b == b'\n') {
        if let Some(pid) = line.strip_prefix(b"Pid:\t") {
            if identity.is_some() {
                return Err(LaunchError::Invalid("duplicate reset pidfd identity"));
            }
            identity =
                Some(number(pid).ok_or(LaunchError::Invalid("reset pidfd has no live identity"))?);
        }
    }
    identity.ok_or(LaunchError::Invalid("missing reset pidfd identity"))
}
