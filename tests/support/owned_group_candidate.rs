//! Bounded candidate filtering for fixed inherited-process-group test bodies.
//!
//! The unreaped leader pins the group number. These bodies and their descendants
//! never change groups, escape, or join another campaign's group. A kernel
//! group match is only a candidate: the exact stat identity and direct parent
//! remain mandatory, followed by the caller's existing waitid/reap checks.
//! This does not provide a snapshot for group-changing workloads or guarantee
//! completion within the unchanged deadline under arbitrary scheduling delay.

use std::io;

#[derive(Default)]
pub(super) struct Inventory {
    pub(super) entries: usize,
    pub(super) numeric: usize,
    pub(super) same_group: usize,
    pub(super) stat_open_attempts: usize,
    pub(super) stat_reads: usize,
}

impl Inventory {
    // Count every returned directory entry, including nonnumeric entries and
    // the first refused entry. At most 65,536 may proceed to examination.
    pub(super) fn entry(&mut self, expired: bool) -> Result<(), String> {
        self.entries += 1;
        if self.entries > 65536 {
            return Err(self.error("bounded process inventory entry limit exhausted"));
        }
        if expired {
            return Err(self.error("bounded process inventory deadline exhausted"));
        }
        Ok(())
    }

    pub(super) fn error(&self, message: &str) -> String {
        format!(
            "{message}; entries={} numeric={} same_group={} stat_open_attempts={} stat_reads={}",
            self.entries, self.numeric, self.same_group, self.stat_open_attempts, self.stat_reads,
        )
    }
}

pub(super) fn owned_group_candidate(
    pid: i32,
    owned_parent: u32,
    group: i32,
    mut expired: impl FnMut() -> bool,
    lookup: impl FnOnce(i32) -> io::Result<i32>,
    read: impl FnOnce() -> io::Result<Option<Vec<u8>>>,
) -> Result<bool, String> {
    if pid <= 0 || group <= 0 || owned_parent == 0 {
        return Err("invalid positive process ownership identity".into());
    }
    if expired() {
        return Err("bounded process inventory deadline before group lookup".into());
    }
    let observed = lookup(pid);
    // Check even a foreign/disappeared candidate: filtering never resets or
    // exempts work from the caller's one original cleanup deadline.
    if expired() {
        return Err("bounded process inventory deadline after group lookup".into());
    }
    let observed = match observed {
        // Kernel tasks may report group zero. It cannot match the positive
        // owned group, but is a valid foreign candidate, as in the stat scan.
        Ok(group) if group >= 0 => group,
        Ok(_) => return Err("invalid kernel process group".into()),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(false),
        Err(error) => return Err(format!("getpgid({pid}): {error}")),
    };
    if observed != group {
        return Ok(false);
    }
    let bytes = read().map_err(|error| format!("read /proc/{pid}/stat: {error}"))?;
    if expired() {
        return Err("bounded process stat read deadline exhausted".into());
    }
    let Some(bytes) = bytes else {
        return Ok(false);
    };
    if bytes.len() > 4096 {
        return Err(format!(
            "bounded process stat size exhausted: bytes={}",
            bytes.len()
        ));
    }
    if !bytes.starts_with(format!("{pid} (").as_bytes()) {
        return Err("process stat identity mismatch".into());
    }
    // comm may contain arbitrary non-UTF8 bytes and parentheses. Only
    // the numeric fields after its final delimiter are ASCII-parsed.
    let close = bytes
        .windows(2)
        .rposition(|pair| pair == b") ")
        .ok_or("malformed process stat")?;
    let suffix =
        std::str::from_utf8(&bytes[close + 2..]).map_err(|_| "non-ASCII numeric process fields")?;
    let fields: Vec<_> = suffix.split_whitespace().collect();
    if fields.len() < 3 {
        return Err("short process stat".into());
    }
    let parent: u32 = fields[1].parse().map_err(|_| "invalid parent PID")?;
    let pgrp: i32 = fields[2].parse().map_err(|_| "invalid process group")?;
    Ok(parent == owned_parent && pgrp == group)
}
