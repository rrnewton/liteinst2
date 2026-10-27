//! Actual PID namespace-object association; no numeric PID normalization.
use super::super::observe::io::{CloseGuard, proc_name};
use super::*;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in super::super) struct Record {
    pub(in super::super) opened: Option<Outcome>,
    pub(in super::super) stat: Option<Outcome>,
    pub(in super::super) filesystem: Option<Outcome>,
    pub(in super::super) device: u64,
    pub(in super::super) inode: u64,
    pub(in super::super) magic: i64,
    pub(in super::super) closed: Option<Outcome>,
    pub(in super::super) complete: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super) struct Namespace {
    pub(in super::super) records: [Record; 2],
    pub(in super::super) complete: bool,
}
impl Namespace {
    pub(super) fn empty() -> Self {
        Self {
            records: [Record::default(); 2],
            complete: false,
        }
    }
    pub(super) fn identity(&self) -> Option<(u64, u64)> {
        self.complete
            .then_some((self.records[0].device, self.records[0].inode))
    }
    pub(super) fn require_complete(&self) -> Result<(), OracleError> {
        if !self.complete {
            return Err(OracleError::Invalid("raw namespace incomplete"));
        }
        require_records(&self.records)
    }
    pub(super) fn capture(&mut self, owner: &Owner, until: Instant) -> Result<(), OracleError> {
        if self.complete || self.records[0].opened.is_some() {
            return Err(OracleError::Invalid("raw namespace capture reused"));
        }
        for (index, pid) in [unsafe { libc::getpid() }, owner.pid]
            .into_iter()
            .enumerate()
        {
            bootstrap::physical(owner, until)?;
            let mut path = [0_u8; 48];
            let path = proc_name(pid, b"/ns/pid", &mut path)?;
            let record = &mut self.records[index];
            // ns/pid is deliberately a procfs namespace magic link. The opened
            // namespace inode, not link text or numeric PID, is compared.
            let opened = outcome(|| {
                i64::from(unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) })
            });
            record.opened = Some(opened);
            if !(0..=i64::from(i32::MAX)).contains(&opened.result) {
                return Err(OracleError::Io {
                    operation: "raw open PID namespace",
                    errno: (opened.errno != 0).then_some(opened.errno),
                });
            }
            let fd = CloseGuard::new(opened.result as i32, &mut record.closed);
            if opened.errno != 0 {
                return Err(OracleError::Invalid("raw namespace open errno differs"));
            }
            bootstrap::physical(owner, until)?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            let result = outcome(|| i64::from(unsafe { libc::fstat(fd.fd(), &raw mut stat) }));
            record.stat = Some(result);
            exact(result, 0, "raw namespace fstat")?;
            record.device = stat.st_dev;
            record.inode = stat.st_ino;
            bootstrap::physical(owner, until)?;
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            let result = outcome(|| i64::from(unsafe { libc::fstatfs(fd.fd(), &raw mut fs) }));
            record.filesystem = Some(result);
            record.magic = fs.f_type;
            exact(result, 0, "raw namespace fstatfs")?;
            if record.magic != 0x6e736673 || record.inode == 0 {
                return Err(OracleError::Invalid("raw namespace object differs"));
            }
            exact(fd.close(), 0, "raw namespace close")?;
            bootstrap::physical(owner, until)?;
            record.complete = true;
        }
        require_records(&self.records)?;
        self.complete = true;
        Ok(())
    }
}

pub(super) fn require_records(records: &[Record; 2]) -> Result<(), OracleError> {
    let success = Some(Outcome {
        result: 0,
        errno: 0,
    });
    for record in records {
        if !record.complete
            || record
                .opened
                .is_none_or(|r| r.errno != 0 || !(0..=i64::from(i32::MAX)).contains(&r.result))
            || record.stat != success
            || record.filesystem != success
            || record.closed != success
            || record.magic != 0x6e736673
            || record.inode == 0
        {
            return Err(OracleError::Invalid("raw namespace records incomplete"));
        }
    }
    if (records[0].device, records[0].inode) != (records[1].device, records[1].inode) {
        return Err(OracleError::Invalid(
            "raw tracee uses another PID namespace",
        ));
    }
    Ok(())
}
