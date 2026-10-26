//! Pure proc-record joins for the fixed kernel-exec oracle, not a product API.
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provider {
    pub mount_id: u64,
    pub device: (u64, u64),
    pub mount_record: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    FdInfo,
    MountInfo,
    MapDevice,
    MapInode,
    MapPath,
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

pub fn parse(fdinfo: &str, mountinfo: &str, inode: u64) -> Result<Provider, Refusal> {
    if fdinfo.len() > 4096 || !fdinfo.ends_with('\n') {
        return Err(Refusal::FdInfo);
    }
    let field = |name: &str| {
        let rows: Vec<_> = fdinfo
            .lines()
            .filter_map(|line| line.strip_prefix(name))
            .collect();
        if rows.len() != 1 {
            return None;
        }
        decimal(rows[0].trim())
    };
    let mount_id = field("mnt_id:")
        .filter(|value| *value != 0)
        .ok_or(Refusal::FdInfo)?;
    if field("ino:") != Some(inode) || inode == 0 {
        return Err(Refusal::FdInfo);
    }
    if mountinfo.len() > 1024 * 1024 || !mountinfo.ends_with('\n') {
        return Err(Refusal::MountInfo);
    }
    let mut selected = None;
    for line in mountinfo.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let id = fields
            .first()
            .and_then(|value| decimal(value))
            .ok_or(Refusal::MountInfo)?;
        if id != mount_id {
            continue;
        }
        if selected.is_some() || fields.len() < 10 {
            return Err(Refusal::MountInfo);
        }
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or(Refusal::MountInfo)?;
        if separator < 6
            || separator + 4 != fields.len()
            || decimal(fields[1]).filter(|parent| *parent != 0).is_none()
            || !fields[3].starts_with('/')
            || !fields[4].starts_with('/')
        {
            return Err(Refusal::MountInfo);
        }
        let (major, minor) = fields[2].split_once(':').ok_or(Refusal::MountInfo)?;
        let device = (
            decimal(major).ok_or(Refusal::MountInfo)?,
            decimal(minor).ok_or(Refusal::MountInfo)?,
        );
        selected = Some(Provider {
            mount_id,
            device,
            mount_record: format!("{line}\n"),
        });
    }
    selected.ok_or(Refusal::MountInfo)
}

pub fn map_owner(
    provider: &Provider,
    expected_path: &Path,
    expected_inode: u64,
    device: (u64, u64),
    inode: u64,
    actual_path: &Path,
) -> Result<(), Refusal> {
    if device != provider.device {
        return Err(Refusal::MapDevice);
    }
    if inode == 0 || inode != expected_inode {
        return Err(Refusal::MapInode);
    }
    if !expected_path.is_absolute() || actual_path.as_os_str() != expected_path.as_os_str() {
        return Err(Refusal::MapPath);
    }
    Ok(())
}
