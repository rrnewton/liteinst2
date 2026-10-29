//! Original executable identity. No allocation of an executable copy or remap.
use super::artifact::Selection;
use super::held::HeldArtifact;
use crate::oracle::native_ordinary::normal_caller::rust_invoke::{Error, Plan, Result};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;
const PAGE: u64 = 4096;
fn require(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Error::Source) }
}
fn number(s: &str, radix: u32) -> Result<u64> {
    require(
        !s.is_empty()
            && s.bytes().all(|b| {
                if radix == 10 {
                    b.is_ascii_digit()
                } else {
                    b.is_ascii_hexdigit()
                }
            }),
    )?;
    u64::from_str_radix(s, radix).map_err(|_| Error::Source)
}
fn text(path: &str, cap: usize) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Error::Io)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io)?;
    require(bytes.len() <= cap && bytes.last() == Some(&b'\n'))?;
    String::from_utf8(bytes).map_err(|_| Error::Source)
}
fn device(info: &str, table: &str) -> Result<(u32, u32)> {
    let ids: Vec<_> = info
        .lines()
        .filter_map(|line| line.strip_prefix("mnt_id:\t"))
        .collect();
    require(ids.len() == 1)?;
    let id = number(ids[0], 10)?;
    require(id != 0)?;
    let mut found = None;
    for line in table.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        require(f.len() >= 10 && f.iter().filter(|&&s| s == "-").count() == 1)?;
        let actual_id = number(f[0], 10)?;
        if actual_id != id {
            continue;
        }
        require(found.is_none())?;
        let (a, b) = f[2].split_once(':').ok_or(Error::Source)?;
        found = Some((
            u32::try_from(number(a, 10)?).map_err(|_| Error::Source)?,
            u32::try_from(number(b, 10)?).map_err(|_| Error::Source)?,
        ));
    }
    found.ok_or(Error::Source)
}
fn mount_device(file: &File) -> Result<(u32, u32)> {
    device(
        &text(&format!("/proc/self/fdinfo/{}", file.as_raw_fd()), 4096)?,
        &text("/proc/self/mountinfo", 1024 * 1024)?,
    )
}
fn mapping(maps: &str, address: u64, offset: u64, dev: (u32, u32), inode: u64) -> Result<()> {
    require(address != 0 && address % PAGE == 0 && offset % PAGE == 0 && inode != 0)?;
    let end = address.checked_add(PAGE).ok_or(Error::Source)?;
    let mut covered = address;
    let mut previous = 0;
    for line in maps.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        require(f.len() >= 5)?;
        let (a, b) = f[0].split_once('-').ok_or(Error::Source)?;
        let (low, high) = (number(a, 16)?, number(b, 16)?);
        require(low < high && low >= previous)?;
        previous = high;
        let (a, b) = f[3].split_once(':').ok_or(Error::Source)?;
        let actual_dev = (
            u32::try_from(number(a, 16)?).map_err(|_| Error::Source)?,
            u32::try_from(number(b, 16)?).map_err(|_| Error::Source)?,
        );
        let actual_inode = number(f[4], 10)?;
        let actual_offset = number(f[2], 16)?;
        if high <= address || end <= low {
            continue;
        }
        require(low <= covered && f[1] == "r-xp" && dev == actual_dev && inode == actual_inode)?;
        require(actual_offset.checked_add(covered - low) == offset.checked_add(covered - address))?;
        covered = high.min(end);
    }
    require(covered == end)
}
fn address_join(
    actual: u64,
    bias: u64,
    selected: Selection,
    candidate: (u64, u64),
    trusted: (u64, u64),
) -> Result<()> {
    require(
        actual != 0
            && candidate != trusted
            && candidate.1 != 0
            && trusted.1 != 0
            && bias.checked_add(selected.virtual_address) == Some(actual),
    )
}
fn page_join(entry: u64, code: &[u8], pages: &[(u64, u64, Vec<u8>)]) -> Result<()> {
    require((1..=256).contains(&code.len()) && (1..=2).contains(&pages.len()))?;
    let end = entry.checked_add(code.len() as u64).ok_or(Error::Source)?;
    let expected: Vec<_> = ((entry & !4095)..=((end - 1) & !4095))
        .step_by(4096)
        .collect();
    require(pages.len() == expected.len())?;
    for ((address, offset, bytes), expected) in pages.iter().zip(expected) {
        require(
            *address == expected
                && *address != 0
                && offset % PAGE == 0
                && bytes.len() == PAGE as usize,
        )?;
        let a = entry.max(*address);
        let b = end.min(address.checked_add(PAGE).ok_or(Error::Source)?);
        require(
            bytes[(a - address) as usize..(b - address) as usize]
                == code[(a - entry) as usize..(b - entry) as usize],
        )?;
    }
    Ok(())
}
pub(super) struct RunningCaller {
    original: HeldArtifact,
    trusted: HeldArtifact,
    executable: File,
    entry: u64,
    bias: u64,
    device: (u32, u32),
    pages: Vec<(u64, u64, Vec<u8>)>,
}
impl RunningCaller {
    /// # Safety
    /// Both files, original executable mappings and every alias remain immutable
    /// through all forks/reaps and final verify. `entry` is the actual csv::invoke
    /// function pointer, not a user-provided address or replacement mapping.
    pub(super) unsafe fn open(path: &Path, trusted: &Path, entry: u64) -> Result<Self> {
        let original = HeldArtifact::open(path)?;
        let trusted = HeldArtifact::open(trusted)?;
        require(
            original.bytes() == trusted.bytes()
                && original.selection() == trusted.selection()
                && original.plan() == trusted.plan(),
        )?;
        // This intentional proc symlink resolves the kernel's running executable;
        // the held FD is joined to the independent original inode and all bytes.
        let executable = File::open("/proc/self/exe").map_err(|_| Error::Io)?;
        original.verify_same_file(&executable)?;
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        require(unsafe { libc::dladdr(entry as usize as *const libc::c_void, &mut info) } != 0)?;
        let bias = entry
            .checked_sub(original.selection().virtual_address)
            .ok_or(Error::Source)?;
        require(info.dli_fbase as usize as u64 == original.mapped_base(bias)?)?;
        address_join(
            entry,
            bias,
            original.selection(),
            original.identity(),
            trusted.identity(),
        )?;
        let device = mount_device(original.file())?;
        let pages = original.pages(bias)?;
        page_join(entry, original.plan().bytes(), &pages)?;
        let owner = Self {
            original,
            trusted,
            executable,
            entry,
            bias,
            device,
            pages,
        };
        unsafe { owner.verify() }?;
        Ok(owner)
    }
    pub(super) fn entry(&self) -> u64 {
        self.entry
    }
    pub(super) fn plan(&self) -> &Plan {
        self.original.plan()
    }
    pub(super) fn pages(&self) -> Vec<(u64, Vec<u8>)> {
        self.pages.iter().map(|(a, _, b)| (*a, b.clone())).collect()
    }
    /// Same no-writer/mapping-lifetime contract as open; map proof precedes read.
    pub(super) unsafe fn verify(&self) -> Result<()> {
        self.original.verify()?;
        self.trusted.verify()?;
        self.original.verify_same_file(&self.executable)?;
        require(self.original.bytes() == self.trusted.bytes())?;
        address_join(
            self.entry,
            self.bias,
            self.original.selection(),
            self.original.identity(),
            self.trusted.identity(),
        )?;
        require(mount_device(self.original.file())? == self.device)?;
        require(self.original.pages(self.bias)? == self.pages)?;
        page_join(self.entry, self.plan().bytes(), &self.pages)?;
        let maps = text("/proc/self/maps", 1024 * 1024)?;
        for (address, offset, expected) in &self.pages {
            mapping(
                &maps,
                *address,
                *offset,
                self.device,
                self.original.identity().1,
            )?;
            let actual =
                unsafe { std::slice::from_raw_parts(*address as usize as *const u8, 4096) };
            require(actual == expected)?;
        }
        self.original.verify()?;
        self.trusted.verify()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn running_caller_requires_distinct_files_actual_entry_and_load_bias() {
        let s = Selection {
            virtual_address: 0x1230,
            file_offset: 0x1230,
            section: 2,
            extent: 20,
        };
        assert!(address_join(0x401230, 0x400000, s, (1, 2), (1, 3)).is_ok());
        for (entry, bias, a, b) in [
            (0x401231, 0x400000, (1, 2), (1, 3)),
            (0x401230, 0x400001, (1, 2), (1, 3)),
            (0x401230, 0x400000, (1, 2), (1, 2)),
            (0x401230, u64::MAX, (1, 2), (1, 3)),
        ] {
            assert!(address_join(entry, bias, s, a, b).is_err());
        }
    }
    #[test]
    fn running_caller_rejects_mapping_device_inode_offset_and_bytes() {
        let row = "400000-402000 r-xp 00001000 00:07 9 source\n";
        assert!(mapping(row, 0x401000, 0x2000, (0, 7), 9).is_ok());
        for bad in [
            row.replace("r-xp", "r-xs"),
            row.replace("00:07", "00:08"),
            row.replace(" 9 ", " 8 "),
            row.replace("00001000", "00002000"),
            format!("{row}{row}"),
        ] {
            assert!(mapping(&bad, 0x401000, 0x2000, (0, 7), 9).is_err());
        }
        assert_eq!(
            device("mnt_id:\t5\n", "5 1 0:7 / / rw - ext4 x rw\n").unwrap(),
            (0, 7)
        );
        assert!(device("mnt_id:\t5\nmnt_id:\t5\n", "5 1 0:7 / / rw - ext4 x rw\n").is_err());
        assert!(
            device(
                "mnt_id:\t5\n",
                "5 1 0:7 / / rw - ext4 x rw\n5 1 0:7 / / rw - ext4 x rw\n"
            )
            .is_err()
        );
        let mut pages = vec![(0x400000, 0, vec![0x90; 4096])];
        assert!(page_join(0x400100, &[0x90; 20], &pages).is_ok());
        pages[0].2[0x100] ^= 1;
        assert!(page_join(0x400100, &[0x90; 20], &pages).is_err());
    }
    #[test]
    fn running_caller_page_union_refuses_gaps_overlap_and_overflow() {
        let pages = vec![
            (0x400000, 0, vec![0x90; 4096]),
            (0x401000, 4096, vec![0x90; 4096]),
        ];
        assert!(page_join(0x400ff8, &[0x90; 20], &pages).is_ok());
        assert!(page_join(0x400ff8, &[0x90; 20], &pages[..1]).is_err());
        let mut gap = pages.clone();
        gap[1].0 += 4096;
        assert!(page_join(0x400ff8, &[0x90; 20], &gap).is_err());
        let mut overlap = pages.clone();
        overlap[1].0 = overlap[0].0;
        assert!(page_join(0x400ff8, &[0x90; 20], &overlap).is_err());
        assert!(page_join(u64::MAX - 8, &[0x90; 20], &pages).is_err());
    }
}
