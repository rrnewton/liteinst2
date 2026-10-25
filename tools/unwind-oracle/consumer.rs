//! Actual linked consumer identity, independently bound to a frozen file copy.
use std::ffi::{CStr, CString};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

const NAMES: [&str; 6] = [
    "__register_frame",
    "_Unwind_Find_FDE",
    "_Unwind_Backtrace",
    "_Unwind_GetIPInfo",
    "_Unwind_GetCFA",
    "_Unwind_GetGR",
];
unsafe extern "C" {
    fn uw_consumer_addresses(output: *mut usize);
}
fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}

// Qualification opens and retains its own read-only descriptors after loader
// setup. These are not claimed to be the loader's original mmap descriptors.
// The fd's mount ID joins the stat inode/path/bytes to the VMA device domain.
struct Backing {
    role: &'static str,
    file: std::fs::File,
    path: PathBuf,
    bytes: Vec<u8>,
    identity: (u64, u64, u64),
}
impl Backing {
    fn open(role: &'static str, path: PathBuf, bytes: Vec<u8>) -> Self {
        assert!(path.is_absolute());
        assert_eq!(std::fs::canonicalize(&path).unwrap(), path);
        assert!(
            !path
                .as_os_str()
                .as_encoded_bytes()
                .iter()
                .any(u8::is_ascii_whitespace)
        );
        let file = std::fs::File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), bytes.len() as u64);
        Self {
            role,
            file,
            path,
            bytes,
            identity: (metadata.dev(), metadata.ino(), metadata.len()),
        }
    }
    fn revalidate(&self) -> (u64, u64, u64) {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;
        let before = self.file.metadata().unwrap();
        let pathname = std::fs::metadata(&self.path).unwrap();
        assert!(before.is_file() && pathname.is_file());
        assert_eq!((before.dev(), before.ino(), before.len()), self.identity);
        assert_eq!(
            (pathname.dev(), pathname.ino(), pathname.len()),
            self.identity
        );
        let mut actual = vec![0; self.bytes.len()];
        self.file.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, self.bytes, "complete retained descriptor bytes");
        assert_eq!(std::fs::read(&self.path).unwrap(), self.bytes);
        let fd = self.file.as_raw_fd();
        let fd_path = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        assert_eq!(fd_path, self.path);
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap();
        assert!(fdinfo.len() < 16 * 1024);
        let mut entries = std::collections::BTreeMap::new();
        for line in fdinfo.lines() {
            let (key, value) = line.split_once(':').expect("fdinfo field");
            assert!(
                entries.insert(key, value.trim()).is_none(),
                "duplicate fdinfo key"
            );
        }
        assert_eq!(entries["ino"].parse::<u64>().unwrap(), before.ino());
        assert_eq!(entries["pos"].parse::<u64>().unwrap(), 0);
        let flags = u64::from_str_radix(entries["flags"], 8).unwrap();
        assert_eq!(flags & u64::try_from(libc::O_ACCMODE).unwrap(), 0);
        let mount_id = entries["mnt_id"].parse::<u64>().unwrap();
        assert!(mount_id > 0);
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        assert!(mountinfo.len() < 2 * 1024 * 1024);
        let owners: Vec<_> = mountinfo
            .lines()
            .filter(|line| {
                line.split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    == Some(mount_id)
            })
            .collect();
        assert_eq!(owners.len(), 1, "unique descriptor mount");
        let mount = owners[0];
        let fields: Vec<_> = mount.split_whitespace().collect();
        let separators: Vec<_> = fields
            .iter()
            .enumerate()
            .filter_map(|(i, f)| (*f == "-").then_some(i))
            .collect();
        assert_eq!(separators.len(), 1);
        let separator = separators[0];
        assert!(separator >= 6);
        assert_eq!(fields.len(), separator + 4);
        assert_eq!(fields[0].parse::<u64>().unwrap(), mount_id);
        assert!(fields[1].parse::<u64>().unwrap() > 0);
        for field in &fields[3..5] {
            assert!(field.starts_with('/') && !field.contains('\\'));
        }
        assert!(
            self.path.starts_with(fields[4]),
            "descriptor path inside its mount"
        );
        let (major, minor) = fields[2].split_once(':').unwrap();
        let device = (major.parse::<u64>().unwrap(), minor.parse::<u64>().unwrap());
        let after = self.file.metadata().unwrap();
        assert_eq!((after.dev(), after.ino(), after.len()), self.identity);
        assert_eq!(std::fs::canonicalize(&self.path).unwrap(), self.path);
        fn hex(bytes: &[u8]) -> String {
            const DIGITS: &[u8] = b"0123456789abcdef";
            let mut out = String::with_capacity(bytes.len() * 2);
            for &byte in bytes {
                out.push(DIGITS[usize::from(byte >> 4)] as char);
                out.push(DIGITS[usize::from(byte & 15)] as char);
            }
            out
        }
        eprintln!(
            "consumer_backing role={} fd={} stat_dev={} inode={} bytes={} mount_major={} mount_minor={} mount_id={} path={} fdinfo_hex={} mountinfo_hex={} fd_path_hex={} whole_file_bytes_exact=true",
            self.role,
            fd,
            before.dev(),
            before.ino(),
            before.len(),
            device.0,
            device.1,
            mount_id,
            self.path.display(),
            hex(fdinfo.as_bytes()),
            hex(mount.as_bytes()),
            hex(fd_path.as_os_str().as_encoded_bytes())
        );
        (device.0, device.1, before.ino())
    }
}
fn executable_backings() -> [Backing; 2] {
    let path = std::fs::canonicalize(std::fs::read_link("/proc/self/exe").unwrap()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!((64..128 * 1024 * 1024).contains(&bytes.len()));
    assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
    assert_eq!(u16_at(&bytes, 18), 62);
    assert_eq!(u16_at(&bytes, 54), 56);
    let phoff = usize::try_from(u64_at(&bytes, 32)).unwrap();
    let count = usize::from(u16_at(&bytes, 56));
    assert!((1..=256).contains(&count));
    assert!(phoff.checked_add(count * 56).unwrap() <= bytes.len());
    let mut interpreters = Vec::new();
    for n in 0..count {
        let p = phoff + n * 56;
        if u32_at(&bytes, p) == 3 {
            let first = usize::try_from(u64_at(&bytes, p + 8)).unwrap();
            let size = usize::try_from(u64_at(&bytes, p + 32)).unwrap();
            assert!((2..=4096).contains(&size));
            let value = &bytes[first..first.checked_add(size).unwrap()];
            assert_eq!(value.last(), Some(&0));
            assert!(!value[..size - 1].contains(&0));
            let name = std::str::from_utf8(&value[..size - 1]).unwrap();
            assert!(name.starts_with('/'));
            interpreters.push(std::fs::canonicalize(name).unwrap());
        }
    }
    assert_eq!(interpreters.len(), 1);
    let interpreter = interpreters.remove(0);
    let interpreter_bytes = std::fs::read(&interpreter).unwrap();
    assert!((64..32 * 1024 * 1024).contains(&interpreter_bytes.len()));
    [
        Backing::open("main", path, bytes),
        Backing::open("interpreter", interpreter, interpreter_bytes),
    ]
}

// The handle is deliberately never closed. The core retains this owner and
// registration for the process lifetime, including retirement and failure.
pub struct Consumer {
    path: PathBuf,
    bytes: Vec<u8>,
    base: u64,
    addresses: [usize; 6],
    handle: usize,
    backing: Backing,
    executable_backings: [Backing; 2],
}
impl Consumer {
    pub fn qualify() -> Self {
        for key in ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"] {
            assert!(
                std::env::var_os(key).is_none(),
                "unadmitted loader override {key}"
            );
        }
        match std::fs::read("/etc/ld.so.preload") {
            Ok(bytes) => assert!(
                bytes.iter().all(u8::is_ascii_whitespace),
                "global preload is active"
            ),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
        }
        let path = std::fs::canonicalize(
            std::env::var_os("UW_LIBGCC_FILE").expect("root-bound actual consumer path"),
        )
        .unwrap();
        let snapshot = PathBuf::from(
            std::env::var_os("UW_LIBGCC_SNAPSHOT").expect("root-frozen consumer copy"),
        );
        assert!(snapshot.is_absolute());
        assert_ne!(snapshot, path);
        let bytes = std::fs::read(&snapshot).unwrap();
        assert!(bytes.len() >= 64 && bytes.len() < 32 * 1024 * 1024);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "full current consumer bytes equal root-frozen copy"
        );
        assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
        assert_eq!(u16_at(&bytes, 16), 3);
        assert_eq!(u16_at(&bytes, 18), 62);
        let mut addresses = [0; 6];
        unsafe {
            uw_consumer_addresses(addresses.as_mut_ptr());
        }
        let mut base = None;
        for (&address, name) in addresses.iter().zip(NAMES) {
            assert_ne!(address, 0);
            let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
            assert_ne!(unsafe { libc::dladdr(address as *const _, &mut info) }, 0);
            assert!(
                !info.dli_fname.is_null() && !info.dli_fbase.is_null() && !info.dli_sname.is_null()
            );
            let actual = unsafe { CStr::from_ptr(info.dli_fname) }.to_str().unwrap();
            assert_eq!(std::fs::canonicalize(actual).unwrap(), path);
            assert_eq!(
                unsafe { CStr::from_ptr(info.dli_sname) }.to_str().unwrap(),
                name
            );
            assert_eq!(
                info.dli_saddr as usize, address,
                "actual exported symbol start"
            );
            let found = info.dli_fbase as usize as u64;
            if let Some(base) = base {
                assert_eq!(found, base);
            } else {
                base = Some(found);
            }
        }
        let cpath = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let handle = unsafe {
            libc::dlopen(
                cpath.as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_NOLOAD | libc::RTLD_NODELETE,
            )
        };
        assert!(
            !handle.is_null(),
            "the actual consumer must already be loaded"
        );
        let backing = Backing::open("libgcc", path.clone(), bytes.clone());
        let executable_backings = executable_backings();
        let result = Self {
            path,
            bytes,
            base: base.unwrap(),
            addresses,
            handle: handle as usize,
            backing,
            executable_backings,
        };
        result.revalidate();
        result
    }
    pub fn revalidate(&self) {
        assert_ne!(self.handle, 0);
        for backing in &self.executable_backings {
            backing.revalidate();
        }
        let mapped_identity = self.backing.revalidate();
        assert_eq!(std::fs::read(&self.path).unwrap(), self.bytes);
        let metadata = std::fs::metadata(&self.path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(mapped_identity.2, metadata.ino());
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        assert!(maps.len() < 2 * 1024 * 1024);
        let phoff = usize::try_from(u64_at(&self.bytes, 32)).unwrap();
        let count = usize::from(u16_at(&self.bytes, 56));
        assert_eq!(u16_at(&self.bytes, 54), 56);
        assert!((1..=256).contains(&count));
        assert!(phoff.checked_add(count * 56).unwrap() <= self.bytes.len());
        let mut owners = [0; 6];
        let mut executable = 0;
        for n in 0..count {
            let p = phoff + n * 56;
            if u32_at(&self.bytes, p) != 1 || u32_at(&self.bytes, p + 4) & 1 == 0 {
                continue;
            }
            assert_eq!(
                u32_at(&self.bytes, p + 4),
                5,
                "consumer code requires R|X and no W"
            );
            let file = u64_at(&self.bytes, p + 8);
            let va = u64_at(&self.bytes, p + 16);
            let size = u64_at(&self.bytes, p + 32);
            assert!(size > 0);
            let start = self.base.checked_add(va).unwrap();
            let end = start.checked_add(size).unwrap();
            let first = usize::try_from(file).unwrap();
            let last = usize::try_from(file.checked_add(size).unwrap()).unwrap();
            assert!(last <= self.bytes.len());
            assert_eq!(
                unsafe { std::slice::from_raw_parts(start as usize as *const u8, last - first) },
                &self.bytes[first..last]
            );
            let matching: Vec<_> = maps
                .lines()
                .filter(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    assert!(fields.len() >= 5);
                    let (left, right) = fields[0].split_once('-').unwrap();
                    let lo = u64::from_str_radix(left, 16).unwrap();
                    let hi = u64::from_str_radix(right, 16).unwrap();
                    lo <= start && end <= hi
                })
                .collect();
            assert_eq!(matching.len(), 1);
            let fields: Vec<_> = matching[0].split_whitespace().collect();
            assert_eq!(fields.len(), 6);
            assert_eq!(fields[1], "r-xp");
            let lo = u64::from_str_radix(fields[0].split_once('-').unwrap().0, 16).unwrap();
            assert_eq!(
                u64::from_str_radix(fields[2], 16).unwrap() + start - lo,
                file
            );
            assert_eq!(fields[4].parse::<u64>().unwrap(), metadata.ino());
            let (major, minor) = fields[3].split_once(':').unwrap();
            assert_eq!(u64::from_str_radix(major, 16).unwrap(), mapped_identity.0);
            assert_eq!(u64::from_str_radix(minor, 16).unwrap(), mapped_identity.1);
            assert_eq!(std::fs::canonicalize(fields[5]).unwrap(), self.path);
            for (i, &address) in self.addresses.iter().enumerate() {
                if start <= address as u64 && (address as u64) < end {
                    owners[i] += 1;
                }
            }
            executable += 1;
        }
        assert!(executable > 0);
        assert_eq!(owners, [1; 6]);
        eprintln!(
            "consumer_identity path={} base={:#x} bytes={} exported_symbols=6 executable_segments={} file_mapping_bytes_exact=true",
            self.path.display(),
            self.base,
            self.bytes.len(),
            executable
        );
    }
}
