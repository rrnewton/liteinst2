//! One closed request schema; immutable transport is not an admission authority.
use super::*;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileExt;

pub const MAGIC: &[u8] = b"LI2-OBSERVER-REQUEST\0\x01";
pub const MAGIC_V2: &[u8] = b"LI2-OBSERVER-REQUEST\0\x02";
pub const WIRE_CAP: usize = 260 * 1024 * 1024;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
fn sealed(fd: i32) -> bool {
    let value = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    value >= 0 && value & SEALS == SEALS
}

struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
    pages: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(length).ok_or(Error::Shape)?;
        let value = self.raw.get(self.at..end).ok_or(Error::Shape)?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Shape)?,
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Shape)?,
        ))
    }
    fn time(&mut self) -> Result<i128> {
        let value = i128::from_le_bytes(self.take(16)?.try_into().map_err(|_| Error::Shape)?);
        if value < 0 {
            return Err(Error::Shape);
        }
        Ok(value)
    }
    fn flag(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Shape),
        }
    }
    fn length(&mut self, cap: usize) -> Result<usize> {
        let value = self.u32()? as usize;
        if value > cap {
            return Err(Error::Shape);
        }
        Ok(value)
    }

    fn kernel_basis(&mut self) -> Result<KernelBasis> {
        if self.take(1)?[0] != 1 {
            return Err(Error::Shape);
        }
        let basis_sha256 = self.take(32)?.try_into().map_err(|_| Error::Shape)?;
        let length = self.length(128)?;
        let release = std::str::from_utf8(self.take(length)?)
            .map_err(|_| Error::Shape)?
            .to_owned();
        let basis = KernelBasis {
            profile: KERNEL_BASIS_PROFILE.to_owned(),
            basis_sha256,
            release,
            config_gzip_bytes: self.u32()?,
            config_gzip_sha256: self.take(32)?.try_into().map_err(|_| Error::Shape)?,
            config_decoded_bytes: self.u32()?,
            config_decoded_sha256: self.take(32)?.try_into().map_err(|_| Error::Shape)?,
        };
        basis.validate()?;
        Ok(basis)
    }

    fn pin(&mut self) -> Result<FilePin> {
        let length = self.length(4095)?;
        let raw = self.take(length)?;
        let path = std::str::from_utf8(raw).map_err(|_| Error::Shape)?;
        if !path.starts_with('/')
            || !raw.iter().all(|b| (33..=126).contains(b))
            || path[1..].split('/').any(|p| matches!(p, "" | "." | ".."))
        {
            return Err(Error::Shape);
        }
        let sha256 = self.take(32)?.try_into().map_err(|_| Error::Shape)?;
        let device = self.u64()?;
        let inode = self.u64()?;
        let mode = self.u32()?;
        let bytes = self.u64()?;
        let mtime_ns = self.time()?;
        let ctime_ns = self.time()?;
        if bytes > FILE_CAP || mode & libc::S_IFMT != libc::S_IFREG {
            return Err(Error::Shape);
        }
        Ok(FilePin {
            path: PathBuf::from(path),
            sha256,
            device,
            inode,
            mode,
            bytes,
            mtime_ns,
            ctime_ns,
        })
    }
    fn permissions(&mut self) -> Result<[u8; 4]> {
        let p: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::Shape)?;
        if !matches!(p[0], b'r' | b'-')
            || !matches!(p[1], b'w' | b'-')
            || !matches!(p[2], b'x' | b'-')
            || p[3] != b'p'
            || p[1..3] == *b"wx"
        {
            return Err(Error::Shape);
        }
        Ok(p)
    }
    fn object(&mut self) -> Result<Object> {
        let file = self.pin()?;
        let length = self.length(65536)?;
        self.pages = self.pages.checked_add(length).ok_or(Error::Shape)?;
        if length == 0 || self.pages > 65536 {
            return Err(Error::Shape);
        }
        let mut pages: Vec<Page> = Vec::with_capacity(length);
        for _ in 0..length {
            let relative = self.u64()?;
            let file_offset = self.u64()?;
            let permissions_at_exec = self.permissions()?;
            let permissions_at_entry = self.permissions()?;
            let file_backed = self.flag()?;
            let bytes = if self.flag()? {
                Some(self.take(4096)?.to_vec())
            } else {
                None
            };
            if relative % 4096 != 0
                || relative >= (1 << 47) - 4096
                || file_offset % 4096 != 0
                || file_offset > FILE_CAP
                || pages.last().is_some_and(|p| p.relative >= relative)
            {
                return Err(Error::Shape);
            }
            pages.push(Page {
                relative,
                file_offset,
                permissions_at_exec,
                permissions_at_entry,
                file_backed,
                bytes,
            });
        }
        Ok(Object { file, pages })
    }
}

pub fn decode(raw: &[u8]) -> Result<Request> {
    if raw.len() > WIRE_CAP || !(raw.starts_with(MAGIC) || raw.starts_with(MAGIC_V2)) {
        return Err(Error::Shape);
    }
    let version2 = raw.starts_with(MAGIC_V2);
    let mut r = Reader {
        raw,
        at: MAGIC.len(),
        pages: 0,
    };
    let main = r.object()?;
    let loader = r.object()?;
    let bootstrap = r.object()?;
    let count = r.length(16)?;
    let mut dependencies = Vec::with_capacity(count);
    for _ in 0..count {
        dependencies.push(r.object()?);
    }
    let dataset = r.pin()?;
    let entry = r.u64()?;
    let length = r.length(15)?;
    let entry_bytes = r.take(length)?.to_vec();
    let completion_relative = r.u64()?;
    let completion_file_offset = if r.flag()? { Some(r.u64()?) } else { None };
    let xstate_bytes = r.length(XSTATE_CAP)?;
    let kernel_basis = if version2 {
        Some(r.kernel_basis()?)
    } else {
        None
    };
    if r.at != raw.len()
        || dataset.bytes > 65536
        || entry >= 1 << 47
        || length == 0
        || completion_relative % 8 != 0
        || completion_relative >= (1 << 47) - 8
        || completion_file_offset.is_some_and(|n| n > FILE_CAP - 8)
        || xstate_bytes < 576
    {
        return Err(Error::Shape);
    }
    Ok(Request {
        main,
        loader,
        bootstrap,
        dependencies,
        dataset,
        entry,
        entry_bytes,
        completion_relative,
        completion_file_offset,
        xstate_bytes,
        kernel_basis,
    })
}

pub fn digest(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Shape);
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&text[2 * index..2 * index + 2], 16).map_err(|_| Error::Shape)?;
    }
    Ok(result)
}

/// Takes exclusive ownership of the inherited request descriptor.
///
/// # Safety
/// `fd` must be a valid, exclusively transferred descriptor in this dedicated
/// single-threaded checked-launcher child. These checks establish transport
/// immutability only. They do not authenticate the caller or admit its package.
pub unsafe fn read_owned_fd(fd: i32, expected: [u8; 32]) -> Result<Request> {
    if !(3..=1024).contains(&fd) {
        return Err(Error::Shape);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata().map_err(io_error)?;
    let name = std::fs::read_link(format!("/proc/self/fd/{fd}")).map_err(io_error)?;
    if name != std::path::Path::new("/memfd:li2-observer-request-v1 (deleted)")
        || !before.is_file()
        || before.nlink() != 0
        || before.uid() != unsafe { libc::geteuid() }
        || before.len() > WIRE_CAP as u64
        || before.len() <= MAGIC.len() as u64
        || !sealed(fd)
    {
        return Err(Error::Custody);
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(Error::Io(errno()));
    }
    let mut bytes = vec![0; before.len() as usize];
    file.read_exact_at(&mut bytes, 0).map_err(io_error)?;
    let mut extra = [0];
    let after = file.metadata().map_err(io_error)?;
    if file.read_at(&mut extra, before.len()).map_err(io_error)? != 0
        || (before.dev(), before.ino(), before.len(), before.mode())
            != (after.dev(), after.ino(), after.len(), after.mode())
        || !sealed(fd)
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != expected
    {
        return Err(Error::Custody);
    }
    decode(&bytes)
}

pub fn hex(raw: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(raw.len() * 2);
    for byte in raw {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 15) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::IntoRawFd;

    fn pin(out: &mut Vec<u8>, name: &str) {
        out.extend((name.len() as u32).to_le_bytes());
        out.extend(name.as_bytes());
        out.extend([7; 32]);
        out.extend(1_u64.to_le_bytes());
        out.extend(2_u64.to_le_bytes());
        out.extend(0o100700_u32.to_le_bytes());
        out.extend(4096_u64.to_le_bytes());
        out.extend(3_i128.to_le_bytes());
        out.extend(4_i128.to_le_bytes());
    }
    fn fixture() -> (Vec<u8>, usize) {
        let mut out = MAGIC.to_vec();
        let mut flag = 0;
        for name in ["/main", "/loader", "/bootstrap"] {
            pin(&mut out, name);
            out.extend(1_u32.to_le_bytes());
            out.extend(0_u64.to_le_bytes());
            out.extend(0_u64.to_le_bytes());
            out.extend(b"rw-prw-p");
            if flag == 0 {
                flag = out.len();
            }
            out.extend([1, 0]);
        }
        out.extend(0_u32.to_le_bytes());
        pin(&mut out, "/dataset");
        out.extend(0x401000_u64.to_le_bytes());
        out.extend(1_u32.to_le_bytes());
        out.push(0xc3);
        out.extend(0x1000_u64.to_le_bytes());
        out.push(0);
        out.extend(576_u32.to_le_bytes());
        (out, flag)
    }
    fn fd(raw: &[u8], seals: i32, name: &str) -> i32 {
        let name = CString::new(name).unwrap();
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC)
        };
        assert!(fd >= 0);
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(raw).unwrap();
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
        file.into_raw_fd()
    }
    #[test]
    fn exact_closed_wire_decodes_all_request_facts() {
        let (raw, _) = fixture();
        let r = decode(&raw).unwrap();
        assert_eq!(r.main.file.path, PathBuf::from("/main"));
        assert_eq!(r.bootstrap.pages.len(), 1);
        assert_eq!(
            (r.entry, r.completion_relative, r.xstate_bytes),
            (0x401000, 0x1000, 576)
        );
        assert_eq!(r.entry_bytes, [0xc3]);
        assert_eq!(r.dataset.bytes, 4096);
        assert!(r.dependencies.is_empty());
    }
    #[test]
    fn every_truncation_and_trailing_byte_refuses() {
        let (raw, _) = fixture();
        for n in 0..raw.len() {
            assert_eq!(decode(&raw[..n]), Err(Error::Shape));
        }
        let mut extra = raw;
        extra.push(0);
        assert_eq!(decode(&extra), Err(Error::Shape));
    }
    #[test]
    fn wrong_version_nonboolean_flag_and_writable_executable_page_refuse() {
        let (raw, flag) = fixture();
        for (at, value) in [(MAGIC.len() - 1, 2), (flag, 2), (flag - 2, b'x')] {
            let mut bad = raw.clone();
            bad[at] = value;
            assert_eq!(decode(&bad), Err(Error::Shape));
        }
    }
    #[test]
    fn canonical_digest_is_exact_lowercase_32_bytes() {
        assert_eq!(digest(&"01".repeat(32)), Ok([1; 32]));
        for bad in [
            "a".repeat(63),
            "a".repeat(65),
            "AA".repeat(32),
            "gg".repeat(32),
        ] {
            assert_eq!(digest(&bad), Err(Error::Shape));
        }
    }
    #[test]
    fn sealed_fd_exact_digest_accepts_and_owns_descriptor() {
        let (raw, _) = fixture();
        let owned = fd(&raw, SEALS, "li2-observer-request-v1");
        let mut before = unsafe { core::mem::zeroed::<libc::stat>() };
        assert_eq!(unsafe { libc::fstat(owned, &mut before) }, 0);
        let r = unsafe { read_owned_fd(owned, Sha256::digest(&raw).into()) }.unwrap();
        assert_eq!(r.entry, 0x401000);
        let mut after = unsafe { core::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(owned, &mut after) } == 0 {
            // Parallel controls may reuse the descriptor number. Its old owned
            // inode must be gone, rather than requiring the number stay empty.
            assert_ne!((before.st_dev, before.st_ino), (after.st_dev, after.st_ino));
        }
    }
    #[test]
    fn each_missing_seal_wrong_digest_and_wrong_memfd_name_refuse() {
        let (raw, _) = fixture();
        let hash = Sha256::digest(&raw).into();
        for missing in [
            libc::F_SEAL_SEAL,
            libc::F_SEAL_SHRINK,
            libc::F_SEAL_GROW,
            libc::F_SEAL_WRITE,
        ] {
            let owned = fd(&raw, SEALS & !missing, "li2-observer-request-v1");
            assert_eq!(unsafe { read_owned_fd(owned, hash) }, Err(Error::Custody));
        }
        let owned = fd(&raw, SEALS, "li2-observer-request-v1");
        assert_eq!(
            unsafe { read_owned_fd(owned, [0; 32]) },
            Err(Error::Custody)
        );
        let owned = fd(&raw, SEALS, "other");
        assert_eq!(unsafe { read_owned_fd(owned, hash) }, Err(Error::Custody));
    }
    #[test]
    fn safe_admission_does_not_accept_a_transport_digest() {
        let (raw, _) = fixture();
        let r = decode(&raw).unwrap();
        assert!(matches!(
            admit(&raw, Sha256::digest(&raw).into(), &r),
            Err(Error::AdmissionUnavailable)
        ));
        let admitted = unsafe { admit_from_checked_launcher(&r) }.unwrap();
        let mut changed = r;
        changed.entry += 1;
        assert!(matches!(
            observe(&changed, &admitted),
            Err(Error::AdmissionUnavailable)
        ));
    }
    #[test]
    fn actual_auxv_requires_exactly_one_secure_zero() {
        let encode = |rows: &[(u64, u64)]| {
            rows.iter()
                .flat_map(|(a, b)| a.to_ne_bytes().into_iter().chain(b.to_ne_bytes()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            secure_auxv(&encode(&[(9, 1), (7, 2), (23, 0), (0, 0)])),
            Ok((1, 2))
        );
        for rows in [
            vec![(9, 1), (7, 2), (0, 0)],
            vec![(9, 1), (7, 2), (23, 1), (0, 0)],
            vec![(9, 1), (7, 2), (23, 0), (23, 0), (0, 0)],
        ] {
            assert_eq!(secure_auxv(&encode(&rows)), Err(Error::Entry));
        }
    }
    #[test]
    fn actual_kernel_shstk_status_requires_both_empty_unique_fields() {
        assert_eq!(
            disabled_shstk(b"Name:\tmain\nx86_Thread_features:\t\nx86_Thread_features_locked:\t\n"),
            Ok(())
        );
        for raw in [
            b"Name:\tmain\n".as_slice(),
            b"x86_Thread_features:\tshstk\nx86_Thread_features_locked:\t\n",
            b"x86_Thread_features:\t\nx86_Thread_features_locked:\twrss\n",
            b"x86_Thread_features:\t\nx86_Thread_features:\t\nx86_Thread_features_locked:\t\n",
        ] {
            assert_eq!(disabled_shstk(raw), Err(Error::Entry));
        }
    }
    #[test]
    fn actual_signal_mask_and_ignored_bits_must_be_zero_including_reserved_signals() {
        assert_eq!(
            controlled_signal_status(b"SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\n"),
            Ok(())
        );
        for raw in [
            b"SigBlk:\t0000000000000008\nSigIgn:\t0000000000000000\n".as_slice(),
            b"SigBlk:\t0000000000000000\nSigIgn:\t0000000100000000\n",
            b"SigBlk:\t0000000000000000\n",
            b"SigBlk:\t0\nSigIgn:\t0\n",
        ] {
            assert_eq!(controlled_signal_status(raw), Err(Error::Entry));
        }
    }

    fn fixture_v2() -> (Vec<u8>, usize) {
        let (mut raw, _) = fixture();
        raw[MAGIC.len() - 1] = 2;
        let capsule = raw.len();
        raw.push(1);
        raw.extend([11; 32]);
        raw.extend(7_u32.to_le_bytes());
        raw.extend(b"release");
        raw.extend(43059_u32.to_le_bytes());
        raw.extend([12; 32]);
        raw.extend(193926_u32.to_le_bytes());
        raw.extend([13; 32]);
        (raw, capsule)
    }
    #[test]
    fn v2_decodes_the_whole_explicit_kernel_basis_without_changing_v1() {
        let (old, _) = fixture();
        assert_eq!(decode(&old).unwrap().kernel_basis, None);
        let (raw, _) = fixture_v2();
        let request = decode(&raw).unwrap();
        assert_eq!(
            request.kernel_basis,
            Some(KernelBasis {
                profile: KERNEL_BASIS_PROFILE.to_owned(),
                basis_sha256: [11; 32],
                release: "release".to_owned(),
                config_gzip_bytes: 43059,
                config_gzip_sha256: [12; 32],
                config_decoded_bytes: 193926,
                config_decoded_sha256: [13; 32],
            })
        );
        let mut without_basis = request;
        without_basis.kernel_basis = None;
        assert_eq!(without_basis, decode(&old).unwrap());
    }
    #[test]
    fn v2_every_truncation_trailing_byte_unknown_mode_and_cross_version_refuses() {
        let (raw, at) = fixture_v2();
        for n in 0..raw.len() {
            assert_eq!(decode(&raw[..n]), Err(Error::Shape));
        }
        for mode in [0, 2, 255] {
            let mut bad = raw.clone();
            bad[at] = mode;
            assert_eq!(decode(&bad), Err(Error::Shape));
        }
        for version in [0, 3, 255] {
            let mut bad = raw.clone();
            bad[MAGIC.len() - 1] = version;
            assert_eq!(decode(&bad), Err(Error::Shape));
        }
        let mut old_with_capsule = raw.clone();
        old_with_capsule[MAGIC.len() - 1] = 1;
        assert_eq!(decode(&old_with_capsule), Err(Error::Shape));
        let mut extra = raw;
        extra.push(0);
        assert_eq!(decode(&extra), Err(Error::Shape));
    }
    #[test]
    fn v2_release_and_both_config_length_bounds_are_exact() {
        let (raw, at) = fixture_v2();
        for value in [0_u32, 129] {
            let mut bad = raw.clone();
            bad[at + 33..at + 37].copy_from_slice(&value.to_le_bytes());
            assert_eq!(decode(&bad), Err(Error::Shape));
        }
        for (offset, limit) in [(at + 44, 65536_u32), (at + 80, 524288)] {
            for value in [0, limit + 1] {
                let mut bad = raw.clone();
                bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                assert_eq!(decode(&bad), Err(Error::Shape));
            }
        }
        for byte in [0, b'\n', b' ', 0xff] {
            let mut bad = raw.clone();
            bad[at + 37] = byte;
            assert_eq!(decode(&bad), Err(Error::Shape));
        }
    }
    #[test]
    fn v2_admission_binds_every_kernel_basis_member() {
        let (raw, _) = fixture_v2();
        let original = decode(&raw).unwrap();
        let admitted = unsafe { admit_from_checked_launcher(&original) }.unwrap();
        for field in 0..8 {
            let mut changed = original.clone();
            let basis = changed.kernel_basis.as_mut().unwrap();
            match field {
                0 => basis.profile.push_str("-changed"),
                1 => basis.basis_sha256[0] ^= 1,
                2 => basis.release.push('x'),
                3 => basis.config_gzip_bytes += 1,
                4 => basis.config_gzip_sha256[0] ^= 1,
                5 => basis.config_decoded_bytes += 1,
                6 => basis.config_decoded_sha256[0] ^= 1,
                7 => changed.kernel_basis = None,
                _ => unreachable!(),
            }
            assert!(matches!(
                observe(&changed, &admitted),
                Err(Error::AdmissionUnavailable)
            ));
        }
    }
}
