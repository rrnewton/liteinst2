//! Private held-file half reused from the unchanged copied-artifact parser.
use super::artifact::{
    Selection, Stamp, end, extract, overlaps, require, slice, stamp, u16_at, u32_at, u64_at,
    verify_file,
};
use crate::oracle::native_ordinary::normal_caller::rust_invoke::{Error, Plan, Result};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
/// Held original final ELF only. This type never allocates or exposes a copied
/// executable mapping. Running-address authority is established separately.
pub struct HeldArtifact {
    file: File,
    initial: Stamp,
    bytes: Vec<u8>,
    selection: Selection,
    plan: Plan,
}
impl HeldArtifact {
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| Error::Io)?;
        let initial = stamp(&file)?;
        require(initial.len != 0, Error::Source)?;
        let mut bytes = vec![0; usize::try_from(initial.len).map_err(|_| Error::Source)?];
        file.read_exact_at(&mut bytes, 0).map_err(|_| Error::Io)?;
        verify_file(&file, initial, &bytes)?;
        let (selection, plan) = extract(&bytes)?;
        Ok(Self {
            file,
            initial,
            bytes,
            selection,
            plan,
        })
    }
    pub fn identity(&self) -> (u64, u64) {
        (self.initial.dev, self.initial.ino)
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn selection(&self) -> Selection {
        self.selection
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn verify(&self) -> Result<()> {
        verify_file(&self.file, self.initial, &self.bytes)
    }
    pub fn verify_same_file(&self, file: &File) -> Result<()> {
        verify_file(file, self.initial, &self.bytes)
    }
    pub fn mapped_base(&self, bias: u64) -> Result<u64> {
        require(u16_at(&self.bytes, 16)? != 2 || bias == 0, Error::Source)?;
        let ph = u64_at(&self.bytes, 32)?;
        let count = u16_at(&self.bytes, 56)?;
        let mut first = None;
        for n in 0..count {
            let at = end(ph, u64::from(n) * 56)?;
            if u32_at(&self.bytes, at)? == 1 {
                let page = u64_at(&self.bytes, at + 16)? & !4095;
                first = Some(first.map_or(page, |old: u64| old.min(page)));
            }
        }
        end(bias, first.ok_or(Error::Source)?)
    }
    /// Exact complete selected-page file offsets from the already admitted ELF.
    /// Partial file-backed pages and any overlapping/conflicting LOAD refuse.
    pub fn pages(&self, bias: u64) -> Result<Vec<(u64, u64, Vec<u8>)>> {
        let first = self.selection.virtual_address & !4095;
        let last = end(
            self.selection.virtual_address,
            self.selection.extent as u64 - 1,
        )? & !4095;
        require(
            last.checked_sub(first).is_some_and(|n| n <= 4096),
            Error::Source,
        )?;
        let ph = u64_at(&self.bytes, 32)?;
        let count = u16_at(&self.bytes, 56)?;
        let mut result = Vec::new();
        for page in [Some(first), (first != last).then_some(last)]
            .into_iter()
            .flatten()
        {
            let mut offset = None;
            for n in 0..count {
                let at = end(ph, u64::from(n) * 56)?;
                if u32_at(&self.bytes, at)? != 1 {
                    continue;
                }
                let address = u64_at(&self.bytes, at + 16)?;
                let memory = u64_at(&self.bytes, at + 40)?;
                if !overlaps(page, 4096, address, memory)? {
                    continue;
                }
                let files = u64_at(&self.bytes, at + 32)?;
                require(
                    offset.is_none()
                        && u32_at(&self.bytes, at + 4)? == 5
                        && address <= page
                        && end(page, 4096)? <= end(address, files)?,
                    Error::Source,
                )?;
                offset = Some(end(u64_at(&self.bytes, at + 8)?, page - address)?);
            }
            let offset = offset.ok_or(Error::Source)?;
            require(offset % 4096 == 0, Error::Source)?;
            result.push((
                end(bias, page)?,
                offset,
                slice(&self.bytes, offset, 4096)?.to_vec(),
            ));
        }
        Ok(result)
    }
}

/// Complete separately held candidate/trusted DSO bytes. Selection and mapping
/// authority is subsequently supplied by the normal retained loader.
pub(super) struct Sources {
    paths: [PathBuf; 2],
    candidate: File,
    trusted: File,
    a: Stamp,
    b: Stamp,
    bytes: Vec<u8>,
}
impl Sources {
    pub(super) fn open(candidate: &Path, trusted: &Path) -> Result<Self> {
        let open = |path: &Path| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)
                .map_err(|_| Error::Io)
        };
        let paths = [candidate.to_owned(), trusted.to_owned()];
        let candidate = open(candidate)?;
        let trusted = open(trusted)?;
        let a = stamp(&candidate)?;
        let b = stamp(&trusted)?;
        require(
            (a.dev, a.ino) != (b.dev, b.ino)
                && a.len == b.len
                && a.len != 0
                && a.len <= 1024 * 1024,
            Error::Source,
        )?;
        let mut bytes = vec![0; usize::try_from(a.len).map_err(|_| Error::Source)?];
        trusted
            .read_exact_at(&mut bytes, 0)
            .map_err(|_| Error::Io)?;
        let held = Self {
            paths,
            candidate,
            trusted,
            a,
            b,
            bytes,
        };
        held.verify()?;
        Ok(held)
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn selected(&self, entry: u64, len: usize) -> Result<Vec<u8>> {
        require(
            self.bytes.get(..6) == Some(&b"\x7fELF\x02\x01"[..])
                && u16_at(&self.bytes, 16)? == 3
                && u16_at(&self.bytes, 18)? == 62
                && u16_at(&self.bytes, 54)? == 56,
            Error::Source,
        )?;
        let ph = u64_at(&self.bytes, 32)?;
        let count = u16_at(&self.bytes, 56)?;
        require(
            (1..=256).contains(&count) && entry != 0 && (1..=256).contains(&len),
            Error::Source,
        )?;
        let mut selected = None;
        for n in 0..count {
            let at = end(ph, u64::from(n) * 56)?;
            if u32_at(&self.bytes, at)? != 1 {
                continue;
            }
            let va = u64_at(&self.bytes, at + 16)?;
            let memory = u64_at(&self.bytes, at + 40)?;
            if !overlaps(entry, len as u64, va, memory)? {
                continue;
            }
            require(
                selected.is_none()
                    && u32_at(&self.bytes, at + 4)? == 5
                    && va <= entry
                    && end(entry, len as u64)? <= end(va, u64_at(&self.bytes, at + 32)?)?,
                Error::Source,
            )?;
            selected = Some(
                slice(
                    &self.bytes,
                    end(u64_at(&self.bytes, at + 8)?, entry - va)?,
                    len as u64,
                )?
                .to_vec(),
            );
        }
        selected.ok_or(Error::Source)
    }
    pub(super) fn verify(&self) -> Result<()> {
        verify_file(&self.candidate, self.a, &self.bytes)?;
        verify_file(&self.trusted, self.b, &self.bytes)?;
        for (path, expected) in self.paths.iter().zip([self.a, self.b]) {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(path)
                .map_err(|_| Error::Io)?;
            verify_file(&file, expected, &self.bytes)?;
        }
        Ok(())
    }
}
