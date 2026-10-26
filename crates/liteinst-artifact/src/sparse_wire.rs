//! Bounded sparse-page wire format. Decoding authenticates complete original
//! content and reconstructs every changed page; it grants no mapping authority.
//! Generated images, readiness and ELF bindings belong to the enclosing artifact.

use crate::sparse::{FileEdit, PAGE_BYTES, Page, SparsePages};
use crate::{Reader, checksum, push32, push64};

const MAGIC: &[u8; 8] = b"LI2SPRS\0";
const HEADER: usize = 56;
const FIXED: usize = 64;

/// Bounds must be chosen by the consumer before reading untrusted data.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete encoded size, including checksum and declarations.
    pub bytes: usize,
    /// Bounds for edit count, edit bytes and changed-page count.
    pub content: crate::sparse::Limits,
}

/// Byte-integrity or exact-original reconstruction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Envelope format, checksum or allocation bound failed.
    Envelope(crate::Error),
    /// Original content, declarations or reconstructed pages differ.
    Content(crate::sparse::Error),
}
impl From<crate::Error> for Error {
    fn from(value: crate::Error) -> Self {
        Self::Envelope(value)
    }
}
impl From<crate::sparse::Error> for Error {
    fn from(value: crate::sparse::Error) -> Self {
        Self::Content(value)
    }
}

/// Serialize exact declarations and original-relative pages, without addresses.
pub fn encode(pages: &SparsePages, limits: Limits) -> Result<Vec<u8>, Error> {
    use crate::Error::ResourceLimit;
    if pages.edits().len() > limits.content.edits || pages.pages().len() > limits.content.pages {
        return Err(ResourceLimit.into());
    }
    let mut edited = 0_usize;
    let mut size = HEADER + FIXED;
    for edit in pages.edits() {
        edited = edited
            .checked_add(edit.expected.len())
            .ok_or(ResourceLimit)?;
        size = edit
            .expected
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(16))
            .and_then(|n| size.checked_add(n))
            .ok_or(ResourceLimit)?;
    }
    for page in pages.pages() {
        size = page
            .bytes
            .len()
            .checked_add(16)
            .and_then(|n| size.checked_add(n))
            .ok_or(ResourceLimit)?;
    }
    if edited > limits.content.edited_bytes || size > limits.bytes {
        return Err(ResourceLimit.into());
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(MAGIC);
    push32(&mut bytes, 1);
    push32(&mut bytes, 0);
    push64(&mut bytes, (size - HEADER) as u64);
    bytes.extend_from_slice(&[0; 32]);
    push64(&mut bytes, pages.original_len());
    bytes.extend_from_slice(&pages.original_id().0);
    push64(&mut bytes, pages.edits().len() as u64);
    push64(&mut bytes, pages.pages().len() as u64);
    push32(&mut bytes, PAGE_BYTES as u32);
    push32(&mut bytes, 0);
    for edit in pages.edits() {
        push64(&mut bytes, edit.offset);
        push64(&mut bytes, edit.expected.len() as u64);
        bytes.extend_from_slice(&edit.expected);
        bytes.extend_from_slice(&edit.replacement);
    }
    for page in pages.pages() {
        push64(&mut bytes, page.offset);
        push64(&mut bytes, page.bytes.len() as u64);
        bytes.extend_from_slice(&page.bytes);
    }
    assert_eq!(bytes.len(), size);
    let digest = checksum(&bytes);
    bytes[24..56].copy_from_slice(&digest.0);
    Ok(bytes)
}

/// Decode under prospective bounds, then require exact page reconstruction.
/// The checksum detects corruption, not a malicious producer's intent.
pub fn decode(bytes: &[u8], original: &[u8], limits: Limits) -> Result<SparsePages, Error> {
    use crate::Error::{Corrupt, Format, Length, ResourceLimit};
    if bytes.len() > limits.bytes {
        return Err(ResourceLimit.into());
    }
    if bytes.len() < HEADER + FIXED {
        return Err(Length.into());
    }
    let mut read = Reader { bytes, at: 0 };
    if read.take(8)? != MAGIC || read.u32()? != 1 || read.u32()? != 0 {
        return Err(Format.into());
    }
    let payload = usize::try_from(read.u64()?).map_err(|_| Length)?;
    if payload.checked_add(HEADER) != Some(bytes.len()) {
        return Err(Length.into());
    }
    if read.id()? != checksum(bytes) {
        return Err(Corrupt.into());
    }
    let original_len = read.u64()?;
    let original_id = read.id()?;
    let count = usize::try_from(read.u64()?).map_err(|_| ResourceLimit)?;
    let page_count = usize::try_from(read.u64()?).map_err(|_| ResourceLimit)?;
    if count > limits.content.edits || page_count > limits.content.pages {
        return Err(ResourceLimit.into());
    }
    if read.u32()? != PAGE_BYTES as u32 || read.u32()? != 0 {
        return Err(Format.into());
    }
    // Even empty records require their fixed headers. Reject huge counts before
    // record-vector allocation, independently of caller-selected count limits.
    let minimum = count
        .checked_add(page_count)
        .and_then(|n| n.checked_mul(16))
        .ok_or(ResourceLimit)?;
    if minimum > bytes.len() - read.at {
        return Err(Length.into());
    }
    if original.len() as u64 != original_len || crate::ContentId::of(original) != original_id {
        return Err(crate::sparse::Error::StaleOriginal.into());
    }
    let mut edits = Vec::with_capacity(count);
    let mut edited = 0_usize;
    let mut previous_end = 0_usize;
    for _ in 0..count {
        let offset = read.u64()?;
        let length = usize::try_from(read.u64()?).map_err(|_| ResourceLimit)?;
        edited = edited.checked_add(length).ok_or(ResourceLimit)?;
        if edited > limits.content.edited_bytes {
            return Err(ResourceLimit.into());
        }
        if length == 0 {
            return Err(crate::sparse::Error::InvalidEdit.into());
        }
        let start = usize::try_from(offset).map_err(|_| crate::sparse::Error::OutOfBounds)?;
        let end = start
            .checked_add(length)
            .ok_or(crate::sparse::Error::OutOfBounds)?;
        let source = original
            .get(start..end)
            .ok_or(crate::sparse::Error::OutOfBounds)?;
        if start < previous_end {
            return Err(crate::sparse::Error::OverlapOrOrder.into());
        }
        let expected = read.take(length)?;
        let replacement = read.take(length)?;
        if source != expected {
            return Err(crate::sparse::Error::StaleEdit.into());
        }
        edits.push(FileEdit {
            offset,
            expected: expected.to_vec(),
            replacement: replacement.to_vec(),
        });
        previous_end = end;
    }
    let mut pages = Vec::with_capacity(page_count);
    let mut previous_page = None;
    for _ in 0..page_count {
        let offset = read.u64()?;
        let length = usize::try_from(read.u64()?).map_err(|_| ResourceLimit)?;
        if length > PAGE_BYTES {
            return Err(ResourceLimit.into());
        }
        if offset % PAGE_BYTES as u64 != 0
            || offset >= original_len
            || length as u64 != (original_len - offset).min(PAGE_BYTES as u64)
            || previous_page.is_some_and(|previous| previous >= offset)
        {
            return Err(crate::sparse::Error::PageMismatch.into());
        }
        pages.push(Page {
            offset,
            bytes: read.take(length)?.to_vec(),
        });
        previous_page = Some(offset);
    }
    if read.at != bytes.len() {
        return Err(Length.into());
    }
    Ok(SparsePages::validate_parts(
        original,
        original_id,
        original_len,
        edits,
        pages,
        limits.content,
    )?)
}

#[cfg(test)]
#[path = "sparse_wire_tests.rs"]
mod tests;
