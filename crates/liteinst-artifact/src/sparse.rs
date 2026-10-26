//! Exact original-file page reconstruction. This module never maps pages.
//!
//! ELF permissions, file-to-virtual translations, zero-fill and page aliases must
//! be separately qualified by the carrier. A short final record contains only
//! original file bytes; it is not a promise that a whole executable page exists.

use crate::ContentId;
use std::collections::BTreeMap;

/// Fixed x86 page granularity for this versioned sparse-file representation.
pub const PAGE_BYTES: usize = 4096;

/// An authenticated same-length edit in original file-offset space.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileEdit {
    /// Original file offset, never a runtime virtual address.
    pub offset: u64,
    /// Exact nonempty bytes before rewriting.
    pub expected: Vec<u8>,
    /// Same-length replacement; unchanged padding remains explicit.
    pub replacement: Vec<u8>,
}

/// File bytes for one actually changed page, including an explicit short tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    /// Page-aligned original file offset.
    pub offset: u64,
    /// Exact original page with only declared byte edits applied.
    pub bytes: Vec<u8>,
}

/// Prospective bounds, checked before constructing replacement page buffers.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum declared edit count.
    pub edits: usize,
    /// Maximum total bytes explicitly named by edits, including unchanged padding.
    pub edited_bytes: usize,
    /// Maximum number of actually changed original pages.
    pub pages: usize,
}

/// Structural/content failure, never permission to execute cached code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// An explicit prospective bound is exceeded.
    ResourceLimit,
    /// Empty or length-changing edit.
    InvalidEdit,
    /// Edit offset/length does not fit original content.
    OutOfBounds,
    /// Edit order is not strictly nonoverlapping.
    OverlapOrOrder,
    /// Expected bytes differ from original content.
    StaleEdit,
    /// The recorded original full identity/length differs.
    StaleOriginal,
    /// Supplied sparse pages differ from exact reconstruction or its inventory.
    PageMismatch,
}

/// Authenticated original-relative sparse changes, with no executable authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparsePages {
    original: ContentId,
    original_len: u64,
    edits: Vec<FileEdit>,
    pages: Vec<Page>,
}

impl SparsePages {
    /// Construct only actually changed pages from exact original expectations.
    pub fn build(original: &[u8], edits: Vec<FileEdit>, limits: Limits) -> Result<Self, Error> {
        validate_edits(original, &edits, limits)?;
        let mut pages = BTreeMap::<usize, Vec<u8>>::new();
        for edit in &edits {
            // Conversion/range bounds were checked before any page allocation.
            let start = edit.offset as usize;
            let mut at = start;
            let end = start + edit.expected.len();
            while at < end {
                let page_start = at / PAGE_BYTES * PAGE_BYTES;
                let page_end = original.len().min(page_start.saturating_add(PAGE_BYTES));
                let stop = end.min(page_end);
                let replacement = &edit.replacement[at - start..stop - start];
                if replacement != &original[at..stop] {
                    if !pages.contains_key(&page_start) && pages.len() >= limits.pages {
                        return Err(Error::ResourceLimit);
                    }
                    let page = pages
                        .entry(page_start)
                        .or_insert_with(|| original[page_start..page_end].to_vec());
                    page[at - page_start..stop - page_start].copy_from_slice(replacement);
                }
                at = stop;
            }
        }
        Ok(Self {
            original: ContentId::of(original),
            original_len: original.len() as u64,
            edits,
            pages: pages
                .into_iter()
                .map(|(offset, bytes)| Page {
                    offset: offset as u64,
                    bytes,
                })
                .collect(),
        })
    }

    /// Authenticate decoded pages against original content and exact declarations.
    /// Any extra, missing, reordered or corrupted page is rejected.
    pub fn validate_parts(
        original: &[u8],
        original_id: ContentId,
        original_len: u64,
        edits: Vec<FileEdit>,
        pages: Vec<Page>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if pages.len() > limits.pages {
            return Err(Error::ResourceLimit);
        }
        if original.len() as u64 != original_len || ContentId::of(original) != original_id {
            return Err(Error::StaleOriginal);
        }
        let rebuilt = Self::build(original, edits, limits)?;
        if rebuilt.pages != pages {
            return Err(Error::PageMismatch);
        }
        Ok(rebuilt)
    }

    /// Original identity, separate from the eventual serialized overlay checksum.
    pub fn original_id(&self) -> ContentId {
        self.original
    }
    /// Exact immutable original-relative edit declarations.
    pub fn edits(&self) -> &[FileEdit] {
        &self.edits
    }
    /// Sorted, nonempty records only for pages containing actual changed bytes.
    pub fn pages(&self) -> &[Page] {
        &self.pages
    }
    /// Complete original file size; a final partial record never implies zero-fill.
    pub fn original_len(&self) -> u64 {
        self.original_len
    }
}

fn validate_edits(original: &[u8], edits: &[FileEdit], limits: Limits) -> Result<(), Error> {
    if edits.len() > limits.edits {
        return Err(Error::ResourceLimit);
    }
    let mut previous_end = 0;
    let mut total = 0_usize;
    for edit in edits {
        if edit.expected.is_empty() || edit.expected.len() != edit.replacement.len() {
            return Err(Error::InvalidEdit);
        }
        total = total
            .checked_add(edit.expected.len())
            .ok_or(Error::ResourceLimit)?;
        if total > limits.edited_bytes {
            return Err(Error::ResourceLimit);
        }
        let start = usize::try_from(edit.offset).map_err(|_| Error::OutOfBounds)?;
        let end = start
            .checked_add(edit.expected.len())
            .ok_or(Error::OutOfBounds)?;
        let bytes = original.get(start..end).ok_or(Error::OutOfBounds)?;
        if start < previous_end {
            return Err(Error::OverlapOrOrder);
        }
        if bytes != edit.expected {
            return Err(Error::StaleEdit);
        }
        previous_end = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> Limits {
        Limits {
            edits: 4,
            edited_bytes: 9000,
            pages: 3,
        }
    }
    fn original() -> Vec<u8> {
        (0..8195).map(|i| (i % 251) as u8).collect()
    }
    fn edit(original: &[u8], start: usize, len: usize) -> FileEdit {
        FileEdit {
            offset: start as u64,
            expected: original[start..start + len].to_vec(),
            replacement: original[start..start + len]
                .iter()
                .map(|b| b ^ 0xff)
                .collect(),
        }
    }
    #[test]
    fn page_crossing_adjacent_edits_and_short_tail_reconstruct_exactly() {
        let original = original();
        let edits = vec![
            edit(&original, 4094, 4),
            edit(&original, 4098, 2),
            edit(&original, 8193, 2),
        ];
        let overlay = SparsePages::build(&original, edits.clone(), limits()).unwrap();
        assert_eq!(
            overlay
                .pages()
                .iter()
                .map(|p| (p.offset, p.bytes.len()))
                .collect::<Vec<_>>(),
            vec![(0, 4096), (4096, 4096), (8192, 3)]
        );
        let mut expected = original.clone();
        for i in [4094, 4095, 4096, 4097, 4098, 4099, 8193, 8194] {
            expected[i] ^= 0xff;
        }
        let reconstructed: Vec<u8> = overlay
            .pages()
            .iter()
            .flat_map(|p| p.bytes.clone())
            .collect();
        assert_eq!(reconstructed, expected);
        assert_eq!(original, super::tests::original());
        assert_eq!(
            SparsePages::validate_parts(
                &original,
                ContentId::of(&original),
                original.len() as u64,
                edits,
                overlay.pages().to_vec(),
                limits()
            )
            .unwrap(),
            overlay
        );
    }
    #[test]
    fn unchanged_padding_and_empty_edit_set_create_no_unmodified_pages() {
        let original = original();
        let mut item = edit(&original, 4095, 4098);
        item.replacement = item.expected.clone();
        item.replacement[1] ^= 0xff;
        let overlay = SparsePages::build(&original, vec![item], limits()).unwrap();
        assert_eq!(overlay.pages().len(), 1);
        assert_eq!(overlay.pages()[0].offset, 4096);
        assert!(
            SparsePages::build(&original, vec![], limits())
                .unwrap()
                .pages()
                .is_empty()
        );
        assert!(
            SparsePages::build(&[], vec![], limits())
                .unwrap()
                .pages()
                .is_empty()
        );
    }
    #[test]
    fn stale_source_expectations_bounds_overlap_order_and_shapes_refuse() {
        let original = original();
        let valid = edit(&original, 100, 4);
        let mut bad = valid.clone();
        bad.expected[0] ^= 1;
        assert_eq!(
            SparsePages::build(&original, vec![bad], limits()),
            Err(Error::StaleEdit)
        );
        for offset in [8194, u64::MAX] {
            let mut bad = valid.clone();
            bad.offset = offset;
            assert_eq!(
                SparsePages::build(&original, vec![bad], limits()),
                Err(Error::OutOfBounds)
            );
        }
        let mut bad = valid.clone();
        bad.replacement.pop();
        assert_eq!(
            SparsePages::build(&original, vec![bad], limits()),
            Err(Error::InvalidEdit)
        );
        assert_eq!(
            SparsePages::build(
                &original,
                vec![FileEdit {
                    offset: 0,
                    expected: vec![],
                    replacement: vec![]
                }],
                limits()
            ),
            Err(Error::InvalidEdit)
        );
        for items in [
            vec![valid.clone(), valid.clone()],
            vec![valid.clone(), edit(&original, 102, 4)],
            vec![valid.clone(), edit(&original, 98, 2)],
        ] {
            assert_eq!(
                SparsePages::build(&original, items, limits()),
                Err(Error::OverlapOrOrder)
            );
        }
    }
    #[test]
    fn sparse_inventory_or_undeclared_byte_change_is_rejected() {
        let original = original();
        let edits = vec![edit(&original, 4095, 2)];
        let overlay = SparsePages::build(&original, edits.clone(), limits()).unwrap();
        let mut mutations = vec![vec![], overlay.pages()[..1].to_vec()];
        let mut reversed = overlay.pages().to_vec();
        reversed.reverse();
        mutations.push(reversed);
        let mut corrupt = overlay.pages().to_vec();
        corrupt[0].bytes[20] ^= 1;
        mutations.push(corrupt);
        let mut wrong = overlay.pages().to_vec();
        wrong[0].offset = 1;
        mutations.push(wrong);
        let mut extra = overlay.pages().to_vec();
        extra.push(Page {
            offset: 8192,
            bytes: original[8192..].to_vec(),
        });
        mutations.push(extra);
        let mut short = overlay.pages().to_vec();
        short[0].bytes.pop();
        mutations.push(short);
        for pages in mutations {
            assert_eq!(
                SparsePages::validate_parts(
                    &original,
                    ContentId::of(&original),
                    original.len() as u64,
                    edits.clone(),
                    pages,
                    limits()
                ),
                Err(Error::PageMismatch)
            );
        }
    }
    #[test]
    fn original_identity_length_and_each_resource_axis_are_required() {
        let original = original();
        let edits = vec![edit(&original, 4095, 2)];
        let overlay = SparsePages::build(&original, edits.clone(), limits()).unwrap();
        for (id, len) in [
            (ContentId([0; 32]), original.len() as u64),
            (ContentId::of(&original), original.len() as u64 - 1),
        ] {
            assert_eq!(
                SparsePages::validate_parts(
                    &original,
                    id,
                    len,
                    edits.clone(),
                    overlay.pages().to_vec(),
                    limits()
                ),
                Err(Error::StaleOriginal)
            );
        }
        for bound in [
            Limits {
                edits: 0,
                ..limits()
            },
            Limits {
                edited_bytes: 1,
                ..limits()
            },
            Limits {
                pages: 1,
                ..limits()
            },
        ] {
            assert_eq!(
                SparsePages::build(&original, edits.clone(), bound),
                Err(Error::ResourceLimit)
            );
        }
    }
}
