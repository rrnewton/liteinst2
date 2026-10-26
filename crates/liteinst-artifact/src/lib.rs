//! Content identity and metadata format; no execution authority.
//!
//! Integrity validates bytes and declared identities. It does not qualify the
//! selected entries, instructions, hooks, CPU, loader readiness or generated
//! code. Every original page remains unknown unless a separate scanner proves
//! otherwise. In particular, successful decoding never publishes code.

use sha2::{Digest as _, Sha256};

pub mod sparse;
pub mod sparse_wire;

const MAGIC: &[u8; 8] = b"LI2META\0";
const FORMAT: u32 = 1;
const HEADER_BYTES: usize = 56;
const PAYLOAD_FIXED_BYTES: usize = 176;
const SITE_BYTES: usize = 40;
/// Authentication granularity; a short final chunk still hashes every byte.
pub const CHUNK_BYTES: usize = 65_536;

/// SHA-256 content identity, independent of names, build IDs and load bias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Hash all supplied bytes, including an empty slice.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

/// Exact compatibility identity. These fields do not certify target support.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Compatibility {
    /// Core planner contract version.
    pub planner: u32,
    /// Encoder and fixup schema version.
    pub encoder: u32,
    /// Hook ABI version.
    pub hook_abi: u32,
    /// Module-relative arena layout version.
    pub arena: u32,
    /// Digest of the complete canonical CPU/xstate/CET target profile.
    pub target: ContentId,
    /// Digest of the complete relocation/load-bias policy.
    pub binding: ContentId,
}

/// Explicit tactic tag; a trap cannot be represented by any of these values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Tactic {
    /// Whole-instruction relocation.
    Relocation = 1,
    /// Generalized instruction pun.
    GeneralizedPun = 2,
    /// Prefix pun.
    PrefixedPun = 3,
    /// Successor eviction.
    SuccessorEviction = 4,
    /// Neighbor eviction.
    NeighborEviction = 5,
}

/// Per-request outcome; a refusal makes complete trampoline coverage false.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// A producer claims this tactic; format integrity does not prove semantics.
    Rewritten(Tactic),
    /// A trap fallback, separately counted from trampoline success.
    Trap,
    /// A nonzero reason in the producer's planner-versioned refusal vocabulary.
    Refused(u32),
}

/// One selected instruction. File location and original ELF PC are distinct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Site {
    /// Strictly increasing stable selected-manifest ID.
    pub id: u64,
    /// Original ELF virtual address, before binding a module load bias.
    pub original_pc: u64,
    /// Byte offset in original content.
    pub file_offset: u64,
    /// Declared instruction length, checked to be in 1..=15.
    pub length: u8,
    /// Complete per-site result.
    pub outcome: Outcome,
}

/// Decode resource limits, applied before allocation.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum encoded bytes, including header/checksum.
    pub bytes: usize,
    /// Maximum original chunk hashes.
    pub chunks: usize,
    /// Maximum selected-site records.
    pub sites: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 64 * 1024 * 1024,
            chunks: 1_048_576,
            sites: 262_144,
        }
    }
}

/// Typed fail-closed validation outcome; none grants execution permission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A declared length/count exceeds the consumer's prospective resource limit.
    ResourceLimit,
    /// The input has missing bytes or surplus bytes outside its declared length.
    Length,
    /// Magic, version, reserved bytes or record tags are not supported.
    Format,
    /// SHA-256 checksum differs.
    Corrupt,
    /// Exact target/planner/ABI/binding policy differs.
    Incompatible,
    /// Selected-manifest identity or complete requested ID set differs.
    Selection,
    /// Arithmetic overflow, instruction length, ordering or source range is invalid.
    InvalidRecord,
    /// Original content has a different length or full/chunk digest.
    Stale,
}

/// Immutable integrity-checked metadata; deliberately contains no clean verdicts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    original_len: u64,
    original: ContentId,
    selection: ContentId,
    compatibility: Compatibility,
    chunks: Vec<ContentId>,
    sites: Vec<Site>,
}

impl Metadata {
    /// Capture original content and declared selected outcomes.
    ///
    /// This is a structural constructor, not a semantic core-plan constructor.
    /// Consumers must authenticate the selected manifest and its complete ID set.
    pub fn new(
        original: &[u8],
        selection: ContentId,
        compatibility: Compatibility,
        sites: Vec<Site>,
    ) -> Result<Self, Error> {
        validate_sites(original.len() as u64, &sites)?;
        Ok(Self {
            original_len: original.len() as u64,
            original: ContentId::of(original),
            selection,
            compatibility,
            chunks: original.chunks(CHUNK_BYTES).map(ContentId::of).collect(),
            sites,
        })
    }

    /// Immutable original digest, not a digest of the patched output.
    pub fn original_id(&self) -> ContentId {
        self.original
    }
    /// Exact compatibility record.
    pub fn compatibility(&self) -> &Compatibility {
        &self.compatibility
    }
    /// Every declared selected outcome in ID order.
    pub fn sites(&self) -> &[Site] {
        &self.sites
    }
    /// Whether every declared site claims a trampoline; does not authenticate IDs.
    pub fn declares_complete_trampoline_coverage(&self) -> bool {
        self.sites
            .iter()
            .all(|site| matches!(site.outcome, Outcome::Rewritten(_)))
    }

    /// Require exact manifest identity and ordered complete IDs, including refusals.
    pub fn verify_selection(&self, identity: ContentId, ids: &[u64]) -> Result<(), Error> {
        if self.selection != identity
            || self.sites.len() != ids.len()
            || !self.sites.iter().zip(ids).all(|(site, id)| site.id == *id)
        {
            return Err(Error::Selection);
        }
        Ok(())
    }

    /// Authenticate full original bytes; build IDs and names are never substitutes.
    pub fn verify_original(&self, original: &[u8]) -> Result<(), Error> {
        if original.len() as u64 != self.original_len || ContentId::of(original) != self.original {
            return Err(Error::Stale);
        }
        Ok(())
    }

    /// Authenticate exactly one complete original chunk before its first use.
    /// Returns the verified file range, not an executable-page admission verdict.
    pub fn verify_chunk(
        &self,
        original_length: u64,
        index: usize,
        bytes: &[u8],
    ) -> Result<std::ops::Range<u64>, Error> {
        if original_length != self.original_len {
            return Err(Error::Stale);
        }
        let hash = self.chunks.get(index).ok_or(Error::InvalidRecord)?;
        let start = u64::try_from(index)
            .map_err(|_| Error::InvalidRecord)?
            .checked_mul(CHUNK_BYTES as u64)
            .ok_or(Error::InvalidRecord)?;
        let length = (self.original_len - start).min(CHUNK_BYTES as u64);
        if bytes.len() as u64 != length || ContentId::of(bytes) != *hash {
            return Err(Error::Stale);
        }
        Ok(start..start + length)
    }

    /// Serialize using fixed integers and a checksum covering header and payload.
    pub fn encode(&self, limits: Limits) -> Result<Vec<u8>, Error> {
        let payload_size = payload_size(self.chunks.len(), self.sites.len(), limits)?;
        let total = HEADER_BYTES
            .checked_add(payload_size)
            .ok_or(Error::ResourceLimit)?;
        if total > limits.bytes {
            return Err(Error::ResourceLimit);
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(MAGIC);
        push32(&mut bytes, FORMAT);
        push32(&mut bytes, 0);
        push64(&mut bytes, payload_size as u64);
        bytes.extend_from_slice(&[0; 32]);
        push64(&mut bytes, self.original_len);
        bytes.extend_from_slice(&self.original.0);
        bytes.extend_from_slice(&self.selection.0);
        for version in [
            self.compatibility.planner,
            self.compatibility.encoder,
            self.compatibility.hook_abi,
            self.compatibility.arena,
        ] {
            push32(&mut bytes, version);
        }
        bytes.extend_from_slice(&self.compatibility.target.0);
        bytes.extend_from_slice(&self.compatibility.binding.0);
        push32(&mut bytes, CHUNK_BYTES as u32);
        push32(&mut bytes, 0);
        push64(&mut bytes, self.chunks.len() as u64);
        push64(&mut bytes, self.sites.len() as u64);
        for chunk in &self.chunks {
            bytes.extend_from_slice(&chunk.0);
        }
        for site in &self.sites {
            push64(&mut bytes, site.id);
            push64(&mut bytes, site.original_pc);
            push64(&mut bytes, site.file_offset);
            bytes.push(site.length);
            let (tag, tactic, reason) = match site.outcome {
                Outcome::Rewritten(tactic) => (0, tactic as u8, 0),
                Outcome::Trap => (1, 0, 0),
                Outcome::Refused(reason) => (2, 0, reason),
            };
            bytes.extend_from_slice(&[tag, tactic, 0]);
            push32(&mut bytes, reason);
            push64(&mut bytes, 0);
        }
        assert_eq!(bytes.len(), total);
        let digest = checksum(&bytes);
        bytes[24..56].copy_from_slice(&digest.0);
        Ok(bytes)
    }

    /// Decode bounded metadata and require exact policy equality before use.
    pub fn decode(bytes: &[u8], policy: &Compatibility, limits: Limits) -> Result<Self, Error> {
        if bytes.len() > limits.bytes {
            return Err(Error::ResourceLimit);
        }
        if bytes.len() < HEADER_BYTES + PAYLOAD_FIXED_BYTES {
            return Err(Error::Length);
        }
        let mut read = Reader { bytes, at: 0 };
        if read.take(8)? != MAGIC || read.u32()? != FORMAT || read.u32()? != 0 {
            return Err(Error::Format);
        }
        let payload = usize::try_from(read.u64()?).map_err(|_| Error::Length)?;
        if payload.checked_add(HEADER_BYTES) != Some(bytes.len()) {
            return Err(Error::Length);
        }
        let recorded = read.id()?;
        if checksum(bytes) != recorded {
            return Err(Error::Corrupt);
        }
        let original_len = read.u64()?;
        let original = read.id()?;
        let selection = read.id()?;
        let compatibility = Compatibility {
            planner: read.u32()?,
            encoder: read.u32()?,
            hook_abi: read.u32()?,
            arena: read.u32()?,
            target: read.id()?,
            binding: read.id()?,
        };
        if compatibility != *policy {
            return Err(Error::Incompatible);
        }
        if read.u32()? != CHUNK_BYTES as u32 || read.u32()? != 0 {
            return Err(Error::Format);
        }
        let chunk_count = usize::try_from(read.u64()?).map_err(|_| Error::ResourceLimit)?;
        let site_count = usize::try_from(read.u64()?).map_err(|_| Error::ResourceLimit)?;
        if payload_size(chunk_count, site_count, limits)? != payload {
            return Err(Error::Length);
        }
        let expected_chunks =
            original_len / CHUNK_BYTES as u64 + u64::from(original_len % CHUNK_BYTES as u64 != 0);
        if chunk_count as u64 != expected_chunks {
            return Err(Error::InvalidRecord);
        }
        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            chunks.push(read.id()?);
        }
        let mut sites = Vec::with_capacity(site_count);
        for _ in 0..site_count {
            let id = read.u64()?;
            let original_pc = read.u64()?;
            let file_offset = read.u64()?;
            let fields = read.take(4)?;
            let length = fields[0];
            let (tag, tactic, reserved) = (fields[1], fields[2], fields[3]);
            let reason = read.u32()?;
            if reserved != 0 || read.u64()? != 0 {
                return Err(Error::Format);
            }
            let outcome = match (tag, tactic, reason) {
                (0, tactic @ 1..=5, 0) => Outcome::Rewritten(match tactic {
                    1 => Tactic::Relocation,
                    2 => Tactic::GeneralizedPun,
                    3 => Tactic::PrefixedPun,
                    4 => Tactic::SuccessorEviction,
                    5 => Tactic::NeighborEviction,
                    _ => unreachable!(),
                }),
                (1, 0, 0) => Outcome::Trap,
                (2, 0, reason) if reason != 0 => Outcome::Refused(reason),
                _ => return Err(Error::Format),
            };
            sites.push(Site {
                id,
                original_pc,
                file_offset,
                length,
                outcome,
            });
        }
        if read.at != bytes.len() {
            return Err(Error::Length);
        }
        validate_sites(original_len, &sites)?;
        Ok(Self {
            original_len,
            original,
            selection,
            compatibility,
            chunks,
            sites,
        })
    }
}

fn validate_sites(original_len: u64, sites: &[Site]) -> Result<(), Error> {
    let mut previous = None;
    for site in sites {
        if previous.is_some_and(|id| id >= site.id)
            || !(1..=15).contains(&site.length)
            || site
                .file_offset
                .checked_add(u64::from(site.length))
                .is_none_or(|end| end > original_len)
            || site
                .original_pc
                .checked_add(u64::from(site.length))
                .is_none()
            || matches!(site.outcome, Outcome::Refused(0))
        {
            return Err(Error::InvalidRecord);
        }
        previous = Some(site.id);
    }
    Ok(())
}

fn payload_size(chunks: usize, sites: usize, limits: Limits) -> Result<usize, Error> {
    if chunks > limits.chunks || sites > limits.sites {
        return Err(Error::ResourceLimit);
    }
    chunks
        .checked_mul(32)
        .and_then(|n| sites.checked_mul(SITE_BYTES).and_then(|s| n.checked_add(s)))
        .and_then(|n| n.checked_add(PAYLOAD_FIXED_BYTES))
        .ok_or(Error::ResourceLimit)
}
fn push32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn push64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn checksum(bytes: &[u8]) -> ContentId {
    let mut hash = Sha256::new();
    hash.update(&bytes[..24]);
    hash.update([0; 32]);
    hash.update(&bytes[56..]);
    ContentId(hash.finalize().into())
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(size).ok_or(Error::Length)?;
        let value = self.bytes.get(self.at..end).ok_or(Error::Length)?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn id(&mut self) -> Result<ContentId, Error> {
        Ok(ContentId(self.take(32)?.try_into().unwrap()))
    }
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
