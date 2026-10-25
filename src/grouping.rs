//! Immutable physical backing shared by images at dictated virtual addresses.
//!
//! Each image remains encoded for, and classified only at, its own address.
//! Sharing saves backing pages, never virtual mappings. This module performs
//! no source publication, signal routing, admission, or mutable probe control.

use crate::contracts::{AddressRange, Refusal};
use crate::trampoline::{ExecutableTrampoline, PendingExecutableTrampoline, TrampolineImage};

/// Page granularity of this Linux x86-64 grouping format.
pub const GROUPING_PAGE_BYTES: usize = 4096;

/// Independent limits for virtual placement and immutable backing storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupingBudget {
    /// Maximum requested RX mapping extents, independent of kernel VMA merges.
    pub max_mappings: usize,
    /// Maximum distinct virtual pages, including every page of dedicated images.
    pub max_virtual_pages: usize,
    /// Maximum sum of virtual mapping lengths.
    pub max_virtual_bytes: u64,
    /// Maximum sum of newly allocated backing lengths.
    pub max_backing_bytes: u64,
    /// Maximum last mapping end minus first mapping start.
    pub max_virtual_span: u64,
}

impl Default for GroupingBudget {
    fn default() -> Self {
        Self {
            max_mappings: 64,
            max_virtual_pages: 128,
            max_virtual_bytes: 512 * 1024,
            max_backing_bytes: 512 * 1024,
            max_virtual_span: 1 << 32,
        }
    }
}

/// Exact planned resource accounting; physical residency is not estimated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupingMemory {
    /// Number of requested RX mapping extents, not backing objects or kernel VMAs.
    pub mappings: usize,
    /// Number of distinct virtual pages.
    pub virtual_pages: usize,
    /// Number of allocated backing pages, counted once across aliases.
    pub backing_pages: usize,
    /// Sum of virtual mapping lengths.
    pub virtual_bytes: u64,
    /// Sum of backing lengths, counted once across aliases.
    pub backing_bytes: u64,
    /// Last mapping end minus first mapping start, including intervening gaps.
    pub virtual_span: u64,
}

/// Why an image belongs to a particular immutable backing object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackingKind {
    /// One page containing one or more images at disjoint page offsets.
    SharedPage,
    /// An image crossing a page boundary, retained in its own complete backing.
    DedicatedImage,
}

/// One backing object and the exact virtual aliases that will map it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackingGroup {
    kind: BackingKind,
    backing_len: usize,
    image_indices: Vec<usize>,
    aliases: Vec<AddressRange>,
}

impl BackingGroup {
    /// Whether this is a shareable page or a complete dedicated image.
    pub const fn kind(&self) -> BackingKind {
        self.kind
    }

    /// Complete page-rounded backing length.
    pub const fn backing_len(&self) -> usize {
        self.backing_len
    }

    /// Indices into [`GroupingPlan::images`], in input order.
    pub fn image_indices(&self) -> &[usize] {
        &self.image_indices
    }

    /// Exact mapping extents corresponding to [`Self::image_indices`].
    pub fn aliases(&self) -> &[AddressRange] {
        &self.aliases
    }
}

/// A pure, deterministic first-fit grouping of already emitted immutable code.
///
/// Every image appears exactly once. Images that cross a page boundary receive
/// dedicated backing; overlapping offsets at different virtual pages receive
/// separate backing groups. Overlapping *virtual mapping extents*, including
/// two disjoint images in one virtual page, are explicitly refused to preserve
/// the current bundle allocation ownership model.
#[derive(Clone, Debug)]
pub struct GroupingPlan {
    images: Vec<TrampolineImage>,
    groups: Vec<BackingGroup>,
    memory: GroupingMemory,
}

impl GroupingPlan {
    /// Groups every image without moving, re-encoding, or mapping any bytes.
    ///
    /// Empty input, an empty image, address overflow, and the null mapping page
    /// are invalid. This immutable format contains no mutable toggle flags.
    pub fn new(images: Vec<TrampolineImage>, budget: GroupingBudget) -> Result<Self, Refusal> {
        if images.is_empty() {
            return Err(Refusal::InvalidPlan);
        }
        if images.len() > budget.max_mappings {
            return Err(Refusal::AllocationUnavailable);
        }
        let mut ranges = Vec::with_capacity(images.len());
        let mut groups: Vec<BackingGroup> = Vec::new();
        let mut virtual_bytes = 0_u64;
        let mut backing_bytes = 0_u64;
        for (index, image) in images.iter().enumerate() {
            let range = image_mapping(image)?;
            if ranges
                .iter()
                .any(|prior: &AddressRange| prior.overlaps(range))
            {
                return Err(Refusal::OwnershipConflict);
            }
            virtual_bytes = virtual_bytes
                .checked_add(range.len())
                .ok_or(Refusal::InvalidRange)?;
            let offset = image.address() - range.start();
            let occupied_end = offset + image.bytes().len() as u64;
            let existing = if range.len() == GROUPING_PAGE_BYTES as u64 {
                groups.iter_mut().find(|group| {
                    group.kind == BackingKind::SharedPage
                        && group.image_indices.iter().all(|&prior| {
                            let other = &images[prior];
                            let start = other.address() % GROUPING_PAGE_BYTES as u64;
                            let end = start + other.bytes().len() as u64;
                            occupied_end <= start || end <= offset
                        })
                })
            } else {
                None
            };
            if let Some(group) = existing {
                group.image_indices.push(index);
                group.aliases.push(range);
            } else {
                let backing_len =
                    usize::try_from(range.len()).map_err(|_| Refusal::InvalidRange)?;
                backing_bytes = backing_bytes
                    .checked_add(range.len())
                    .ok_or(Refusal::InvalidRange)?;
                groups.push(BackingGroup {
                    kind: if backing_len == GROUPING_PAGE_BYTES {
                        BackingKind::SharedPage
                    } else {
                        BackingKind::DedicatedImage
                    },
                    backing_len,
                    image_indices: vec![index],
                    aliases: vec![range],
                });
            }
            ranges.push(range);
        }
        let low = ranges.iter().map(|range| range.start()).min().unwrap();
        let high = ranges.iter().map(|range| range.end()).max().unwrap();
        let memory = GroupingMemory {
            mappings: ranges.len(),
            virtual_pages: usize::try_from(virtual_bytes / GROUPING_PAGE_BYTES as u64)
                .map_err(|_| Refusal::InvalidRange)?,
            backing_pages: usize::try_from(backing_bytes / GROUPING_PAGE_BYTES as u64)
                .map_err(|_| Refusal::InvalidRange)?,
            virtual_bytes,
            backing_bytes,
            virtual_span: high - low,
        };
        if memory.virtual_pages > budget.max_virtual_pages
            || memory.virtual_bytes > budget.max_virtual_bytes
            || memory.backing_bytes > budget.max_backing_bytes
            || memory.virtual_span > budget.max_virtual_span
        {
            return Err(Refusal::AllocationUnavailable);
        }
        Ok(Self {
            images,
            groups,
            memory,
        })
    }

    /// Input images and their original addresses and PC maps, without aliases.
    pub fn images(&self) -> &[TrampolineImage] {
        &self.images
    }

    /// Every planned immutable backing and its virtual mapping obligations.
    pub fn groups(&self) -> &[BackingGroup] {
        &self.groups
    }

    /// Separate mapping, virtual page, backing page, byte, and span totals.
    pub const fn memory(&self) -> GroupingMemory {
        self.memory
    }

    /// Stages every exact RX alias after sealing its backing against mutation.
    ///
    /// No source bytes or global PC maps are published. Any error releases all
    /// aliases staged by this call, including earlier completed groups. The
    /// returned owner releases all mappings unless explicitly committed.
    pub fn stage(&self) -> Result<StagedGrouping, Refusal> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            native::stage(self)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            Err(Refusal::UnsupportedSemantics(
                "immutable grouping requires Linux x86-64 with 4096-byte pages".into(),
            ))
        }
    }
}

fn image_mapping(image: &TrampolineImage) -> Result<AddressRange, Refusal> {
    let occupied = AddressRange::new(image.address(), image.bytes().len())?;
    let mask = GROUPING_PAGE_BYTES as u64 - 1;
    let start = occupied.start() & !mask;
    let end = occupied
        .end()
        .checked_add(mask)
        .ok_or(Refusal::InvalidRange)?
        & !mask;
    if start == 0 {
        return Err(Refusal::InvalidRange);
    }
    AddressRange::new(
        start,
        usize::try_from(end - start).map_err(|_| Refusal::InvalidRange)?,
    )
}

/// Unpublished executable mappings with rollback ownership.
///
/// No executable handles are exposed before commit, preventing premature
/// publication of reverse-PC metadata for mappings that may still be removed.
pub struct StagedGrouping {
    images: Vec<PendingExecutableTrampoline>,
    memory: GroupingMemory,
    // Read-only kernel measurements captured while descriptors are still owned.
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    backing_file_bytes: Vec<u64>,
}

impl StagedGrouping {
    /// Resources held by this staging transaction.
    pub const fn memory(&self) -> GroupingMemory {
        self.memory
    }

    /// Transfers every image to process-lifetime ownership, in input order.
    ///
    /// This is the irrevocable allocation commit, not source publication.
    /// Returned mappings intentionally survive handle drop, including failed
    /// subsequent publication. Global PC maps remain unpublished until the
    /// caller invokes each handle's publication method. Only the input image's
    /// own PC maps are attached to its alias; other backing contents have none.
    pub fn commit(self) -> Vec<ExecutableTrampoline> {
        self.images
            .into_iter()
            .map(PendingExecutableTrampoline::commit)
            .collect()
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod native {
    use super::*;

    const REQUIRED_SEALS: libc::c_int =
        libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

    struct Backing(libc::c_int);

    impl Backing {
        fn new(plan: &GroupingPlan, group: &BackingGroup) -> Result<Self, Refusal> {
            // SAFETY: constant terminated name and scalar memfd options.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_memfd_create,
                    c"liteinst2-immutable-group".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                ) as libc::c_int
            };
            if fd < 0 {
                return Err(os_error("memfd_create immutable group"));
            }
            let backing = Self(fd);
            let len =
                libc::off_t::try_from(group.backing_len).map_err(|_| Refusal::InvalidRange)?;
            // SAFETY: this object exclusively owns a newly created memfd.
            if unsafe { libc::ftruncate(fd, len) } != 0 {
                return Err(os_error("ftruncate immutable group"));
            }
            // Unoccupied bytes are traps, not an additional executable image.
            // pwrite avoids creating any writable shared mapping at all.
            let fill = [0xcc; GROUPING_PAGE_BYTES];
            for offset in (0..group.backing_len).step_by(GROUPING_PAGE_BYTES) {
                backing.write_all(&fill, offset)?;
            }
            for (&index, alias) in group.image_indices.iter().zip(&group.aliases) {
                let image = &plan.images[index];
                let offset = usize::try_from(image.address() - alias.start())
                    .map_err(|_| Refusal::InvalidRange)?;
                backing.write_all(image.bytes(), offset)?;
            }
            // Seal before creating even an RX shared alias; all later mappings
            // must lack permission to acquire shared write access with mprotect.
            // SAFETY: scalar fcntl commands on the exclusively owned descriptor.
            if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, REQUIRED_SEALS) } != 0 {
                return Err(os_error("seal immutable group"));
            }
            if unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } != REQUIRED_SEALS {
                return Err(os_error("verify immutable group seals"));
            }
            Ok(backing)
        }

        fn write_all(&self, mut bytes: &[u8], mut offset: usize) -> Result<(), Refusal> {
            while !bytes.is_empty() {
                let native_offset =
                    libc::off_t::try_from(offset).map_err(|_| Refusal::InvalidRange)?;
                // SAFETY: the byte slice remains live; pwrite does not retain it.
                let written = unsafe {
                    libc::pwrite(self.0, bytes.as_ptr().cast(), bytes.len(), native_offset)
                };
                if written < 0 {
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(os_error("pwrite immutable group"));
                }
                if written == 0 {
                    return Err(Refusal::Backend(
                        "pwrite immutable group made no progress".into(),
                    ));
                }
                bytes = &bytes[written as usize..];
                offset += written as usize;
            }
            Ok(())
        }

        fn close(mut self) -> Result<(), Refusal> {
            let fd = core::mem::replace(&mut self.0, -1);
            // SAFETY: disarming before close prevents a double-close if Linux
            // releases the descriptor while reporting an error.
            if unsafe { libc::close(fd) } != 0 {
                return Err(os_error("close immutable group memfd"));
            }
            Ok(())
        }
    }

    impl Drop for Backing {
        fn drop(&mut self) {
            if self.0 >= 0 {
                // SAFETY: this descriptor has not been transferred or closed.
                unsafe { libc::close(self.0) };
            }
        }
    }

    pub(super) fn stage(plan: &GroupingPlan) -> Result<StagedGrouping, Refusal> {
        // SAFETY: sysconf takes no pointer arguments.
        if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != GROUPING_PAGE_BYTES as libc::c_long {
            return Err(Refusal::UnsupportedSemantics(
                "immutable grouping requires 4096-byte pages".into(),
            ));
        }
        let mut staged = Vec::with_capacity(plan.images.len());
        #[cfg(test)]
        let mut backing_file_bytes = Vec::with_capacity(plan.groups.len());
        for group in &plan.groups {
            let backing = Backing::new(plan, group)?;
            #[cfg(test)]
            {
                let mut stat = core::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: live owned fd and writable output storage; successful
                // fstat initializes the complete stat structure.
                if unsafe { libc::fstat(backing.0, stat.as_mut_ptr()) } != 0 {
                    return Err(os_error("fstat immutable grouping evidence"));
                }
                backing_file_bytes.push(
                    u64::try_from(unsafe { stat.assume_init() }.st_size)
                        .map_err(|_| Refusal::InvalidRange)?,
                );
            }
            for (&index, alias) in group.image_indices.iter().zip(&group.aliases) {
                let address = usize::try_from(alias.start()).map_err(|_| Refusal::InvalidRange)?;
                let len = usize::try_from(alias.len()).map_err(|_| Refusal::InvalidRange)?;
                // SAFETY: MAP_FIXED_NOREPLACE cannot clobber an existing mapping.
                // The sealed file owns all initialized immutable bytes.
                let pointer = unsafe {
                    libc::mmap(
                        address as *mut libc::c_void,
                        len,
                        libc::PROT_READ | libc::PROT_EXEC,
                        libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                        backing.0,
                        0,
                    )
                };
                if pointer == libc::MAP_FAILED {
                    return Err(Refusal::AllocationUnavailable);
                }
                if pointer as usize != address {
                    // Older kernels may ignore MAP_FIXED_NOREPLACE. Reject and
                    // release an unintended mapping instead of accepting it.
                    // SAFETY: the returned mapping is owned by this call.
                    unsafe { libc::munmap(pointer, len) };
                    return Err(Refusal::AllocationUnavailable);
                }
                // SAFETY: this exact, fully initialized sealed RX extent is
                // owned exclusively here, has no published metadata or source
                // entries, and contains the image encoded for this alias.
                let pending = unsafe {
                    PendingExecutableTrampoline::from_owned_mapping(
                        &plan.images[index],
                        alias.start(),
                        len,
                    )
                };
                staged.push((index, pending));
            }
            backing.close()?;
        }
        staged.sort_unstable_by_key(|(index, _)| *index);
        Ok(StagedGrouping {
            images: staged.into_iter().map(|(_, image)| image).collect(),
            memory: plan.memory,
            #[cfg(test)]
            backing_file_bytes,
        })
    }

    fn os_error(operation: &str) -> Refusal {
        Refusal::Backend(format!("{operation}: {}", std::io::Error::last_os_error()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::scanner::InstructionScanner;
        use crate::trampoline::{TrampolinePlan, translate_program_counter};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        struct Mapping {
            address: *mut u8,
            len: usize,
        }

        impl Mapping {
            fn reserve(len: usize) -> Self {
                // SAFETY: anonymous private reservation with no executable or
                // writable access, exclusively owned by this fixture.
                let address = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        len,
                        libc::PROT_NONE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(address, libc::MAP_FAILED);
                Self {
                    address: address.cast(),
                    len,
                }
            }

            fn base(&self) -> u64 {
                self.address as usize as u64
            }

            fn release(mut self) -> u64 {
                let address = self.base();
                assert_eq!(unsafe { libc::munmap(self.address.cast(), self.len) }, 0);
                self.len = 0;
                address
            }
        }

        impl Drop for Mapping {
            fn drop(&mut self) {
                if self.len != 0 {
                    // SAFETY: fixture entries have drained before storage drops.
                    assert_eq!(unsafe { libc::munmap(self.address.cast(), self.len) }, 0);
                }
            }
        }

        fn image(source: &[u8], original: u64, generated: u64) -> TrampolineImage {
            let scan = InstructionScanner::default()
                .scan(source, original)
                .unwrap();
            TrampolinePlan::from_instruction(&scan, original)
                .unwrap()
                .emit_at(generated)
                .unwrap()
        }

        fn mapping_line(address: u64) -> (String, String, String) {
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            for line in maps.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                let (low, high) = fields[0].split_once('-').unwrap();
                if u64::from_str_radix(low, 16).unwrap() <= address
                    && address < u64::from_str_radix(high, 16).unwrap()
                {
                    return (
                        fields[1].to_owned(),
                        fields[2].to_owned(),
                        format!("{}:{}", fields[3], fields[4]),
                    );
                }
            }
            panic!("missing mapping at {address:#x}");
        }

        fn assert_group_fds_closed() {
            for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
                if let Ok(path) = std::fs::read_link(entry.unwrap().path()) {
                    assert!(!path.to_string_lossy().contains("liteinst2-immutable-group"));
                }
            }
        }

        fn measured_smaps(addresses: &[u64]) -> Result<(usize, u64, u64), String> {
            let smaps =
                std::fs::read_to_string("/proc/self/smaps").map_err(|error| error.to_string())?;
            let (mut vmas, mut rss, mut pss) = (0, 0, 0);
            let (mut rss_records, mut pss_records) = (0, 0);
            let mut selected = false;
            for line in smaps.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if let Some((low, high)) = fields.first().and_then(|field| field.split_once('-')) {
                    let low = u64::from_str_radix(low, 16).map_err(|error| error.to_string())?;
                    let high = u64::from_str_radix(high, 16).map_err(|error| error.to_string())?;
                    selected = addresses
                        .iter()
                        .any(|&address| low <= address && address < high);
                    if selected {
                        vmas += 1;
                    }
                } else if selected && matches!(fields.first(), Some(&"Rss:" | &"Pss:")) {
                    if fields.len() != 3 || fields[2] != "kB" {
                        return Err(format!("unrecognized smaps measurement: {line}"));
                    }
                    let amount = fields[1]
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?;
                    if fields[0] == "Rss:" {
                        rss += amount;
                        rss_records += 1;
                    } else {
                        pss += amount;
                        pss_records += 1;
                    }
                }
            }
            if vmas == 0 || rss_records != vmas || pss_records != vmas {
                return Err("incomplete smaps measurements for the selected aliases".into());
            }
            Ok((vmas, rss, pss))
        }

        fn assert_claimable(address: u64, len: usize) {
            // SAFETY: this verifies a vacated fixture range without replacement.
            let result = unsafe {
                libc::mmap(
                    address as usize as *mut libc::c_void,
                    len,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_eq!(result as usize as u64, address);
            assert_eq!(unsafe { libc::munmap(result, len) }, 0);
        }

        fn run_native() {
            let page = GROUPING_PAGE_BYTES;
            // Two original continuations intentionally produce different sums.
            let first = [0xb8, 37, 0, 0, 0, 0x83, 0xc0, 5, 0xc3];
            let second = [0xb8, 91, 0, 0, 0, 0x83, 0xc0, 7, 0xc3];
            let source = Mapping::reserve(page);
            assert_eq!(
                unsafe {
                    libc::mprotect(
                        source.address.cast(),
                        page,
                        libc::PROT_READ | libc::PROT_WRITE,
                    )
                },
                0
            );
            unsafe {
                core::ptr::copy_nonoverlapping(first.as_ptr(), source.address, first.len());
                core::ptr::copy_nonoverlapping(
                    second.as_ptr(),
                    source.address.add(32),
                    second.len(),
                );
            }
            assert_eq!(
                unsafe {
                    libc::mprotect(
                        source.address.cast(),
                        page,
                        libc::PROT_READ | libc::PROT_EXEC,
                    )
                },
                0
            );
            let aliases = Mapping::reserve(2 * page).release();
            let images = vec![
                image(&first, source.base(), aliases + 0x100),
                image(&second, source.base() + 32, aliases + page as u64 + 0x900),
            ];
            let plan = GroupingPlan::new(images.clone(), GroupingBudget::default()).unwrap();
            assert_eq!(plan.groups.len(), 1);
            assert_eq!(plan.groups[0].image_indices, [0, 1]);
            assert_eq!(
                plan.memory,
                GroupingMemory {
                    mappings: 2,
                    virtual_pages: 2,
                    backing_pages: 1,
                    virtual_bytes: (2 * page) as u64,
                    backing_bytes: page as u64,
                    virtual_span: (2 * page) as u64,
                }
            );

            // Exercise the actual backing constructor, all four kernel seals,
            // and both file and shared-mapping mutation paths.
            let backing = Backing::new(&plan, &plan.groups[0]).unwrap();
            assert_eq!(
                unsafe { libc::fcntl(backing.0, libc::F_GET_SEALS) },
                REQUIRED_SEALS
            );
            let byte = 0_u8;
            assert_eq!(
                unsafe { libc::pwrite(backing.0, (&raw const byte).cast(), 1, 0) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            for size in [page / 2, 2 * page] {
                assert_eq!(
                    unsafe { libc::ftruncate(backing.0, size as libc::off_t) },
                    -1
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EPERM)
                );
            }
            assert_eq!(unsafe { libc::fcntl(backing.0, libc::F_ADD_SEALS, 0) }, -1);
            let writer = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    backing.0,
                    0,
                )
            };
            assert_eq!(writer, libc::MAP_FAILED);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            backing.close().unwrap();
            assert_group_fds_closed();

            let staged = plan.stage().unwrap();
            assert_eq!(staged.memory(), plan.memory());
            assert_eq!(staged.backing_file_bytes, [page as u64]);
            let measured_file_bytes: u64 = staged.backing_file_bytes.iter().sum();
            assert_group_fds_closed();
            let map_a = mapping_line(aliases);
            let map_b = mapping_line(aliases + page as u64);
            assert_eq!(map_a.0, "r-xs");
            assert_eq!(map_b.0, "r-xs");
            assert_eq!(map_a.1, "00000000");
            assert_eq!(map_b.1, "00000000");
            assert_eq!(map_a.2, map_b.2, "aliases must share one backing inode");
            assert_eq!(
                unsafe {
                    libc::mprotect(
                        aliases as usize as *mut libc::c_void,
                        page,
                        libc::PROT_READ | libc::PROT_WRITE,
                    )
                },
                -1,
                "sealed shared code must not become writable"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EACCES)
            );
            assert_eq!(mapping_line(aliases).0, "r-xs");
            for image in &images {
                assert_eq!(translate_program_counter(image.address()), None);
            }
            let handles = staged.commit();
            for (handle, image) in handles.iter().zip(&images) {
                assert_eq!(handle.address(), image.address());
                assert_eq!(handle.code_len(), image.bytes().len());
                assert_eq!(
                    handle.program_counter_mappings(),
                    image.program_counter_mappings()
                );
                assert_eq!(handle.allocation_len(), page);
                handle.publish_program_counter_mappings();
                assert_eq!(
                    translate_program_counter(handle.address()),
                    handle.translate_program_counter(handle.address())
                );
                let actual = unsafe {
                    core::slice::from_raw_parts(
                        handle.address() as usize as *const u8,
                        handle.code_len(),
                    )
                };
                assert_eq!(actual, image.bytes());
            }
            // Both backing members are visible in both aliases, but only their
            // own encoded locations have valid entry and PC-map authority.
            let foreign_a = aliases + 0x900;
            let foreign_b = aliases + page as u64 + 0x100;
            assert_eq!(handles[0].translate_program_counter(foreign_a), None);
            assert_eq!(handles[1].translate_program_counter(foreign_b), None);
            assert_eq!(translate_program_counter(foreign_a), None);
            assert_eq!(translate_program_counter(foreign_b), None);
            unsafe {
                assert_eq!(
                    core::slice::from_raw_parts(
                        foreign_a as usize as *const u8,
                        images[1].bytes().len()
                    ),
                    images[1].bytes()
                );
                assert_eq!(
                    core::slice::from_raw_parts(
                        foreign_b as usize as *const u8,
                        images[0].bytes().len()
                    ),
                    images[0].bytes()
                );
                let call_a: extern "C" fn() -> u32 =
                    core::mem::transmute(handles[0].address() as usize);
                let call_b: extern "C" fn() -> u32 =
                    core::mem::transmute(handles[1].address() as usize);
                assert_eq!(call_a(), 42);
                assert_eq!(call_b(), 98);
                drop(handles);
                // Committed aliases and their reverse maps intentionally remain.
                assert_eq!(call_a(), 42);
                assert_eq!(call_b(), 98);
            }
            match measured_smaps(&[aliases, aliases + page as u64]) {
                Ok((vmas, rss, pss)) => println!(
                    "grouping_geometry: mappings=2 virtual_pages=2 backing_pages=1 virtual_bytes=8192 backing_bytes=4096 fstat_file_bytes={measured_file_bytes} alias_vmas={vmas} alias_rss_kib={rss} alias_pss_kib={pss}"
                ),
                Err(reason) => println!(
                    "grouping_geometry: mappings=2 virtual_pages=2 backing_pages=1 virtual_bytes=8192 backing_bytes=4096 fstat_file_bytes={measured_file_bytes} smaps_unavailable={reason}"
                ),
            }

            // Force a collision in a later backing group, after both aliases
            // of the first group have been staged. Every earlier alias must go.
            let rollback = Mapping::reserve(3 * page);
            let base = rollback.base();
            assert_eq!(unsafe { libc::munmap(rollback.address.cast(), page) }, 0);
            assert_eq!(
                unsafe { libc::munmap(rollback.address.add(2 * page).cast(), page) },
                0
            );
            let collision_images = vec![
                image(&first, source.base(), base + 0x100),
                image(&first, source.base(), base + page as u64 + 0x100),
                image(&second, source.base() + 32, base + 2 * page as u64 + 0x900),
            ];
            let collision = GroupingPlan::new(collision_images, GroupingBudget::default()).unwrap();
            assert_eq!(collision.groups.len(), 2);
            assert_eq!(collision.groups[0].image_indices, [0, 2]);
            assert_eq!(collision.groups[1].image_indices, [1]);
            assert!(matches!(
                collision.stage(),
                Err(Refusal::AllocationUnavailable)
            ));
            assert_claimable(base, page);
            assert_claimable(base + 2 * page as u64, page);
            assert_eq!(mapping_line(base + page as u64).0, "---p");
            assert_group_fds_closed();
            rollback.release();
            let retried = collision.stage().unwrap();
            assert_eq!(retried.memory().mappings, 3);
            assert_group_fds_closed();
            drop(retried);
            assert_claimable(base, 3 * page);
            // Rollback never published reverse maps.
            for image in collision.images() {
                assert_eq!(translate_program_counter(image.address()), None);
            }

            // A short image crossing the page boundary is still installed and
            // executed in its complete explicit dedicated backing.
            let crossing_base = Mapping::reserve(2 * page).release();
            let crossing = GroupingPlan::new(
                vec![image(
                    &first,
                    source.base(),
                    crossing_base + page as u64 - 4,
                )],
                GroupingBudget::default(),
            )
            .unwrap();
            assert_eq!(crossing.groups[0].kind, BackingKind::DedicatedImage);
            assert_eq!(crossing.memory.mappings, 1);
            assert_eq!(crossing.memory.virtual_pages, 2);
            assert_eq!(crossing.memory.backing_pages, 2);
            let handles = crossing.stage().unwrap().commit();
            let call: extern "C" fn() -> u32 =
                unsafe { core::mem::transmute(handles[0].address() as usize) };
            assert_eq!(call(), 42);
            assert_group_fds_closed();
            println!(
                "grouping-native-complete: shared aliases, dedicated crossing, seals, PC maps, rollback"
            );
        }

        #[test]
        fn native_grouped_images_seals_aliases_and_transactional_cleanup() {
            const CHILD: &str = "LITEINST2_GROUPING_NATIVE_CHILD";
            if std::env::var_os(CHILD).is_some() {
                run_native();
                return;
            }
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "grouping::native::tests::native_grouped_images_seals_aliases_and_transactional_cleanup", "--nocapture", "--test-threads=1"])
                .env(CHILD, "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // SAFETY: only async-signal-safe setrlimit runs before child exec.
            unsafe {
                command.pre_exec(|| {
                    for (resource, value) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_CPU, 10)] {
                        let limit = libc::rlimit {
                            rlim_cur: value,
                            rlim_max: value,
                        };
                        if libc::setrlimit(resource, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
            let mut child = command.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let output = child.wait_with_output().unwrap();
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert!(
                        status.success(),
                        "native grouping child failed: {status}\n{stdout}\n{stderr}"
                    );
                    assert!(
                        stdout.contains("grouping-native-complete:"),
                        "native child filter ran no fixture: {stdout}"
                    );
                    print!("{stdout}");
                    break;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("native grouping child exceeded 20 seconds");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::InstructionScanner;
    use crate::trampoline::{HookContext, TrampolinePlan};

    fn image(address: u64) -> TrampolineImage {
        let scan = InstructionScanner::default()
            .scan(&[0xb8, 7, 0, 0, 0, 0xc3], 0x10_0000)
            .unwrap();
        TrampolinePlan::from_instruction(&scan, 0x10_0000)
            .unwrap()
            .emit_at(address)
            .unwrap()
    }

    #[test]
    fn explicit_groups_cover_overlapping_offsets_and_multipage_images() {
        let images = vec![image(0x20_0100), image(0x22_0100), image(0x24_0900)];
        let plan = GroupingPlan::new(images.clone(), GroupingBudget::default()).unwrap();
        assert_eq!(plan.images(), images);
        assert_eq!(plan.groups().len(), 2);
        assert_eq!(plan.groups()[0].image_indices(), [0, 2]);
        assert_eq!(plan.groups()[1].image_indices(), [1]);
        assert_eq!(
            plan.memory(),
            GroupingMemory {
                mappings: 3,
                virtual_pages: 3,
                backing_pages: 2,
                virtual_bytes: 3 * 4096,
                backing_bytes: 2 * 4096,
                virtual_span: 0x41000,
            }
        );
        assert!(
            plan.groups()
                .iter()
                .all(|group| group.kind() == BackingKind::SharedPage)
        );
        assert!(matches!(
            GroupingPlan::new(
                vec![image(0x20_0100), image(0x20_0900)],
                GroupingBudget::default()
            ),
            Err(Refusal::OwnershipConflict)
        ));
        assert!(matches!(
            GroupingPlan::new(Vec::new(), GroupingBudget::default()),
            Err(Refusal::InvalidPlan)
        ));

        unsafe extern "C" fn noop(_: *mut HookContext) {}
        let code = vec![0x90; 64];
        let scan = InstructionScanner::default()
            .scan(&code, 0x10_0000)
            .unwrap();
        let actions: Vec<_> = (0..64)
            .map(|index| (0x10_0000 + index, noop as _, false))
            .collect();
        let large = TrampolinePlan::from_actions(&scan, 0x10_0000, 0x10_0040, &actions)
            .unwrap()
            .emit_at(0x30_0100)
            .unwrap();
        assert!(large.bytes().len() > GROUPING_PAGE_BYTES);
        let crossing = image(0x40_0ffc);
        assert!(crossing.bytes().len() <= GROUPING_PAGE_BYTES);
        let plan = GroupingPlan::new(
            vec![large.clone(), crossing.clone()],
            GroupingBudget::default(),
        )
        .unwrap();
        assert_eq!(plan.images(), [large, crossing]);
        assert_eq!(plan.groups().len(), 2);
        assert!(
            plan.groups()
                .iter()
                .all(|group| group.kind() == BackingKind::DedicatedImage)
        );
        assert_eq!(plan.groups()[0].image_indices(), [0]);
        assert_eq!(plan.groups()[1].image_indices(), [1]);
        assert_eq!(plan.groups()[1].backing_len(), 8192);
        assert_eq!(
            plan.groups()[1].aliases(),
            [AddressRange::new(0x40_0000, 8192).unwrap()]
        );
        assert_eq!(plan.memory().mappings, 2);
        assert!(plan.memory().virtual_pages > 2);
        assert_eq!(plan.memory().virtual_bytes, plan.memory().backing_bytes);
        assert_eq!(plan.memory().virtual_pages, plan.memory().backing_pages);
    }

    #[test]
    fn shared_backing_does_not_relax_any_virtual_or_physical_budget() {
        let images = vec![image(0x20_0100), image(0x24_0900)];
        let exact = GroupingBudget {
            max_mappings: 2,
            max_virtual_pages: 2,
            max_virtual_bytes: 8192,
            max_backing_bytes: 4096,
            max_virtual_span: 0x41000,
        };
        let accepted = GroupingPlan::new(images.clone(), exact).unwrap();
        assert_eq!(accepted.memory().backing_pages, 1);
        for budget in [
            GroupingBudget {
                max_mappings: 1,
                ..exact
            },
            GroupingBudget {
                max_virtual_pages: 1,
                ..exact
            },
            GroupingBudget {
                max_virtual_bytes: 8191,
                ..exact
            },
            GroupingBudget {
                max_backing_bytes: 4095,
                ..exact
            },
            GroupingBudget {
                max_virtual_span: 0x40fff,
                ..exact
            },
            GroupingBudget {
                max_mappings: 0,
                ..exact
            },
        ] {
            assert!(matches!(
                GroupingPlan::new(images.clone(), budget),
                Err(Refusal::AllocationUnavailable)
            ));
        }
        assert!(matches!(
            GroupingPlan::new(vec![image(0x20_0100), image(0x24_0100)], exact),
            Err(Refusal::AllocationUnavailable)
        ));
        assert!(matches!(
            GroupingPlan::new(vec![image(0x100)], GroupingBudget::default()),
            Err(Refusal::InvalidRange)
        ));
    }
}
