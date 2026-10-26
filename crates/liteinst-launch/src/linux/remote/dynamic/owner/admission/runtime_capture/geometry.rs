//! Byte windows are dependencies of a full VMA identity, never fabricated VMAs.
use super::*;

pub(super) const PAGE: u64 = 4096;
const LOOK_BEHIND: u64 = 14;
// RuntimeScan considers known heads up to target.end + 14 (exclusive).
// The last such head can consume 15 bytes, ending at target.end + 28.
const KNOWN_HEAD_END: u64 = 28;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VmaGeometry {
    pub(super) range: AddressRange,
    pub(super) before: Boundary,
    pub(super) after: Boundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WindowGeometry {
    pub(super) target: AddressRange,
    pub(super) snapshot: AddressRange,
    pub(super) head_scope: AddressRange,
    pub(super) before: Boundary,
    pub(super) after: Boundary,
}

impl WindowGeometry {
    pub(super) fn for_target(
        vma: VmaGeometry,
        target: AddressRange,
        maximum: usize,
    ) -> Result<Self, GateError> {
        if vma.range.start() == 0
            || vma.range.start() % PAGE != 0
            || vma.range.end() % PAGE != 0
            || target.start() % PAGE != 0
            || target.end() % PAGE != 0
            || !vma.range.covers(target)
            || maximum == 0
            || maximum > MAX_WINDOW_BYTES
        {
            return Err(refused("initial runtime window geometry differs"));
        }
        let first = target
            .start()
            .checked_sub(LOOK_BEHIND)
            .ok_or_else(|| refused("initial runtime lower decode closure overflows"))?;
        let head_end = target
            .end()
            .checked_add(LOOK_BEHIND)
            .ok_or_else(|| refused("initial runtime head scope overflows"))?;
        let last = target
            .end()
            .checked_add(KNOWN_HEAD_END)
            .ok_or_else(|| refused("initial runtime upper decode closure overflows"))?;
        if (first < vma.range.start() && vma.before == Boundary::Unknown)
            || (last > vma.range.end() && vma.after == Boundary::Unknown)
        {
            return Err(refused(
                "initial runtime cross-VMA decode closure is unqualified",
            ));
        }
        let snapshot = AddressRange::new(first.max(vma.range.start()), last.min(vma.range.end()))
            .ok_or_else(|| refused("initial runtime snapshot range differs"))?;
        if usize::try_from(snapshot.end() - snapshot.start())
            .ok()
            .is_none_or(|len| len > maximum)
        {
            return Err(refused("initial runtime decode closure exceeds its window"));
        }
        let head_scope =
            AddressRange::new(first.max(vma.range.start()), head_end.min(vma.range.end()))
                .ok_or_else(|| refused("initial runtime head scope differs"))?;
        Ok(Self {
            target,
            snapshot,
            head_scope,
            before: if snapshot.start() == vma.range.start() {
                vma.before
            } else {
                Boundary::Unknown
            },
            after: if snapshot.end() == vma.range.end() {
                vma.after
            } else {
                Boundary::Unknown
            },
        })
    }

    /// A whole scanner input must keep this exact range and both boundaries.
    /// This is not a coverage-plan, cross-VMA or publication certificate.
    pub(super) fn validate_snapshot(&self, snapshot: &Snapshot) -> Result<(), GateError> {
        if snapshot.range() != self.snapshot
            || snapshot.before != self.before
            || snapshot.after != self.after
            || snapshot.writes != WriteControl::Owned
        {
            return Err(refused(
                "initial runtime complete snapshot geometry differs",
            ));
        }
        Ok(())
    }
}

pub(super) fn target_stride(maximum: usize) -> Result<u64, GateError> {
    if maximum > MAX_WINDOW_BYTES {
        return Err(refused("initial runtime window bound differs"));
    }
    let usable = maximum
        .checked_sub((LOOK_BEHIND + KNOWN_HEAD_END) as usize)
        .ok_or_else(|| refused("initial runtime window cannot contain decode closure"))?;
    let pages = usable / PAGE as usize;
    if pages == 0 {
        return Err(refused(
            "initial runtime window cannot contain a whole target page",
        ));
    }
    Ok(pages as u64 * PAGE)
}

pub(super) fn next_target(
    vma: AddressRange,
    start: u64,
    stride: u64,
) -> Result<AddressRange, GateError> {
    if !vma.contains(start) || start % PAGE != 0 || stride == 0 || stride % PAGE != 0 {
        return Err(refused("initial runtime target partition differs"));
    }
    let end = start
        .checked_add(stride)
        .ok_or_else(|| refused("initial runtime target partition overflows"))?
        .min(vma.end());
    AddressRange::new(start, end).ok_or_else(|| refused("initial runtime empty target partition"))
}
