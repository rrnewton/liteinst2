//! Checked access to the PKRU component consumed by this invocation's XRSTOR.

use super::{
    ExecutableTrampoline, HookContext, InstalledHook, PKRU_XFEATURE, PRESERVED_USER_STATE_MASK,
    SAVED_EXTENDED_STATE_COMPONENT_CAPACITY, SavedExtendedStateComponent,
    SavedExtendedStateDescriptor, SavedExtendedStateFormat, SavedExtendedStateLayout,
    TrampolineError,
};
use core::sync::atomic::{Ordering, compiler_fence};

const XSTATE_BV: usize = 512;
const XCOMP_BV: usize = 520;
const HEADER_END: usize = 576;

/// One callback's checked, borrowed saved-PKRU value.
///
/// Dropping the view leaves the image unchanged. Read and drop it before Tool
/// dispatch, then obtain a fresh view for an explicit return-image commit.
/// This does not open live Tool permissions or move the earlier capture frame.
pub struct SavedPkruView<'invocation> {
    context: &'invocation mut HookContext,
    trampoline: &'invocation ExecutableTrampoline,
    value: u32,
}

impl SavedPkruView<'_> {
    /// Returns interrupted PKRU, including the architectural init value zero
    /// when this standard image's XSTATE_BV does not contain bit 9.
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// Commits the explicit PKRU value consumed by the actual return's XRSTOR.
    ///
    /// The descriptor, retained layout and header are checked again before any
    /// write. Unrelated components and header bits are preserved. The caller
    /// must choose rights that permit the remaining restore-frame reads: this
    /// API does not repair the XRSTOR-before-GPR-pop transport limitation.
    pub fn commit(self, value: u32) -> Result<(), TrampolineError> {
        let geometry = geometry(
            self.context as *mut HookContext as usize as u64,
            self.context.saved_extended_state(),
            self.trampoline.layout().saved_extended_state,
        )?
        .ok_or_else(|| invalid("saved PKRU became unavailable before commit"))?;
        let pkru_offset = geometry
            .pkru_offset
            .ok_or_else(|| invalid("saved PKRU became unavailable before commit"))?;
        // SAFETY: construction borrowed this genuine invocation and its live,
        // exclusive save area. Geometry is revalidated without widening it.
        let present = unsafe { checked_header(geometry)? };
        let base = geometry.address as usize as *mut u8;
        // SAFETY: exactly the validated eight-byte PKRU component is written;
        // its reserved upper word is initialized to zero, never read uninit.
        unsafe {
            base.add(pkru_offset).cast::<u32>().write_volatile(value);
            base.add(pkru_offset + 4).cast::<u32>().write_volatile(0);
        }
        compiler_fence(Ordering::Release);
        // SAFETY: encode_save initialized this whole header; presence is
        // published only after both component words have been written.
        unsafe {
            base.add(XSTATE_BV)
                .cast::<u64>()
                .write_volatile(present | PKRU_XFEATURE);
        }
        Ok(())
    }
}

impl ExecutableTrampoline {
    /// Borrows the saved PKRU image of this trampoline's current callback.
    ///
    /// FXSAVE and exact-syscall layouts report `None`, without executing a PKRU
    /// instruction or inventing guest rights. Malformed/unavailable descriptors
    /// are errors. An absent bit 9 in a PKRU-bearing image means init PKRU zero.
    ///
    /// # Safety
    ///
    /// `context` must be the unique live HookContext passed by this retained
    /// trampoline to the current callback, not a copied/synthesized context.
    /// Its actual save allocation must remain mapped and exclusively accessible
    /// through this borrow until the view is dropped or consumed. Invocation
    /// provenance is this existing unsafe contract, not descriptor equality.
    /// The callback must not unwind through emitted code. No mutable image view
    /// may be retained across dispatch or beyond this callback.
    pub unsafe fn saved_pkru_view<'invocation>(
        &'invocation self,
        context: &'invocation mut HookContext,
    ) -> Result<Option<SavedPkruView<'invocation>>, TrampolineError> {
        let Some(geometry) = geometry(
            context as *mut HookContext as usize as u64,
            context.saved_extended_state(),
            self.layout().saved_extended_state,
        )?
        else {
            return Ok(None);
        };
        // SAFETY: forwarded from the genuine invocation/save-area contract.
        let present = unsafe { checked_header(geometry)? };
        let Some(pkru_offset) = geometry.pkru_offset else {
            return Ok(None);
        };
        let value = if present & PKRU_XFEATURE == 0 {
            // The component can contain stale/uninitialized bytes. XRSTOR uses
            // init PKRU zero instead, so do not read those bytes.
            0
        } else {
            // SAFETY: XSAVE initialized this selected, present four-byte field.
            unsafe {
                (geometry.address as usize as *const u8)
                    .add(pkru_offset)
                    .cast::<u32>()
                    .read_volatile()
            }
        };
        Ok(Some(SavedPkruView {
            context,
            trampoline: self,
            value,
        }))
    }
}

impl InstalledHook {
    /// Borrows this installed hook's actual per-invocation saved PKRU.
    ///
    /// # Safety
    ///
    /// The invocation/lifetime requirements of
    /// [`ExecutableTrampoline::saved_pkru_view`] apply to this hook's retained
    /// trampoline. Do not substitute a different hook or copied context.
    pub unsafe fn saved_pkru_view<'invocation>(
        &'invocation self,
        context: &'invocation mut HookContext,
    ) -> Result<Option<SavedPkruView<'invocation>>, TrampolineError> {
        // SAFETY: forwarded from this method's corresponding-hook contract.
        unsafe { self.trampoline().saved_pkru_view(context) }
    }
}

#[derive(Clone, Copy)]
struct Geometry {
    address: u64,
    mask: u64,
    pkru_offset: Option<usize>,
}

fn invalid(message: &'static str) -> TrampolineError {
    TrampolineError::InvalidExtendedStateLayout { message }
}

fn require(condition: bool, message: &'static str) -> Result<(), TrampolineError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

// No memory access occurs until every layout, descriptor and frame check passes.
fn geometry(
    context_address: u64,
    descriptor: SavedExtendedStateDescriptor,
    layout: SavedExtendedStateLayout,
) -> Result<Option<Geometry>, TrampolineError> {
    require(
        descriptor.matches_layout(layout) && !descriptor.is_empty(),
        "saved-state descriptor does not match the retained trampoline",
    )?;
    let alignment = layout
        .format()
        .required_alignment()
        .ok_or_else(|| invalid("saved-state format is unavailable"))?;
    require(
        context_address != 0 && context_address % core::mem::align_of::<HookContext>() as u64 == 0,
        "saved-state context is unaligned or unavailable",
    )?;
    context_address
        .checked_add(core::mem::size_of::<HookContext>() as u64)
        .ok_or_else(|| invalid("saved-state context extent overflows"))?;
    let frame_end = context_address & !(alignment - 1);
    let expected = frame_end
        .checked_sub(layout.len())
        .ok_or_else(|| invalid("saved-state frame address underflows"))?;
    require(
        expected != 0
            && descriptor.address() == expected
            && descriptor.address() % alignment == 0
            && descriptor.address().checked_add(layout.len()) == Some(frame_end),
        "saved-state address is not the emitted invocation frame",
    )?;
    if layout.format() == SavedExtendedStateFormat::FXSAVE64 {
        require(
            layout == SavedExtendedStateLayout::FXSAVE64,
            "malformed FXSAVE layout",
        )?;
        return Ok(None);
    }
    require(
        layout.format() == SavedExtendedStateFormat::XSAVE64_STANDARD
            && layout.mask() & 3 == 3
            && layout.mask() & !PRESERVED_USER_STATE_MASK == 0
            && layout.image_len() >= HEADER_END as u64
            && layout.len() <= i32::MAX as u64,
        "malformed standard XSAVE extent or mask",
    )?;
    let padded = layout
        .image_len()
        .checked_add(63)
        .ok_or_else(|| invalid("saved-state padding overflows"))?
        & !63;
    require(
        layout.len() == padded,
        "saved-state padding does not match the image extent",
    )?;
    let count = usize::try_from(layout.component_count)
        .map_err(|_| invalid("saved-state component count overflows"))?;
    require(
        count <= SAVED_EXTENDED_STATE_COMPONENT_CAPACITY,
        "saved-state component count is too large",
    )?;
    let mut selected = 3_u64;
    let mut image_end = HEADER_END as u64;
    let mut pkru = None;
    for (index, component) in layout.components[..count].iter().copied().enumerate() {
        let bit = component.xfeature();
        let end = component
            .offset()
            .checked_add(component.size())
            .ok_or_else(|| invalid("saved-state component extent overflows"))?;
        require(
            bit.is_power_of_two()
                && bit & 3 == 0
                && bit & layout.mask() != 0
                && bit & selected == 0
                && component.size() != 0
                && component.offset() >= HEADER_END as u64
                && end <= layout.image_len(),
            "invalid or truncated saved-state component",
        )?;
        for earlier in &layout.components[..index] {
            let earlier_end = earlier
                .offset()
                .checked_add(earlier.size())
                .ok_or_else(|| invalid("saved-state component extent overflows"))?;
            require(
                end <= earlier.offset() || earlier_end <= component.offset(),
                "saved-state components overlap",
            )?;
        }
        selected |= bit;
        image_end = image_end.max(end);
        if bit == PKRU_XFEATURE {
            require(
                component.size() == 8 && component.offset() % 8 == 0,
                "malformed standard PKRU component",
            )?;
            pkru = Some(component.offset() as usize);
        }
    }
    require(
        selected == layout.mask()
            && image_end == layout.image_len()
            && layout.components[count..]
                .iter()
                .all(|c| *c == SavedExtendedStateComponent::UNAVAILABLE),
        "saved-state component table does not cover the exact retained layout",
    )?;
    Ok(Some(Geometry {
        address: expected,
        mask: layout.mask(),
        pkru_offset: pkru,
    }))
}

// Read only the initialized standard header, never a slice of the entire image.
unsafe fn checked_header(geometry: Geometry) -> Result<u64, TrampolineError> {
    let base = geometry.address as usize as *const u8;
    // SAFETY: geometry bound the live image and its initialized 64-byte header.
    let present = unsafe { base.add(XSTATE_BV).cast::<u64>().read_volatile() };
    let compacted = unsafe { base.add(XCOMP_BV).cast::<u64>().read_volatile() };
    require(
        present & !geometry.mask == 0 && compacted == 0,
        "saved XSAVE header has an invalid presence or compacted mask",
    )?;
    for offset in (XCOMP_BV + 8..HEADER_END).step_by(8) {
        // SAFETY: encode_save initializes each reserved header word to zero.
        require(
            unsafe { base.add(offset).cast::<u64>().read_volatile() } == 0,
            "saved XSAVE header has nonzero reserved bytes",
        )?;
    }
    if present & PKRU_XFEATURE != 0 {
        let pkru_offset = geometry
            .pkru_offset
            .ok_or_else(|| invalid("saved PKRU presence has no retained component"))?;
        // SAFETY: encode_save explicitly initializes the reserved upper word.
        require(
            unsafe { base.add(pkru_offset + 4).cast::<u32>().read_volatile() } == 0,
            "saved PKRU component has nonzero reserved bytes",
        )?;
    }
    Ok(present)
}

#[cfg(any(test, feature = "saved-pkru-probe"))]
mod fixtures;
#[cfg(feature = "saved-pkru-probe")]
mod probe;
#[cfg(feature = "saved-pkru-probe")]
pub use probe::run_saved_pkru_physical_probe;
#[cfg(test)]
mod tests;
