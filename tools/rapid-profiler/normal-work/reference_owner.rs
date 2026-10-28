//! Fixture-private owner for the four-argument fenced reference helper.
//! Distinct from the old three-argument CallerOwner; no public SDK admission.
use super::reference_bytes as bytes;
use super::{CallerError, FixtureOwner, FixtureSpec, Parsed, Result, parse_spec, require, sealed};
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolFlags, SymbolKind};
use std::path::Path;

struct Profile;
impl sealed::Sealed for Profile {}
impl FixtureSpec for Profile {
    fn name() -> &'static str {
        bytes::SYMBOL
    }
    fn symbol() -> &'static std::ffi::CStr {
        c"normal_reference_caller"
    }
    fn bytes() -> &'static [u8] {
        bytes::BYTES
    }
    fn body(code: &[u8]) -> Result<()> {
        bytes::validate_body(code).map_err(|_| CallerError::SourceBytes)
    }
    fn symbols(trusted: &[u8], entry: u64, file_offset: u64) -> Result<()> {
        validate_symbols(trusted, entry, file_offset)
    }
    fn parse(trusted: &[u8]) -> Result<Parsed> {
        parse_spec::<Self>(trusted)
    }
}

/// Check the separately trusted static symbol authority before opening/loading a
/// candidate. The common parser already authenticated the sole dynamic function,
/// exact RX segment/body, no dependencies/constructors/relocations and CET rules.
pub(super) fn validate_symbols(trusted: &[u8], entry: u64, file_offset: u64) -> Result<()> {
    let file = object::File::parse(trusted).map_err(|_| CallerError::Format)?;
    let functions: Vec<_> = file
        .symbols()
        .filter(|s| s.name() == Ok(bytes::SYMBOL))
        .collect();
    require(functions.len() == 1, CallerError::SymbolOwner)?;
    let function = &functions[0];
    require(
        function.is_definition()
            && function.kind() == SymbolKind::Text
            && function.address() == entry
            && function.size() == bytes::END
            && matches!(
                function.flags(),
                SymbolFlags::Elf {
                    st_info: 0x12,
                    st_other: 0
                }
            ),
        CallerError::SymbolOwner,
    )?;
    let section_index = function.section_index().ok_or(CallerError::SymbolOwner)?;
    let section = file
        .section_by_index(section_index)
        .map_err(|_| CallerError::Format)?;
    require(
        section.name() == Ok(".text")
            && section.address() == entry
            && section.size() == bytes::END
            && section.file_range() == Some((file_offset, bytes::END))
            && matches!(section.flags(), SectionFlags::Elf { sh_flags: 6 })
            && section.data().map_err(|_| CallerError::Format)? == bytes::BYTES,
        CallerError::SymbolOwner,
    )?;
    let mut seen = [false; bytes::LABELS.len()];
    let mut addresses = [0; bytes::LABELS.len()];
    for symbol in file.symbols() {
        let name = symbol.name().map_err(|_| CallerError::SymbolOwner)?;
        if name == bytes::SYMBOL {
            continue;
        }
        if let Some(k) = bytes::LABELS.iter().position(|&(label, _)| label == name) {
            // GNU ELF linkers may localize a hidden global to local DEFAULT or
            // local HIDDEN. All three cases are source-frozen here, never inferred
            // from candidate output. Exported/default globals and weak symbols fail.
            let hidden = matches!(
                symbol.flags(),
                SymbolFlags::Elf {
                    st_info: 0,
                    st_other: 0 | 2
                } | SymbolFlags::Elf {
                    st_info: 0x10,
                    st_other: 2
                }
            );
            require(
                !seen[k]
                    && symbol.is_definition()
                    && symbol.kind() == SymbolKind::Unknown
                    && hidden
                    && symbol.section_index() == Some(section_index)
                    && symbol.size() == 0
                    && entry.checked_add(bytes::LABELS[k].1) == Some(symbol.address()),
                CallerError::SymbolOwner,
            )?;
            seen[k] = true;
            addresses[k] = symbol.address();
        } else if name.starts_with("normal_reference_") {
            return Err(CallerError::SymbolOwner);
        } else if symbol.is_definition() && symbol.section_index() == Some(section_index) {
            // Only the optional standard local section symbol may share this
            // section beyond the closed function and named label set.
            require(
                symbol.kind() == SymbolKind::Section
                    && symbol.address() == entry
                    && symbol.size() == 0
                    && matches!(
                        symbol.flags(),
                        SymbolFlags::Elf {
                            st_info: 3,
                            st_other: 0
                        }
                    ),
                CallerError::SymbolOwner,
            )?;
        }
    }
    require(seen.into_iter().all(|x| x), CallerError::SymbolOwner)?;
    bytes::validate_layout(
        entry,
        &addresses,
        section.data().map_err(|_| CallerError::Format)?,
    )
    .map_err(|_| CallerError::SymbolOwner)
}

/// Thread-local owner, with process-lived fd/dlopen custody in the shared core.
/// It inherits !Send/!Sync from that core, without any unsafe trait implementation.
pub struct CallerOwner {
    inner: FixtureOwner<Profile>,
}
impl CallerOwner {
    /// Authenticate the complete independent reference ELF before dlopen.
    ///
    /// # Safety
    /// Trusted bytes are independent output of the pinned reference_caller.S and
    /// reviewed link command, never read from the candidate as expected authority.
    /// The loader, code and dependencies of the loader are trusted. No active CET,
    /// signals, fork, reentry, source/alias writer, mapping change or unload through
    /// last use. Loader operations occur before any helper calls. Each actual
    /// calling thread holds its own local owner and exclusive private cells/output;
    /// at most two controlled threads may share the immutable helper code. Their
    /// admitted target/profile must separately permit those two callers. Original
    /// versus installed publication remains quiescent and externally controlled.
    /// Loading is not hardware admission or permission to execute a timestamp.
    pub unsafe fn load(candidate: &Path, trusted: &[u8]) -> Result<Self> {
        // SAFETY: this private wrapper can select only the reference spec.
        let inner = unsafe { FixtureOwner::<Profile>::load(candidate, trusted) }?;
        let mut owner = Self { inner };
        owner.verify()?;
        Ok(owner)
    }
    pub fn entry(&self) -> u64 {
        self.inner.entry()
    }
    pub fn source(&self) -> (u64, &[u8]) {
        self.inner.source()
    }
    /// Exact mapped addresses of labels proved in the trusted complete ELF.
    /// Hidden labels are not guessed with dlsym: mapping identity/bias and complete
    /// live page equality transfer the authenticated symbol offsets to these PCs.
    pub fn labels(&self) -> Result<Vec<u64>> {
        bytes::LABELS
            .iter()
            .map(|&(_, offset)| {
                self.inner
                    .entry()
                    .checked_add(offset)
                    .ok_or(CallerError::SymbolOwner)
            })
            .collect()
    }
    /// Whole retained file, stamp, device/inode, dlsym/dladdr/link-map bias and
    /// complete live RX page checks. Continuous immutability remains required.
    pub fn verify(&mut self) -> Result<()> {
        self.inner.verify()?;
        let labels = self.labels()?;
        // SAFETY: retained loader owner and the permanent no-unmap/no-writer
        // contract; the common check just authenticated the complete live page.
        let code = unsafe {
            std::slice::from_raw_parts(self.inner.entry() as usize as *const u8, bytes::BYTES.len())
        };
        bytes::validate_layout(self.inner.entry(), &labels, code)
            .map_err(|_| CallerError::SourceBytes)
    }
    /// Raw four-argument fixture invocation; no source scan or checkpoint inside.
    ///
    /// # Safety
    /// All load obligations remain true. BEFORE this call, the actual calling
    /// thread must satisfy the exact existing ReferenceAmdV1 hardware predicate
    /// and singleton affinity, with stable hardware/CPU/user-TSC policy throughout.
    /// This method does not query or infer that admission. `target` is the retained
    /// admitted ordinary scalar leaf, called with the unchanged pointer/length ABI
    /// and normal returns. Requests, complete readable inputs, writable results,
    /// two fresh private cells, helper/target/generated pages, journal and full
    /// protected stack have the disjoint lifetime/custody required by reference_bytes.
    /// Fresh cells are used once, not exposed while either CALL is active, and all
    /// complete source/generated/input/cell postflight checks must pass after this
    /// real helper return before endpoints are published or a runtime checkpoint
    /// consumes pending receipts. No physical-return proof follows from phase2.
    /// Keep both code owners process-lived; this wrapper grants no reclamation,
    /// native eligibility, timing calibration or general ordinary-caller capability.
    pub unsafe fn invoke(
        &mut self,
        target: u64,
        requests: &[bytes::Request; 2],
        results: &mut [u64; 2],
        cells: &mut [bytes::ReferenceCell; 2],
    ) -> u64 {
        assert_eq!(self.inner.pid(), std::process::id());
        assert_ne!(target, 0);
        let caller: bytes::Caller = unsafe { std::mem::transmute(self.inner.entry() as usize) };
        let target: bytes::Target = unsafe { std::mem::transmute(target as usize) };
        let value = unsafe {
            caller(
                target,
                requests.as_ptr(),
                results.as_mut_ptr(),
                cells.as_mut_ptr(),
            )
        };
        // Actual post-call use prevents a tail transfer. A later native qualifier
        // must still authenticate the real enclosing CALL and outer RET itself.
        assert_eq!(value, results[0].wrapping_add(results[1]));
        value
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::*;
    const SYMTAB: usize = 0x3400;
    const STRTAB: usize = 0x3800;
    const LABEL_FIRST: usize = SYMTAB + 24;
    fn w(b: &mut [u8], at: usize, value: u64, width: usize) {
        b[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    fn image() -> Vec<u8> {
        // Reuse the literal existing pure ELF fixture; no compiler/candidate file.
        let mut b = super::super::tests::elf();
        b.resize(0x5000, 0);
        for at in [64 + 56 + 32, 64 + 56 + 40, 0x328, 0x3100 + 3 * 64 + 32] {
            w(&mut b, at, bytes::END, 8);
        }
        b[0x1000..0x1000 + bytes::BYTES.len()].copy_from_slice(bytes::BYTES);
        let name = b"\0normal_reference_caller\0";
        b[0x380..0x380 + name.len()].copy_from_slice(name);
        w(&mut b, 0x2f00 + 3 * 16 + 8, name.len() as u64, 8);
        w(&mut b, 0x3100 + 2 * 64 + 32, name.len() as u64, 8);
        let names = b"\0.dynsym\0.dynstr\0.text\0.dynamic\0.shstrtab\0.symtab\0.strtab\0";
        b[0x3050..0x3050 + names.len()].copy_from_slice(names);
        w(&mut b, 0x3100 + 5 * 64 + 32, names.len() as u64, 8);
        w(&mut b, 60, 8, 2);
        let mut strings = vec![0];
        // All local hidden labels precede the global function in the static table.
        for (k, &(label, offset)) in bytes::LABELS.iter().enumerate() {
            let at = LABEL_FIRST + k * 24;
            w(&mut b, at, strings.len() as u64, 4);
            strings.extend_from_slice(label.as_bytes());
            strings.push(0);
            b[at + 5] = 2;
            w(&mut b, at + 6, 3, 2);
            w(&mut b, at + 8, 0x1000 + offset, 8);
        }
        let function = LABEL_FIRST + bytes::LABELS.len() * 24;
        w(&mut b, function, strings.len() as u64, 4);
        strings.extend_from_slice(bytes::SYMBOL.as_bytes());
        strings.push(0);
        b[function + 4] = 0x12;
        w(&mut b, function + 6, 3, 2);
        w(&mut b, function + 8, 0x1000, 8);
        w(&mut b, function + 16, bytes::END, 8);
        assert!(STRTAB + strings.len() < b.len());
        b[STRTAB..STRTAB + strings.len()].copy_from_slice(&strings);
        for (i, name, kind, offset, size, link, info, align, entsize) in [
            (
                6,
                42,
                2,
                SYMTAB,
                (bytes::LABELS.len() + 2) * 24,
                7,
                bytes::LABELS.len() + 1,
                8,
                24,
            ),
            (7, 50, 3, STRTAB, strings.len(), 0, 0, 1, 0),
        ] {
            let at = 0x3100 + i * 64;
            for (delta, n, width) in [
                (0, name, 4),
                (4, kind, 4),
                (24, offset, 8),
                (32, size, 8),
                (40, link, 4),
                (44, info, 4),
                (48, align, 8),
                (56, entsize, 8),
            ] {
                w(&mut b, at + delta, n as u64, width);
            }
        }
        b
    }
    #[test]
    fn reference_owner_profiles_keep_exact_function_body_and_legacy_identity() {
        // Compile the exact private ABI surface without invoking a loader or code.
        let _: unsafe fn(&Path, &[u8]) -> Result<CallerOwner> = CallerOwner::load;
        let _: fn(&CallerOwner) -> u64 = CallerOwner::entry;
        let _: fn(&CallerOwner) -> (u64, &[u8]) = CallerOwner::source;
        let _: fn(&CallerOwner) -> Result<Vec<u64>> = CallerOwner::labels;
        let _: fn(&mut CallerOwner) -> Result<()> = CallerOwner::verify;
        type Invoke = unsafe fn(
            &mut CallerOwner,
            u64,
            &[bytes::Request; 2],
            &mut [u64; 2],
            &mut [bytes::ReferenceCell; 2],
        ) -> u64;
        let _: Invoke = CallerOwner::invoke;
        let legacy = super::super::tests::elf();
        assert!(parse(&legacy).is_ok());
        assert!(parse_spec::<Profile>(&legacy).is_err());
        let good = image();
        let p = parse_spec::<Profile>(&good).unwrap();
        assert_eq!(
            (p.entry, p.page_offset, p.source.len()),
            (0x1000, 0x1000, 4096)
        );
        assert_eq!(&p.source[..295], bytes::BYTES);
        assert!(parse(&good).is_err());
        let mut named_entry = good.clone();
        w(&mut named_entry, 24, 0x1000, 8);
        assert!(parse_spec::<Profile>(&named_entry).is_ok());
        for entry in [1, 0x1001, 0x1126, 0x2000, u64::MAX] {
            w(&mut named_entry, 24, entry, 8);
            assert!(parse_spec::<Profile>(&named_entry).is_err());
        }
        let function = LABEL_FIRST + bytes::LABELS.len() * 24;
        for (delta, value, width) in [
            (0, 0, 4),
            (4, 0x22, 1),
            (5, 2, 1),
            (6, 2, 2),
            (8, 0x1001, 8),
            (16, 294, 8),
        ] {
            let mut bad = good.clone();
            w(&mut bad, function + delta, value, width);
            assert!(
                parse_spec::<Profile>(&bad).is_err(),
                "function delta{delta}"
            );
        }
        let mut duplicate = good.clone();
        duplicate[LABEL_FIRST..LABEL_FIRST + 24].copy_from_slice(&good[function..function + 24]);
        assert!(parse_spec::<Profile>(&duplicate).is_err());
        for at in [0x380 + 1, 0x31c, 0x328, 0x1000, 0x1126] {
            let mut bad = good.clone();
            bad[at] ^= 1;
            assert!(parse_spec::<Profile>(&bad).is_err(), "{at:x}");
        }
    }
    #[test]
    fn reference_owner_all_hidden_labels_require_exact_shape_and_address() {
        let good = image();
        assert!(parse_spec::<Profile>(&good).is_ok());
        for k in 0..bytes::LABELS.len() {
            let at = LABEL_FIRST + k * 24;
            for (delta, value, width) in [
                (4, 0x20, 1),
                (4, 0x02, 1),
                (5, 1, 1),
                (5, 3, 1),
                (6, 2, 2),
                (6, 0, 2),
                (8, 0x1001 + bytes::LABELS[k].1, 8),
                (16, 1, 8),
            ] {
                let mut bad = good.clone();
                w(&mut bad, at + delta, value, width);
                assert!(
                    parse_spec::<Profile>(&bad).is_err(),
                    "label{k} delta{delta}"
                );
            }
            let mut missing = good.clone();
            w(&mut missing, at, 0, 4);
            assert!(parse_spec::<Profile>(&missing).is_err());
        }
        // Duplicating one name loses a different required label and fails even
        // when its value is also coherently changed to the duplicated address.
        let mut duplicate = good.clone();
        duplicate[LABEL_FIRST + 24..LABEL_FIRST + 48]
            .copy_from_slice(&good[LABEL_FIRST..LABEL_FIRST + 24]);
        assert!(parse_spec::<Profile>(&duplicate).is_err());
        let mut exported = good.clone();
        exported[LABEL_FIRST + 4] = 0x10;
        exported[LABEL_FIRST + 5] = 0;
        assert!(parse_spec::<Profile>(&exported).is_err());
    }
    #[test]
    fn reference_owner_linker_localization_is_closed_not_candidate_selected() {
        let good = image();
        assert!(parse_spec::<Profile>(&good).is_ok());
        let mut local_default = good.clone();
        for k in 0..bytes::LABELS.len() {
            local_default[LABEL_FIRST + k * 24 + 5] = 0;
        }
        assert!(parse_spec::<Profile>(&local_default).is_ok());
        let mut global_hidden = good.clone();
        for k in 0..bytes::LABELS.len() {
            global_hidden[LABEL_FIRST + k * 24 + 4] = 0x10;
        }
        w(&mut global_hidden, 0x3100 + 6 * 64 + 44, 1, 4);
        assert!(parse_spec::<Profile>(&global_hidden).is_ok());
        for raw in [0x01, 0x03, 0x11, 0x12, 0x20, 0x22, 0x30, 0xff] {
            let mut bad = good.clone();
            bad[LABEL_FIRST + 4] = raw;
            assert!(parse_spec::<Profile>(&bad).is_err());
        }
    }
    #[test]
    fn reference_owner_retains_segment_dynamic_cet_and_section_refusals() {
        let good = image();
        assert!(parse_spec::<Profile>(&good).is_ok());
        for (at, value, width) in [
            (18, 3, 2),
            (64 + 56 + 4, 7, 4),
            (64 + 56 + 16, 0x1001, 8),
            (64 + 56 + 32, 294, 8),
            (64 + 56 + 40, 296, 8),
            (64 + 4 * 56 + 4, 7, 4),
            (0x2f00, 1, 8),
            (0x3100 + 3 * 64 + 8, 7, 8),
            (0x3100 + 3 * 64 + 24, 0x1100, 8),
            (0x3100 + 3 * 64 + 32, 294, 8),
            (0x3100 + 6 * 64 + 4, 0, 4),
        ] {
            let mut bad = good.clone();
            w(&mut bad, at, value, width);
            assert!(parse_spec::<Profile>(&bad).is_err(), "{at:x}");
        }
        assert!(parse_spec::<Profile>(&good[..0x1100]).is_err());
    }
}
