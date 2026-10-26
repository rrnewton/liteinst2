//! Pure map identity models, not native executable or head authority.
use super::*;

const ORIGINAL: &str = concat!(
    "00400000-00430000 r-xp 00000000 08:01 100 /objects/main  image\n",
    "00430000-00431000 r-xp 00000000 08:02 200 /objects/adjacent\n",
    "00600000-00601000 rw-p 00000000 00:00 0 [stack]\n",
);
fn descriptor(row: MapEntry<'_>) -> MemoryMapping {
    MemoryMapping {
        start: row.start,
        end: row.end,
        file_offset: row.file_offset,
        permissions: std::str::from_utf8(&row.permissions.bytes())
            .unwrap()
            .to_owned(),
        pathname: row
            .pathname
            .map(|p| std::str::from_utf8(p).unwrap().to_owned()),
    }
}
fn with_inventory<T>(call: impl FnOnce(SourceInventory<'_>, &[u8], &[u8]) -> T) -> T {
    let final_maps = ORIGINAL.replace("r-xp", "r--p") + "00800000-00801000 r-xp 00000000 00:00 0\n";
    let old = parse(ORIGINAL.as_bytes()).unwrap();
    let new = parse(final_maps.as_bytes()).unwrap();
    let originals: Vec<_> = old
        .entries()
        .filter(|row| row.permissions.bytes()[2] == b'x')
        .map(descriptor)
        .collect();
    let current: Vec<_> = new.entries().map(descriptor).collect();
    let entry = EntryEvidence {
        first_image: FirstImage::Executable,
        executable_entry: 0x401000,
        initial_instruction: 0x401000,
        interpreter: None,
        interpreter_base: 0,
    };
    let inventory = SourceInventory::new(
        old,
        new,
        &SourceGeometry {
            originals: &originals,
            current: &current,
            island: &(0x800000..0x801000),
            entry: &entry,
            executable: FileIdentity {
                major: 8,
                minor: 1,
                inode: 100,
            },
        },
    )
    .unwrap();
    call(inventory, ORIGINAL.as_bytes(), final_maps.as_bytes())
}

#[test]
fn source_inventory_keeps_whole_vma_and_original_executable_neighbors() {
    with_inventory(|inventory, original, quarantine| {
        let mut rows = Vec::with_capacity(1);
        inventory.collect(&mut rows, 1).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].end - rows[0].start, 3 * MAP_BYTES as u64);
        let view = rows[0].view(original, quarantine).unwrap();
        assert_eq!(view.original.permissions.bytes(), *b"r-xp");
        assert_eq!(view.quarantined.permissions.bytes(), *b"r--p");
        assert_eq!(
            view.original.pathname,
            Some(b"/objects/main  image".as_slice())
        );
        assert_eq!(view.upper_original.unwrap().permissions.bytes(), *b"r-xp");
        assert_eq!(
            view.upper_quarantined.unwrap().permissions.bytes(),
            *b"r--p"
        );
        assert!(view.lower_original.is_none());
        assert!(view.lower_quarantined.is_none());
        // The original X neighbor is retained; imposed NX cannot prove a
        // non-executable window boundary. Window policy is the caller's gate.
        let changed = String::from_utf8(quarantine.to_vec())
            .unwrap()
            .replace("08:01", "08:03");
        assert!(matches!(
            rows[0].view(original, changed.as_bytes()),
            Err(GateError::Refused(
                "exec source receipt raw identity differs"
            ))
        ));
    });
}

#[test]
fn source_inventory_requires_preallocated_pristine_bounded_row_storage() {
    with_inventory(|inventory, _, _| {
        let mut none = Vec::new();
        assert!(inventory.collect(&mut none, 1).is_err());
        assert!(none.is_empty());
        let mut rows = Vec::with_capacity(1);
        for max in [0, MAP_ROWS + 1] {
            assert!(inventory.collect(&mut rows, max).is_err());
            assert!(rows.is_empty());
        }
        inventory.collect(&mut rows, 1).unwrap();
        let before = rows.clone();
        assert!(inventory.collect(&mut rows, 1).is_err());
        assert_eq!(rows, before);
    });
}
