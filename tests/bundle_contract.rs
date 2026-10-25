#![deny(warnings)]
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
//! Bounded native two-image publication and transactional-failure fixtures.
use liteinst2::bundle::{BundleBudget, PlannedBundle, WritableAlias};
use liteinst2::contracts::*;
use liteinst2::grouping::{BackingKind, GroupingBudget};
use liteinst2::planner::HookSemantics;
use liteinst2::quiescent::{
    AllocationPolicy, InstallRequest, PlannedInstall, SearchPolicy, TacticPolicy, plan_install,
};
use liteinst2::trampoline::HookContext;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static HOOKS: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" fn observe(_: *mut HookContext) {
    HOOKS.fetch_add(1, Ordering::Relaxed);
}
const ADDRESS: u64 = 0x2600_0000_0000;
const ENV: &str = "LITEINST_BUNDLE_CONTRACT_CHILD";

struct Fixture {
    write: *mut u8,
    execute: *mut u8,
    originals: Vec<ExpectedBytes>,
    identity: CodeIdentity,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        // SAFETY: child exclusively owns fresh aliases, with no executable users yet.
        let (write, execute) = unsafe {
            let fd = libc::memfd_create(c"bundle-contract".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, 4096), 0);
            let w = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            let x = libc::mmap(
                ADDRESS as *mut _,
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                fd,
                0,
            );
            assert_ne!(w, libc::MAP_FAILED);
            assert_ne!(x, libc::MAP_FAILED);
            assert_eq!(libc::close(fd), 0);
            (w.cast::<u8>(), x.cast::<u8>())
        };
        let originals = vec![
            ExpectedBytes {
                address: ADDRESS + 0x100,
                bytes: if mode == "evex-lock" {
                    let mut bytes = vec![
                        0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x90, 0xb8, 0x21, 0x43, 0x65, 0x07, 0xc3,
                    ];
                    bytes.resize(32, 0x90);
                    bytes
                } else if mode == "router" {
                    vec![0x90, 0xb8, 0x21, 0x43, 0x65, 0x07, 0xc3]
                } else {
                    vec![0xb8, 0x21, 0x43, 0x65, 0x07, 0xc3]
                },
            },
            ExpectedBytes {
                address: ADDRESS + 0x180,
                bytes: vec![0x66, 0x90, 0xb8, 0x03, 0x02, 0x10, 0x00, 0xc3],
            },
        ];
        for read in &originals {
            // SAFETY: exact checked offsets in the private writable page.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    read.bytes.as_ptr(),
                    write.add((read.address - ADDRESS) as usize),
                    read.bytes.len(),
                )
            };
        }
        Self {
            write,
            execute,
            originals,
            identity: CodeIdentity {
                source: SourceIdentity([41; 32]),
                mapping: 41,
                generation: 1,
            },
        }
    }
    fn members(&self) -> Vec<PlannedInstall> {
        let mut members = Vec::new();
        for (index, source) in self.originals.iter().enumerate() {
            let scope = AddressRange::new(source.address, source.bytes.len()).unwrap();
            let entries = LegalEntrySet {
                identity: self.identity,
                scope,
                provenance: EntryProvenance::Declared("two-image private fixture".into()),
                completeness: EntryCompleteness::AllInstructionHeads,
                entries: vec![],
                resumes: ResumeObligation::NoneExist,
            };
            let mut allocation = AllocationPolicy::near(source.address).unwrap();
            if index == 0 {
                allocation.preferred_address = Some(ADDRESS + 0x10_0000);
            }
            let evex_tail = index == 0 && source.bytes[0] == 0x48;
            let member = plan_install(&InstallRequest {
                identity: self.identity,
                code: &source.bytes,
                base_address: source.address,
                function: scope,
                block: if evex_tail {
                    AddressRange::new(source.address, 8).unwrap()
                } else {
                    scope
                },
                logical_pc: source.address + if evex_tail { 7 } else { 0 },
                entries: &entries,
                hook: observe,
                semantics: HookSemantics::Observe,
                allocation: &allocation,
                search: SearchPolicy {
                    tactics: if index == 0 {
                        TacticPolicy::RelocationOnly
                    } else {
                        TacticPolicy::GeneralizedPunOnly
                    },
                    ..SearchPolicy::default()
                },
            })
            .unwrap();
            assert_eq!(
                matches!(member.plan().parts().kind, PlanKind::GeneralizedPun(_)),
                index == 1
            );
            members.push(member);
        }
        members
    }
    fn bundle(&self) -> PlannedBundle {
        PlannedBundle::compose(
            self.originals.clone(),
            self.members(),
            BundleBudget::default(),
        )
        .unwrap()
    }
    fn conflicting_successor(&self) -> PlannedInstall {
        let address = self.originals[0].address + 8;
        let bytes = &self.originals[0].bytes[8..];
        let scope = AddressRange::new(address, bytes.len()).unwrap();
        let entries = LegalEntrySet {
            identity: self.identity,
            scope,
            provenance: EntryProvenance::Declared("verified successor of qualified marker".into()),
            completeness: EntryCompleteness::AllInstructionHeads,
            entries: vec![],
            resumes: ResumeObligation::NoneExist,
        };
        let mut allocation = AllocationPolicy::near(address).unwrap();
        allocation.preferred_address = Some(address + 5 + 0x20_0004);
        let plan = plan_install(&InstallRequest {
            identity: self.identity,
            code: bytes,
            base_address: address,
            function: scope,
            block: scope,
            logical_pc: address,
            entries: &entries,
            hook: observe,
            semantics: HookSemantics::Observe,
            allocation: &allocation,
            search: SearchPolicy {
                tactics: TacticPolicy::RelocationOnly,
                ..SearchPolicy::default()
            },
        })
        .unwrap();
        assert_ne!(plan.plan().parts().writes[0].bytes[1] & 4, 0);
        plan
    }
    fn alias(&self) -> WritableAlias {
        // SAFETY: both aliases share this child's exclusively owned original page.
        unsafe { WritableAlias::new(AddressRange::new(ADDRESS, 4096).unwrap(), self.write) }
            .unwrap()
    }
    fn held(&self) -> Vec<AddressRange> {
        self.originals
            .iter()
            .map(|s| AddressRange::new(s.address, s.bytes.len()).unwrap())
            .collect()
    }
    fn check(&self, bytes: &[ExpectedBytes]) {
        for expected in bytes {
            // SAFETY: private mapping with no concurrent executor/writer.
            assert_eq!(
                unsafe {
                    std::slice::from_raw_parts(
                        self.write.add((expected.address - ADDRESS) as usize),
                        expected.bytes.len(),
                    )
                },
                expected.bytes
            );
        }
    }
    fn calls(&self, expected_hooks: usize) {
        let before = HOOKS.load(Ordering::Relaxed);
        let mut entries = vec![
            (ADDRESS + 0x100, 0x0765_4321_u32),
            (ADDRESS + 0x180, 0x0010_0203),
            (ADDRESS + 0x182, 0x0010_0203),
        ];
        if self.originals[0].bytes[0] == 0x90 {
            entries.push((ADDRESS + 0x101, 0x0765_4321));
        }
        if self.originals[0].bytes[0] == 0x48 {
            entries.push((ADDRESS + 0x107, 0x0765_4321));
        }
        for (address, expected) in entries {
            // SAFETY: these private verified fixtures have u32(void) ABI and no active mutation.
            let call: unsafe extern "C" fn() -> u32 =
                unsafe { std::mem::transmute(address as usize) };
            assert_eq!(unsafe { call() }, expected);
        }
        assert_eq!(HOOKS.load(Ordering::Relaxed) - before, expected_hooks);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: each scenario drains all calls before dropping the fixture.
        unsafe {
            assert_eq!(libc::munmap(self.write.cast(), 4096), 0);
            assert_eq!(libc::munmap(self.execute.cast(), 4096), 0);
        }
    }
}

// Additive grouping fixtures keep the original transaction scenarios below intact.
fn all_body_entries(expected_hooks: usize) {
    let before = HOOKS.load(Ordering::Relaxed);
    for (address, expected) in [
        (ADDRESS + 0x100, 0x0765_4321_u64),
        (ADDRESS + 0x105, 0x0765_4321),
        (ADDRESS + 0x180, 0x0010_0203),
        (ADDRESS + 0x182, 0x0010_0203),
        (ADDRESS + 0x187, 0x0010_0203),
    ] {
        let actual: u64;
        // SAFETY: only this child can execute these verified MOV/NOP/RET heads.
        // Seed RAX so direct RET entry has a defined observable result too.
        unsafe {
            core::arch::asm!(
                "call r11",
                in("r11") address,
                inlateout("rax") expected => actual,
                clobber_abi("C"),
            );
        }
        assert_eq!(actual, expected, "entry {address:#x}");
    }
    assert_eq!(HOOKS.load(Ordering::Relaxed) - before, expected_hooks);
}

fn full_source(fixture: &Fixture) -> Vec<u8> {
    // SAFETY: the complete source page is owned and no concurrent writer exists.
    unsafe { std::slice::from_raw_parts(fixture.write, 4096) }.to_vec()
}

fn final_source(original: &[u8], bundle: &PlannedBundle) -> Vec<u8> {
    let mut final_bytes = original.to_vec();
    for source in bundle.plan().final_bytes() {
        let offset = (source.address - ADDRESS) as usize;
        final_bytes[offset..offset + source.bytes.len()].copy_from_slice(&source.bytes);
    }
    final_bytes
}

fn grouped_bundle(fixture: &Fixture) -> PlannedBundle {
    PlannedBundle::compose_grouped(
        fixture.originals.clone(),
        fixture.members(),
        BundleBudget::default(),
        GroupingBudget::default(),
    )
    .unwrap()
}

fn assert_grouped_plan(bundle: &PlannedBundle) {
    let grouping = bundle
        .grouping()
        .expect("grouping metadata must be retained");
    assert_eq!(grouping.groups().len(), 1);
    let group = &grouping.groups()[0];
    assert_eq!(group.kind(), BackingKind::SharedPage);
    assert_eq!(group.image_indices(), &[0, 1]);
    assert_eq!(group.backing_len(), 4096);
    let aliases: Vec<_> = bundle
        .plan()
        .steps()
        .iter()
        .map(|step| {
            assert_eq!(step.parts().allocations.len(), 1);
            step.parts().allocations[0].range
        })
        .collect();
    assert_eq!(group.aliases(), aliases);
    assert_eq!(aliases.len(), 2);
    assert!(!aliases[0].overlaps(aliases[1]));
    assert!(aliases.iter().all(|range| range.len() == 4096));
    let offsets: Vec<_> = bundle
        .images()
        .iter()
        .map(|image| AddressRange::new(image.address() % 4096, image.bytes().len()).unwrap())
        .collect();
    assert!(
        !offsets[0].overlaps(offsets[1]),
        "required images must share backing"
    );
    assert!(offsets.iter().all(|range| range.end() <= 4096));
    assert_eq!(bundle.plan().memory().mappings, 2);
    assert_eq!(bundle.plan().memory().virtual_bytes, 8192);
    assert_eq!(bundle.plan().memory().backing_bytes, 4096);
    assert_eq!(grouping.memory().mappings, 2);
    assert_eq!(grouping.memory().virtual_pages, 2);
    assert_eq!(grouping.memory().backing_pages, 1);
    assert_eq!(grouping.memory().virtual_bytes, 8192);
    assert_eq!(grouping.memory().backing_bytes, 4096);
    assert_eq!(
        grouping.memory().virtual_span,
        bundle.plan().memory().virtual_span
    );
    for (image, grouped) in bundle.images().iter().zip(grouping.images()) {
        assert_eq!(image.address(), grouped.address());
        assert_eq!(image.bytes(), grouped.bytes());
        assert_eq!(
            image.program_counter_mappings(),
            grouped.program_counter_mappings()
        );
    }
}

fn assert_live_grouping(bundle: &PlannedBundle) {
    let grouping = bundle.grouping().unwrap();
    let aliases = grouping.groups()[0].aliases();
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut backings = Vec::new();
    for alias in aliases {
        let fields = maps
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .find(|fields| {
                let (low, high) = fields[0].split_once('-').unwrap();
                u64::from_str_radix(low, 16).unwrap() == alias.start()
                    && u64::from_str_radix(high, 16).unwrap() == alias.end()
            })
            .expect("exact grouped alias mapping must exist");
        assert_eq!(fields[1], "r-xs");
        assert_eq!(u64::from_str_radix(fields[2], 16).unwrap(), 0);
        let inode = fields[4].parse::<u64>().unwrap();
        assert_ne!(inode, 0);
        backings.push((fields[3].to_owned(), inode));
        for image in bundle.images() {
            let offset = image.address() % 4096;
            // SAFETY: publication established this exact RX alias. Every image
            // occupies a separately checked nonoverlapping backing-page span.
            let actual = unsafe {
                std::slice::from_raw_parts(
                    (alias.start() + offset) as *const u8,
                    image.bytes().len(),
                )
            };
            assert_eq!(actual, image.bytes());
            for mapping in image.program_counter_mappings() {
                let at_alias =
                    alias.start() + mapping.generated_start() - (image.address() & !4095);
                assert_eq!(
                    liteinst2::trampoline::translate_program_counter(at_alias),
                    if at_alias == mapping.generated_start() {
                        Some(mapping.logical_address())
                    } else {
                        None
                    },
                    "only an image's declared virtual alias may own its PC maps"
                );
            }
        }
    }
    assert_eq!(
        backings[0], backings[1],
        "aliases must use one actual backing object"
    );
}

fn full_retirement_lease_ranges(fixture: &Fixture, bundle: &PlannedBundle) -> Vec<AddressRange> {
    let mut held = fixture.held();
    held.extend(bundle.plan().steps().iter().flat_map(|step| {
        step.parts()
            .allocations
            .iter()
            .map(|allocation| allocation.range)
    }));
    held
}

fn assert_grouped_budgets(fixture: &Fixture, bundle: &PlannedBundle) {
    let memory = bundle.plan().memory();
    let tight_bundle = BundleBudget {
        max_steps: 2,
        max_mappings: 2,
        max_virtual_bytes: 8192,
        max_backing_bytes: 4096,
        max_virtual_span: memory.virtual_span,
    };
    let tight_grouping = GroupingBudget {
        max_mappings: 2,
        max_virtual_pages: 2,
        max_virtual_bytes: 8192,
        max_backing_bytes: 4096,
        max_virtual_span: memory.virtual_span,
    };
    assert_eq!(
        PlannedBundle::compose(fixture.originals.clone(), fixture.members(), tight_bundle)
            .unwrap_err(),
        Refusal::AllocationUnavailable,
        "ungrouped backing still costs two pages"
    );
    let exact = PlannedBundle::compose_grouped(
        fixture.originals.clone(),
        fixture.members(),
        tight_bundle,
        tight_grouping,
    )
    .unwrap();
    assert_grouped_plan(&exact);
    for budget in [
        BundleBudget {
            max_steps: 1,
            ..tight_bundle
        },
        BundleBudget {
            max_mappings: 1,
            ..tight_bundle
        },
        BundleBudget {
            max_virtual_bytes: 8191,
            ..tight_bundle
        },
        BundleBudget {
            max_backing_bytes: 4095,
            ..tight_bundle
        },
        BundleBudget {
            max_virtual_span: memory.virtual_span - 1,
            ..tight_bundle
        },
    ] {
        assert_eq!(
            PlannedBundle::compose_grouped(
                fixture.originals.clone(),
                fixture.members(),
                budget,
                tight_grouping
            )
            .unwrap_err(),
            Refusal::AllocationUnavailable
        );
    }
    for budget in [
        GroupingBudget {
            max_mappings: 1,
            ..tight_grouping
        },
        GroupingBudget {
            max_virtual_pages: 1,
            ..tight_grouping
        },
        GroupingBudget {
            max_virtual_bytes: 8191,
            ..tight_grouping
        },
        GroupingBudget {
            max_backing_bytes: 4095,
            ..tight_grouping
        },
        GroupingBudget {
            max_virtual_span: memory.virtual_span - 1,
            ..tight_grouping
        },
    ] {
        assert_eq!(
            PlannedBundle::compose_grouped(
                fixture.originals.clone(),
                fixture.members(),
                tight_bundle,
                budget
            )
            .unwrap_err(),
            Refusal::AllocationUnavailable
        );
    }
}

fn grouped_child(mode: &str) {
    let fixture = Fixture::new("success");
    let original = full_source(&fixture);
    all_body_entries(0);
    let bundle = grouped_bundle(&fixture);
    assert_grouped_plan(&bundle);
    if mode == "grouped-budgets" {
        assert_grouped_budgets(&fixture, &bundle);
        assert_eq!(full_source(&fixture), original);
    }
    let aliases = [fixture.alias()];
    let mut guard = ();
    // SAFETY: this isolated child is the sole alias owner and executor, parked
    // throughout the borrow. Every application call occurs after dropping it.
    let mut lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
    if mode == "grouped-collision" {
        let group_aliases = bundle.grouping().unwrap().groups()[0].aliases();
        let collision = group_aliases[1];
        let mapping = unsafe {
            libc::mmap(
                collision.start() as *mut _,
                collision.len() as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_eq!(mapping as usize as u64, collision.start());
        let failure = unsafe { bundle.publish(&aliases, &mut lease) }
            .err()
            .unwrap();
        assert_eq!(failure.reason, Refusal::AllocationUnavailable);
        assert_eq!(failure.stage, FailureStage::BeforeWrite);
        assert!(!lease.is_poisoned());
        assert_eq!(full_source(&fixture), original);
        let mut residency = 0;
        assert_eq!(
            unsafe { libc::mincore(group_aliases[0].start() as *mut _, 4096, &mut residency) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM)
        );
        assert_eq!(unsafe { libc::mincore(mapping, 4096, &mut residency) }, 0);
        for image in bundle.images() {
            for pc in image.program_counter_mappings() {
                assert_eq!(
                    liteinst2::trampoline::translate_program_counter(pc.generated_start()),
                    None
                );
            }
        }
        assert_eq!(
            unsafe { libc::munmap(mapping, collision.len() as usize) },
            0
        );
        drop(lease);
        all_body_entries(0);
        lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
    }
    if mode == "grouped-postwrite" {
        let failure =
            unsafe { bundle.publish_with(&aliases, &mut lease, || Err(Refusal::Synchronization)) }
                .err()
                .unwrap();
        assert_eq!(failure.reason, Refusal::Synchronization);
        assert_eq!(failure.stage, FailureStage::KeepGated);
        assert!(lease.is_poisoned());
        assert_eq!(full_source(&fixture), final_source(&original, &bundle));
        assert_live_grouping(&bundle);
        let retry = unsafe { bundle.publish(&aliases, &mut lease) }
            .err()
            .unwrap();
        assert_eq!(retry.reason, Refusal::LeasePoisoned);
        assert_eq!(retry.stage, FailureStage::BeforeWrite);
        std::mem::forget(fixture); // No execution or mapping teardown after KeepGated.
        println!("bundle scenario {mode}: complete");
        return;
    }
    let (mut installed, receipt) = unsafe { bundle.publish(&aliases, &mut lease) }.unwrap();
    assert_eq!(receipt.plan().steps(), bundle.plan().steps());
    assert_eq!(receipt.plan().memory(), bundle.plan().memory());
    assert!(!lease.is_poisoned());
    assert_eq!(full_source(&fixture), final_source(&original, &bundle));
    assert_live_grouping(&bundle);
    drop(lease);
    all_body_entries(2);
    let mut lease = unsafe {
        QuiescenceLease::new(
            &mut guard,
            fixture.identity,
            full_retirement_lease_ranges(&fixture, &bundle),
        )
    };
    if mode == "grouped-retire-postwrite" {
        let failure =
            unsafe { installed.retire_with(&mut lease, || Err(Refusal::Synchronization)) }
                .unwrap_err();
        assert_eq!(failure.reason, Refusal::Synchronization);
        assert_eq!(failure.stage, FailureStage::KeepGated);
        assert!(lease.is_poisoned());
        assert!(!installed.is_retired());
        assert_eq!(full_source(&fixture), original);
        assert_live_grouping(&bundle);
        let retry = unsafe { installed.retire(&mut lease) }.unwrap_err();
        assert_eq!(retry.reason, Refusal::LeasePoisoned);
        assert_eq!(retry.stage, FailureStage::BeforeWrite);
        std::mem::forget(fixture); // Restored bytes do not release poisoned admission.
        println!("bundle scenario {mode}: complete");
        return;
    }
    unsafe { installed.retire(&mut lease) }.unwrap();
    assert!(installed.is_retired());
    assert!(!lease.is_poisoned());
    assert_eq!(full_source(&fixture), original);
    drop(lease);
    all_body_entries(0);
    println!("bundle scenario {mode}: complete");
}

fn prefixed_bundle_child() {
    let fixture = Fixture::new("success");
    let original = full_source(&fixture);
    all_body_entries(0);
    let mut members = fixture.members();
    let source = &fixture.originals[1];
    let scope = AddressRange::new(source.address, source.bytes.len()).unwrap();
    let entries = LegalEntrySet {
        identity: fixture.identity,
        scope,
        provenance: EntryProvenance::Declared("prefixed bundle successor heads".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: vec![],
        resumes: ResumeObligation::NoneExist,
    };
    // L2/P1 fixes all four displacement bytes to the untouched MOV encoding.
    let displacement = i32::from_le_bytes(source.bytes[2..6].try_into().unwrap());
    let target = u64::try_from(i128::from(source.address + 6) + i128::from(displacement)).unwrap();
    let mut allocation = AllocationPolicy::near(source.address).unwrap();
    allocation.preferred_address = Some(target);
    allocation.ranges = vec![AddressRange::new(target & !4095, 8192).unwrap()];
    members[1] = plan_install(&InstallRequest {
        identity: fixture.identity,
        code: &source.bytes,
        base_address: source.address,
        function: scope,
        block: scope,
        logical_pc: source.address,
        entries: &entries,
        hook: observe,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: SearchPolicy {
            tactics: TacticPolicy::PrefixPunOnly,
            ..SearchPolicy::default()
        },
    })
    .unwrap();
    let PlanKind::PrefixedPun(pun) = &members[1].plan().parts().kind else {
        panic!("required T1 bundle member");
    };
    assert_eq!(pun.instruction_len, 2);
    assert_eq!(pun.prefix_count, 1);
    assert_eq!(pun.target_window, AddressRange::new(target, 1).unwrap());
    assert_eq!(members[1].image().address(), target);
    assert_eq!(members[1].plan().parts().writes[0].bytes, [0x2e, 0xe9]);
    let bundle =
        PlannedBundle::compose(fixture.originals.clone(), members, BundleBudget::default())
            .unwrap();
    assert!(bundle.grouping().is_none());
    let aliases = [fixture.alias()];
    let mut guard = ();
    // SAFETY: exclusive child owns aliases, execution and all continuations.
    let mut lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
    let (mut installed, receipt) = unsafe { bundle.publish(&aliases, &mut lease) }.unwrap();
    assert_eq!(receipt.plan().steps(), bundle.plan().steps());
    assert!(!lease.is_poisoned());
    assert_eq!(full_source(&fixture), final_source(&original, &bundle));
    drop(lease);
    all_body_entries(2);
    let mut lease = unsafe {
        QuiescenceLease::new(
            &mut guard,
            fixture.identity,
            full_retirement_lease_ranges(&fixture, &bundle),
        )
    };
    unsafe { installed.retire(&mut lease) }.unwrap();
    assert!(installed.is_retired());
    assert!(!lease.is_poisoned());
    assert_eq!(full_source(&fixture), original);
    drop(lease);
    all_body_entries(0);
    println!("bundle scenario prefixed-success: complete");
}

fn child(mode: &str) {
    if mode.starts_with("grouped-") {
        grouped_child(mode);
        return;
    }
    if mode == "prefixed-success" {
        prefixed_bundle_child();
        return;
    }
    let fixture = Fixture::new(mode);
    fixture.calls(0);
    let bundle = fixture.bundle();
    if mode == "evex-lock" {
        let members = fixture.members();
        assert_eq!(members[0].plan().parts().writes[0].bytes[7], 0x62);
        assert!(
            bundle
                .plan()
                .locks()
                .iter()
                .any(|lock| lock.covers(AddressRange::new(ADDRESS + 0x107, 15).unwrap()))
        );
        let successor = fixture.conflicting_successor();
        let failure = PlannedBundle::compose(
            fixture.originals.clone(),
            vec![members[0].clone(), successor, members[1].clone()],
            BundleBudget::default(),
        )
        .unwrap_err();
        assert_eq!(failure, Refusal::OwnershipConflict);
        fixture.check(&fixture.originals);
    }
    assert_eq!(bundle.plan().memory().mappings, 2);
    assert_eq!(
        bundle.plan().memory().backing_bytes,
        bundle.plan().memory().virtual_bytes
    );
    let mut guard = ();
    // SAFETY: child alone owns/executes all mappings and is parked in this test.
    let mut lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
    let aliases = [fixture.alias()];
    match mode {
        "success" | "router" | "evex-lock" | "retire-postwrite" => {
            let expected_hooks = if mode == "evex-lock" { 3 } else { 2 };
            let (mut installed, receipt) = unsafe { bundle.publish(&aliases, &mut lease) }.unwrap();
            assert_eq!(receipt.plan().steps(), bundle.plan().steps());
            assert!(!lease.is_poisoned());
            drop(lease);
            fixture.check(bundle.plan().final_bytes());
            fixture.calls(expected_hooks);
            if mode == "router" || mode == "evex-lock" {
                assert!(installed.routed_entries() > 0);
            }
            let mut lease =
                unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
            let failure = unsafe { installed.retire(&mut lease) }.unwrap_err();
            assert_eq!(failure.reason, Refusal::DependencyNotHeld);
            assert_eq!(failure.stage, FailureStage::BeforeWrite);
            drop(lease);
            fixture.check(bundle.plan().final_bytes());
            fixture.calls(expected_hooks);
            let mut held = fixture.held();
            held.extend(
                bundle
                    .plan()
                    .steps()
                    .iter()
                    .flat_map(|p| p.parts().allocations.iter().map(|a| a.range)),
            );
            let mut lease = unsafe { QuiescenceLease::new(&mut guard, fixture.identity, held) };
            if mode == "retire-postwrite" {
                let error =
                    unsafe { installed.retire_with(&mut lease, || Err(Refusal::Synchronization)) }
                        .unwrap_err();
                assert_eq!(error.stage, FailureStage::KeepGated);
                assert!(lease.is_poisoned());
                assert!(!installed.is_retired());
                fixture.check(&fixture.originals);
                let retry = unsafe { installed.retire(&mut lease) }.unwrap_err();
                assert_eq!(retry.reason, Refusal::LeasePoisoned);
                // Restored bytes alone do not authorize execution after failed synchronization.
                std::mem::forget(fixture);
                println!("bundle scenario {mode}: complete");
                return;
            }
            unsafe { installed.retire(&mut lease) }.unwrap();
            assert!(installed.is_retired());
            assert!(!lease.is_poisoned());
            drop(lease);
            fixture.check(&fixture.originals);
            fixture.calls(0);
        }
        "collision" => {
            let collision = bundle.plan().steps()[1].parts().allocations[0].range;
            let mapping = unsafe {
                libc::mmap(
                    collision.start() as *mut _,
                    collision.len() as usize,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            let error = unsafe { bundle.publish(&aliases, &mut lease) }
                .err()
                .unwrap();
            assert_eq!(error.stage, FailureStage::BeforeWrite);
            assert!(!lease.is_poisoned());
            drop(lease);
            fixture.check(&fixture.originals);
            fixture.calls(0);
            assert_eq!(
                unsafe { libc::munmap(mapping, collision.len() as usize) },
                0
            );
            // Retry proves both the first staged mapping and every reservation were released.
            let mut lease =
                unsafe { QuiescenceLease::new(&mut guard, fixture.identity, fixture.held()) };
            let (_installed, _) = unsafe { bundle.publish(&aliases, &mut lease) }.unwrap();
            drop(lease);
            fixture.check(bundle.plan().final_bytes());
            fixture.calls(2);
            // Active handles intentionally retain ownership; child exit reclaims everything.
            std::mem::forget(fixture);
        }
        "stale" => {
            unsafe {
                *fixture.write.add(0x183) ^= 1;
            }
            let error = unsafe { bundle.publish(&aliases, &mut lease) }
                .err()
                .unwrap();
            assert_eq!(error.reason, Refusal::ExpectedBytesChanged);
            assert_eq!(error.stage, FailureStage::BeforeWrite);
            assert!(!lease.is_poisoned());
            unsafe {
                *fixture.write.add(0x183) ^= 1;
            }
            fixture.check(&fixture.originals);
            let (_installed, _) = unsafe { bundle.publish(&aliases, &mut lease) }.unwrap();
            drop(lease);
            fixture.calls(2);
            std::mem::forget(fixture);
        }
        "postwrite" => {
            let error = unsafe {
                bundle.publish_with(&aliases, &mut lease, || Err(Refusal::Synchronization))
            }
            .err()
            .unwrap();
            assert_eq!(error.stage, FailureStage::KeepGated);
            assert!(lease.is_poisoned());
            fixture.check(bundle.plan().final_bytes());
            let retry = unsafe { bundle.publish(&aliases, &mut lease) }
                .err()
                .unwrap();
            assert_eq!(retry.reason, Refusal::LeasePoisoned);
            // No application execution after a failed synchronization/finalization.
            std::mem::forget(fixture);
        }
        "budgets" => {
            drop(lease);
            for budget in [
                BundleBudget {
                    max_steps: 1,
                    ..BundleBudget::default()
                },
                BundleBudget {
                    max_mappings: 1,
                    ..BundleBudget::default()
                },
                BundleBudget {
                    max_virtual_bytes: 0,
                    ..BundleBudget::default()
                },
                BundleBudget {
                    max_backing_bytes: 0,
                    ..BundleBudget::default()
                },
                BundleBudget {
                    max_virtual_span: 0,
                    ..BundleBudget::default()
                },
            ] {
                let error =
                    PlannedBundle::compose(fixture.originals.clone(), fixture.members(), budget)
                        .unwrap_err();
                assert_eq!(error, Refusal::AllocationUnavailable);
                fixture.check(&fixture.originals);
            }
            fixture.calls(0);
        }
        _ => panic!("unknown scenario"),
    }
    println!("bundle scenario {mode}: complete");
}
#[test]
fn bundle_transactions() {
    if let Ok(mode) = std::env::var(ENV) {
        child(&mode);
        return;
    }
    for mode in [
        "success",
        "router",
        "evex-lock",
        "collision",
        "stale",
        "postwrite",
        "retire-postwrite",
        "budgets",
        "grouped-success",
        "grouped-collision",
        "grouped-postwrite",
        "grouped-retire-postwrite",
        "grouped-budgets",
        "prefixed-success",
    ] {
        let mut process = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "bundle_transactions", "--nocapture"])
            .env(ENV, mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if process.try_wait().unwrap().is_some() {
                break;
            }
            if start.elapsed() > Duration::from_secs(15) {
                process.kill().unwrap();
                panic!(
                    "bundle child {mode} timed out: {:?}",
                    process.wait_with_output().unwrap()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = process.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "scenario {mode}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("bundle scenario {mode}: complete"))
        );
    }
}
