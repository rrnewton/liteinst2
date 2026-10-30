//! Pure prospective catalog fixtures. These bytes are never executed and make no
//! semantic/ISA claim; the exact positive exercises all structural joins.
use super::*;
use crate::{Compatibility, Outcome, Site, Tactic};
fn p16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
#[derive(Clone, Copy)]
struct Ph {
    kind: u32,
    flags: u32,
    off: u64,
    va: u64,
    files: u64,
    mem: u64,
    align: u64,
}
fn record(b: &mut [u8], at: usize, p: Ph) {
    p32(b, at, p.kind);
    p32(b, at + 4, p.flags);
    p64(b, at + 8, p.off);
    p64(b, at + 16, p.va);
    p64(b, at + 24, p.va);
    p64(b, at + 32, p.files);
    p64(b, at + 40, p.mem);
    p64(b, at + 48, p.align);
}
fn input() -> Input {
    fixture(false)
}
fn fixture(auxiliary: bool) -> Input {
    fixture_program(1, auxiliary)
}
fn fixture_program(program: u64, auxiliary: bool) -> Input {
    let (head_count, selected_count) = if program == 1 {
        (80usize, 16usize)
    } else {
        (107, 26)
    };
    let image_count = selected_count + usize::from(auxiliary);
    let header_count = image_count + 7;
    let rx = Ph {
        kind: 1,
        flags: 5,
        off: 0,
        va: 0x400000,
        files: 4096,
        mem: 4096,
        align: 4096,
    };
    let rw = Ph {
        kind: 1,
        flags: 6,
        off: 4096,
        va: 0x600000,
        files: 0,
        mem: 65536,
        align: 4096,
    };
    let stack = Ph {
        kind: 0x6474e551,
        flags: 6,
        off: 0,
        va: 0,
        files: 0,
        mem: 0,
        align: 16,
    };
    let mut original = vec![0; 4096];
    original[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    p16(&mut original, 16, 2);
    p16(&mut original, 18, 62);
    p32(&mut original, 20, 1);
    p64(&mut original, 24, 0x400400);
    p64(&mut original, 32, 64);
    p16(&mut original, 52, 64);
    p16(&mut original, 54, 56);
    p16(&mut original, 56, 3);
    for (i, p) in [rx, rw, stack].into_iter().enumerate() {
        record(&mut original, 64 + i * 56, p);
    }
    original[0x400..0x400 + head_count].fill(0x90);
    original[0x800] = 0xc3;
    let state = State {
        domain: 1,
        format: 1,
        allocation: 512,
        image: 512,
        mask: 3,
        components: vec![],
    };
    let policy = Policy {
        interpreter: b"/pkg/ld.so".to_vec(),
        bootstrap_dso: b"/pkg/bootstrap.so".to_vec(),
        dependencies: vec![Dependency {
            path: b"/pkg/ld.so".to_vec(),
            identity: ContentId::of(b"loader-package-input"),
        }],
        app_stack: Span {
            start: 0x600000,
            len: 65536,
        },
        hook_pc: 0x400800,
        hook_id: 1,
        state,
        qualification_contract: ContentId::of(b"PURE STRUCTURAL CONTROL, NO RUNTIME QUALIFICATION"),
    };
    let selection =
        format!("pure fixed program {program}: complete {selected_count}-site selection")
            .into_bytes();
    let target = target_bytes(&policy.state).unwrap();
    let sites = (0..selected_count as u64)
        .map(|i| Site {
            id: i + 1,
            original_pc: 0x400400 + i,
            file_offset: 0x400 + i,
            length: 1,
            outcome: Outcome::Rewritten(Tactic::Relocation),
        })
        .collect();
    let metadata = Metadata::new(
        &original,
        ContentId::of(&selection),
        Compatibility {
            planner: 3,
            encoder: 1,
            hook_abi: 1,
            arena: 1,
            target: ContentId::of(&target),
            binding: ContentId::of(&selection),
        },
        sites,
    )
    .unwrap()
    .encode(crate::Limits::default())
    .unwrap();
    let mut main = original.clone();
    main.resize((image_count + 2) * 4096, 0);
    p64(&mut main, 32, 4096);
    p16(&mut main, 56, header_count as u16);
    let interpreter = 4096 + header_count * 56 + 64;
    let str_start = interpreter + policy.interpreter.len() + 1;
    let str_bytes = [&[0][..], policy.bootstrap_dso.as_slice(), &[0]].concat();
    let str_end = str_start + str_bytes.len();
    let sym = (str_end + 7) & !7;
    let hash = (sym + 24 + 3) & !3;
    let dynamic = (hash + 16 + 7) & !7;
    let delta = 0x500000 - 4096;
    main[interpreter..interpreter + policy.interpreter.len()].copy_from_slice(&policy.interpreter);
    main[str_start..str_end].copy_from_slice(&str_bytes);
    for (i, n) in [1u32, 1, 0, 0].into_iter().enumerate() {
        p32(&mut main, hash + i * 4, n);
    }
    for (i, (tag, val)) in [
        (1, 1),
        (5, (delta + str_start) as u64),
        (10, str_bytes.len() as u64),
        (6, (delta + sym) as u64),
        (11, 24),
        (4, (delta + hash) as u64),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        p64(&mut main, dynamic + i * 16, tag);
        p64(&mut main, dynamic + i * 16 + 8, val);
    }
    let mut headers = vec![
        Ph {
            kind: 6,
            flags: 4,
            off: 4096,
            va: 0x500000,
            files: (header_count * 56) as u64,
            mem: (header_count * 56) as u64,
            align: 8,
        },
        Ph {
            kind: 3,
            flags: 4,
            off: interpreter as u64,
            va: (delta + interpreter) as u64,
            files: policy.interpreter.len() as u64 + 1,
            mem: policy.interpreter.len() as u64 + 1,
            align: 1,
        },
        rx,
        Ph {
            kind: 1,
            flags: 4,
            off: 4096,
            va: 0x500000,
            files: (dynamic + 112 - 4096) as u64,
            mem: (dynamic + 112 - 4096) as u64,
            align: 4096,
        },
        rw,
    ];
    let mut steps = Vec::new();
    let mut images = Vec::new();
    for i in 0..image_count as u64 {
        let h = 0x400400 + i;
        let g = 0x700000 + i * 4096;
        let off = (2 + i) * 4096;
        headers.push(Ph {
            kind: 1,
            flags: 5,
            off,
            va: g,
            files: 2,
            mem: 2,
            align: 4096,
        });
        main[off as usize..off as usize + 2].copy_from_slice(&[0x90, 0xc3]);
        main[0x400 + i as usize] = 0x06;
        steps.push(Step {
            selected_id: if i == selected_count as u64 { 1 } else { i + 1 },
            logical: h,
            physical: h,
            displaced: Span { start: h, len: 1 },
            kind: Kind::Relocation,
            neighbor: None,
            reads: vec![Blob {
                address: h,
                bytes: vec![0x90],
            }],
            writes: vec![Blob {
                address: h,
                bytes: vec![0x06],
            }],
            dependencies: vec![Span { start: h, len: 1 }],
            allocation: Span {
                start: g,
                len: 4096,
            },
            image: g,
            obligations: vec![Obligation {
                original: h,
                generated: Some(g),
            }],
        });
        images.push(Image {
            body: Blob {
                address: g,
                bytes: vec![0x90, 0xc3],
            },
            entries: vec![(h, g)],
            requirements: if i == selected_count as u64 {
                vec![(1, 0), (2, 0), (3, 0), (4, 0), (7, 0), (8, 0), (6, 0)]
            } else {
                vec![
                    (1, 0),
                    (2, 0),
                    (3, 0),
                    (4, 0),
                    (7, 0),
                    (8, 0),
                    (5, 1),
                    (6, 0),
                ]
            },
        });
    }
    headers.push(stack);
    headers.push(Ph {
        kind: 2,
        flags: 4,
        off: dynamic as u64,
        va: (delta + dynamic) as u64,
        files: 112,
        mem: 112,
        align: 8,
    });
    assert_eq!(headers.len(), header_count);
    for (i, p) in headers.into_iter().enumerate() {
        record(&mut main, 4096 + i * 56, p);
    }
    Input {
        program,
        policy,
        original,
        main,
        selection,
        metadata,
        target,
        ledger: b"frozen compiler ledger; independently joined by W01".to_vec(),
        heads: (0..head_count as u64).map(|i| 0x400400 + i).collect(),
        steps,
        images,
    }
}
#[test]
fn exact_complete_catalog_round_trip() {
    let c = Catalog::new(input()).unwrap();
    assert_eq!(c.input().heads.len(), 80);
    assert_eq!(c.input().steps.len(), 16);
    assert_eq!(c.input().images.len(), 16);
    assert_eq!(c.routes().len(), 16);
    for (i, (h, g)) in c.routes().into_iter().enumerate() {
        assert_eq!((h, g), (0x400400 + i as u64, 0x700000 + i as u64 * 4096));
    }
    let encoded = c.encode().unwrap();
    assert_eq!(Catalog::decode(&encoded).unwrap(), c);
    assert_eq!(
        Catalog::decode(&encoded).unwrap().encode().unwrap(),
        encoded
    );
}
#[test]
fn rejects_omissions_extras_and_wrong_owners_before_activation() {
    let base = input();
    Catalog::new(base.clone()).unwrap();
    let mutations: [fn(&mut Input); 12] = [
        |x| {
            x.heads.pop();
        },
        |x| {
            x.steps.pop();
        },
        |x| {
            x.images.pop();
        },
        |x| {
            x.steps[0].obligations.clear();
        },
        |x| {
            let o = x.steps[0].obligations[0];
            x.steps[0].obligations.push(o);
        },
        |x| {
            x.steps[0].obligations[0].generated = Some(x.images[1].body.address);
        },
        |x| {
            x.steps[0].obligations[0].generated = None;
        },
        |x| {
            x.images[0].entries.clear();
        },
        |x| {
            x.images[0].requirements.retain(|&(tag, _)| tag != 6);
        },
        |x| {
            x.steps[0].allocation = x.steps[1].allocation;
        },
        |x| {
            x.images.push(x.images[0].clone());
        },
        |x| {
            x.images[0].requirements.push((99, 0));
        },
    ];
    for (i, mutate) in mutations.into_iter().enumerate() {
        let mut x = base.clone();
        mutate(&mut x);
        assert!(Catalog::new(x).is_err(), "required mutant {i} accepted");
    }
}
#[test]
fn rejects_exact_byte_and_startup_tampering() {
    let base = input();
    Catalog::new(base.clone()).unwrap();
    let mutations: [fn(&mut Input); 12] = [
        |x| {
            x.main[0x400] = 0x90;
        },
        |x| {
            x.main[8192] ^= 1;
        },
        |x| {
            x.original[0x401] ^= 1;
        },
        |x| {
            x.selection.push(b'x');
        },
        |x| {
            x.target.push(b'x');
        },
        |x| {
            x.policy.interpreter[1] ^= 1;
        },
        |x| {
            x.policy.bootstrap_dso[1] ^= 1;
        },
        |x| {
            x.policy.dependencies.clear();
        },
        |x| {
            x.policy.app_stack.len -= 1;
        },
        |x| {
            x.policy.hook_pc += 1;
        },
        |x| {
            p64(&mut x.main, 24, 0x400401);
        },
        |x| {
            p32(&mut x.main, 4096 + 3 * 56 + 4, 6);
        },
    ];
    for (i, mutate) in mutations.into_iter().enumerate() {
        let mut x = base.clone();
        mutate(&mut x);
        assert!(Catalog::new(x).is_err(), "required tamper {i} accepted");
    }
}
#[test]
fn closed_wire_refuses_corruption_truncation_and_surplus() {
    let c = Catalog::new(input()).unwrap();
    let bytes = c.encode().unwrap();
    let mut corrupt = bytes.clone();
    corrupt[100] ^= 1;
    assert_eq!(Catalog::decode(&corrupt), Err(Error::Identity));
    assert!(Catalog::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut surplus = bytes[..bytes.len() - 32].to_vec();
    surplus.push(0);
    let id = ContentId::of(&surplus);
    surplus.extend_from_slice(&id.0);
    assert_eq!(Catalog::decode(&surplus), Err(Error::Shape));
    let mut oversized = bytes[..bytes.len() - 32].to_vec();
    oversized[24..32].copy_from_slice(&4096u64.to_le_bytes());
    let id = ContentId::of(&oversized);
    oversized.extend_from_slice(&id.0);
    assert_eq!(Catalog::decode(&oversized), Err(Error::Limit));
}
#[test]
fn exact_marker_and_full_fetch_rules() {
    let mut x = input();
    let at = 0x440usize;
    let pc = 0x400440;
    x.main[at..at + 15].copy_from_slice(&[0x62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let elf = parse(&x.main).unwrap();
    assert_eq!(validate_marker(&elf, pc), Ok(()));
    x.main[at + 2] = 4;
    assert_eq!(
        validate_marker(&parse(&x.main).unwrap(), pc),
        Err(Error::Route)
    );
    x.main[4090] = 0x62;
    assert_eq!(
        validate_marker(&parse(&x.main).unwrap(), 0x400ffa),
        Err(Error::Route)
    );
    x.main[at] = 0x06;
    assert_eq!(validate_marker(&parse(&x.main).unwrap(), pc), Ok(()));
    x.main[at] = 0x90;
    assert_eq!(
        validate_marker(&parse(&x.main).unwrap(), pc),
        Err(Error::Route)
    );
}

#[test]
fn complete_auxiliary_image_retains_exact_role_and_router_requirement() {
    let base = fixture(true);
    let c = Catalog::new(base.clone()).unwrap();
    assert_eq!(
        (
            c.input().heads.len(),
            c.input().steps.len(),
            c.input().images.len(),
            c.routes().len()
        ),
        (80, 17, 17, 17)
    );
    assert_eq!(c.input().steps[16].selected_id, 1);
    assert_eq!(
        c.input().images[16].requirements,
        vec![(1, 0), (2, 0), (3, 0), (4, 0), (7, 0), (8, 0), (6, 0)]
    );
    let mut wrong = base.clone();
    wrong.images[16].requirements.insert(6, (5, 1));
    assert_eq!(Catalog::new(wrong), Err(Error::Image));
    let mut missing = base.clone();
    missing.images[0].requirements.remove(6);
    assert_eq!(Catalog::new(missing), Err(Error::Image));
    let mut reordered = base;
    reordered.images[0].requirements.swap(6, 7);
    assert_eq!(Catalog::new(reordered), Err(Error::Image));
}

#[test]
fn exact_complete_rle_catalog_retains_107_heads_and_26_selected() {
    let c = Catalog::new(fixture_program(2, false)).unwrap();
    assert_eq!(
        (
            c.input().heads.len(),
            c.input().steps.len(),
            c.input().images.len(),
            c.routes().len()
        ),
        (107, 26, 26, 26)
    );
    let encoded = c.encode().unwrap();
    assert_eq!(Catalog::decode(&encoded).unwrap(), c);
    let mut missing = c.input().clone();
    missing.steps.pop();
    assert!(Catalog::new(missing).is_err());
    let mut shortened = c.input().clone();
    shortened.heads.pop();
    assert!(Catalog::new(shortened).is_err());
}

#[test]
fn geometry_wire_version_is_explicit_and_old_envelope_is_not_reinterpreted() {
    let c = Catalog::new(input()).unwrap();
    let encoded = c.encode().unwrap();
    assert_eq!(&encoded[8..16], &2u64.to_le_bytes());
    let mut old = encoded[..encoded.len() - 32].to_vec();
    old[8..16].copy_from_slice(&1u64.to_le_bytes());
    let id = ContentId::of(&old);
    old.extend_from_slice(&id.0);
    assert_eq!(Catalog::decode(&old), Err(Error::Shape));
}

// Independent complete-ELF construction for the additional class. The original
// bytes, full head/selected populations and route/image obligations are unchanged.
fn absolute_input(program: u64) -> (Input, AbsolutePrerequisites) {
    let mut x = fixture_program(program, false);
    x.policy.dependencies.extend([
        Dependency {
            path: b"/pkg/libc.so".to_vec(),
            identity: ContentId::of(b"libc control"),
        },
        Dependency {
            path: b"/pkg/libgcc.so".to_vec(),
            identity: ContentId::of(b"libgcc control"),
        },
    ]);
    let roles = AbsolutePrerequisites {
        libgcc_dependency: 2,
        libc_dependency: 1,
    };
    let elf = parse(&x.main).unwrap();
    let start = elf
        .segments(SegmentType::Interpreter)
        .next()
        .unwrap()
        .offset
        .0 as usize;
    let dyn_index = elf.segments(SegmentType::Dynamic).next().unwrap().index;
    x.main[start..8192].fill(0);
    let strings = [
        b"\0/pkg/libgcc.so\0/pkg/libc.so\0".as_slice(),
        x.policy.bootstrap_dso.as_slice(),
        &[0],
    ]
    .concat();
    let str_at = start + x.policy.interpreter.len() + 1;
    let sym_at = (str_at + strings.len() + 7) & !7;
    let hash_at = sym_at + 24;
    let dyn_at = hash_at + 16;
    let va = |at: usize| (0x500000 + at - 4096) as u64;
    let interp_end = start + x.policy.interpreter.len();
    x.main[start..interp_end].copy_from_slice(&x.policy.interpreter);
    x.main[str_at..str_at + strings.len()].copy_from_slice(&strings);
    for (i, value) in [1u32, 1, 0, 0].into_iter().enumerate() {
        p32(&mut x.main, hash_at + i * 4, value);
    }
    for (i, (tag, value)) in [
        (1, 1),
        (1, 16),
        (1, 29),
        (5, va(str_at)),
        (10, strings.len() as u64),
        (6, va(sym_at)),
        (11, 24),
        (4, va(hash_at)),
        (0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        p64(&mut x.main, dyn_at + i * 16, tag);
        p64(&mut x.main, dyn_at + i * 16 + 8, value);
    }
    // Literal lengths above are checked against the independently assembled names.
    assert_eq!(&strings[1..16], b"/pkg/libgcc.so\0");
    assert_eq!(&strings[16..29], b"/pkg/libc.so\0");
    for delta in [32, 40] {
        p64(
            &mut x.main,
            4096 + 3 * 56 + delta,
            (dyn_at + 144 - 4096) as u64,
        );
    }
    record(
        &mut x.main,
        4096 + dyn_index * 56,
        Ph {
            kind: 2,
            flags: 4,
            off: dyn_at as u64,
            va: va(dyn_at),
            files: 144,
            mem: 144,
            align: 8,
        },
    );
    (x, roles)
}

#[test]
fn absolute_class_retains_both_complete_populations_and_wire_roles() {
    for (program, heads, sites) in [(1, 80, 16), (2, 107, 26)] {
        let (x, roles) = absolute_input(program);
        let c = Catalog::new_absolute_prerequisites(x, roles).unwrap();
        assert_eq!(
            (
                c.input().heads.len(),
                c.input().steps.len(),
                c.input().images.len(),
                c.routes().len()
            ),
            (heads, sites, sites, sites)
        );
        assert_eq!(
            c.startup_class(),
            StartupClass::AbsolutePrerequisites(roles)
        );
        let encoded = c.encode().unwrap();
        assert_eq!(&encoded[8..16], &3u64.to_le_bytes());
        assert_eq!(&encoded[24..32], &2u64.to_le_bytes());
        assert_eq!(&encoded[32..40], &1u64.to_le_bytes());
        assert_eq!(Catalog::decode(&encoded).unwrap(), c);
        assert_eq!(
            Catalog::decode(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        let elf = parse(&c.input().main).unwrap();
        assert_eq!(c.validate_startup(&elf), Ok(0x500000));
        assert!(validate_startup(&elf, &c.input().policy).is_err());
        assert!(Catalog::new(c.input().clone()).is_err());
        assert!(
            Catalog::new_absolute_prerequisites(fixture_program(program, false), roles).is_err()
        );
    }
}

#[test]
fn absolute_roles_are_distinct_actual_sorted_roster_indices() {
    let (x, roles) = absolute_input(1);
    Catalog::new_absolute_prerequisites(x.clone(), roles).unwrap();
    for changed in [
        AbsolutePrerequisites {
            libgcc_dependency: 1,
            libc_dependency: 1,
        },
        AbsolutePrerequisites {
            libgcc_dependency: 3,
            libc_dependency: 1,
        },
        AbsolutePrerequisites {
            libgcc_dependency: 0,
            libc_dependency: 1,
        },
        AbsolutePrerequisites {
            libgcc_dependency: 1,
            libc_dependency: 2,
        },
    ] {
        assert!(Catalog::new_absolute_prerequisites(x.clone(), changed).is_err());
    }
    let mut reordered = x.clone();
    reordered.policy.dependencies.swap(1, 2);
    assert!(
        Catalog::new_absolute_prerequisites(
            reordered,
            AbsolutePrerequisites {
                libgcc_dependency: 1,
                libc_dependency: 2
            }
        )
        .is_err()
    );
    let mut token = x.clone();
    token.policy.dependencies[2].path = b"/pkg/$LIB.so".to_vec();
    assert!(Catalog::new_absolute_prerequisites(token, roles).is_err());
    let mut extra_token = x.clone();
    extra_token.policy.dependencies.push(Dependency {
        path: b"/zzz/$TOKEN.so".to_vec(),
        identity: ContentId::of(b"extra pinned bytes"),
    });
    assert!(Catalog::new_absolute_prerequisites(extra_token, roles).is_err());
    let mut excessive = x;
    excessive.policy.bootstrap_dso = [b"/".as_slice(), vec![b'z'; 4094].as_slice()].concat();
    assert_eq!(
        Catalog::new_absolute_prerequisites(excessive, roles),
        Err(Error::Limit)
    );
}

#[test]
fn absolute_metadata_every_byte_and_owner_are_exact() {
    let (base, roles) = absolute_input(1);
    Catalog::new_absolute_prerequisites(base.clone(), roles).unwrap();
    let elf = parse(&base.main).unwrap();
    let start = elf
        .segments(SegmentType::Interpreter)
        .next()
        .unwrap()
        .offset
        .0 as usize;
    let dynamic = elf.segments(SegmentType::Dynamic).next().unwrap();
    let end = (dynamic.offset.0 + dynamic.file_size) as usize;
    // Includes all strings/NULs/padding, the entire null symbol/hash and all nine rows.
    for at in start..end {
        let mut x = base.clone();
        x.main[at] ^= 1;
        assert!(
            Catalog::new_absolute_prerequisites(x, roles).is_err(),
            "metadata byte {at}"
        );
    }
    for flags in [5, 6, 7] {
        let mut x = base.clone();
        p32(&mut x.main, 4096 + 3 * 56 + 4, flags);
        assert!(Catalog::new_absolute_prerequisites(x, roles).is_err());
    }
    for size in [112, 143, 145, 160] {
        let mut x = base.clone();
        for delta in [32, 40] {
            p64(&mut x.main, 4096 + dynamic.index * 56 + delta, size);
        }
        assert!(Catalog::new_absolute_prerequisites(x, roles).is_err());
    }
    let mutations: [fn(&mut Input); 4] = [
        |x| {
            x.heads.pop();
        },
        |x| {
            x.steps.pop();
        },
        |x| {
            x.images.pop();
        },
        |x| {
            x.steps[0].obligations.clear();
        },
    ];
    for mutate in mutations {
        let mut x = base.clone();
        mutate(&mut x);
        assert!(Catalog::new_absolute_prerequisites(x, roles).is_err());
    }
}

#[test]
fn absolute_wire_cannot_relabel_roles_version_or_surplus_with_a_fresh_digest() {
    let (x, roles) = absolute_input(1);
    let encoded = Catalog::new_absolute_prerequisites(x, roles)
        .unwrap()
        .encode()
        .unwrap();
    for (at, value) in [(8, 2u64), (8, 4), (24, 0), (24, 1), (24, u64::MAX), (32, 2)] {
        let mut body = encoded[..encoded.len() - 32].to_vec();
        p64(&mut body, at, value);
        let id = ContentId::of(&body);
        body.extend_from_slice(&id.0);
        assert!(Catalog::decode(&body).is_err(), "wire word {at}={value}");
    }
    for length in [24, 32, 40, encoded.len() - 33] {
        let mut body = encoded[..length].to_vec();
        let id = ContentId::of(&body);
        body.extend_from_slice(&id.0);
        assert!(Catalog::decode(&body).is_err());
    }
    let mut body = encoded[..encoded.len() - 32].to_vec();
    body.push(0);
    let id = ContentId::of(&body);
    body.extend_from_slice(&id.0);
    assert_eq!(Catalog::decode(&body), Err(Error::Shape));
}
