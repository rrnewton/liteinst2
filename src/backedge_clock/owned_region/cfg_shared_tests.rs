//! Explicit acceptance/refusal controls for the shared-CFG consumers.
//! These bytes are decoded only; no authored source is executed or mapped.
use super::*;
use crate::backedge_clock::owned_loop;

const BASE: u64 = 0x100000;
const CONDITIONS: [Option<u8>; 4] = [Some(5), Some(15), Some(2), None];

fn edge(bytes: &mut Vec<u8>, condition: Option<u8>, target: usize) -> usize {
    let site = bytes.len();
    if let Some(condition) = condition {
        bytes.extend([0x0f, 0x80 | condition]);
    } else {
        bytes.push(0xe9);
    }
    let displacement = i32::try_from(target as i64 - (bytes.len() + 4) as i64).unwrap();
    bytes.extend(displacement.to_le_bytes());
    site
}

fn body(bytes: &mut Vec<u8>, condition: Option<u8>) -> usize {
    let target = bytes.len();
    bytes.extend([0x83, 0xc0, 1, 0x85, 0xc9]); // ADD EAX,1; TEST ECX,ECX.
    bytes.extend([0x74, if condition.is_some() { 6 } else { 5 }]);
    edge(bytes, condition, target)
}

fn single(prefix: &[u8], condition: Option<u8>) -> (Vec<u8>, usize) {
    let mut bytes = prefix.to_vec();
    let site = body(&mut bytes, condition);
    bytes.push(0xc3);
    (bytes, site)
}

fn double(prefix: &[u8], conditions: [Option<u8>; 2]) -> (Vec<u8>, [usize; 2]) {
    let mut bytes = prefix.to_vec();
    let sites = conditions.map(|condition| body(&mut bytes, condition));
    bytes.push(0xc3);
    (bytes, sites)
}

fn check_loop(bytes: &[u8], base: u64, pc: u64, expected: Result<Option<u8>, ClockError>) {
    assert_eq!(owned_loop::admit(bytes, base, pc), expected, "{bytes:02x?}");
}

fn check_region(
    bytes: &[u8],
    base: u64,
    sites: [u64; 2],
    expected: Result<[Option<u8>; 2], ClockError>,
) {
    assert_eq!(
        super::admit(bytes, base, sites).map(|(scan, conditions)| {
            assert_eq!(scan.snapshot(), bytes);
            assert_eq!(scan.instructions().first().unwrap().address(), base);
            assert_eq!(
                scan.instructions().last().unwrap().instruction().next_ip(),
                base.checked_add(bytes.len() as u64).unwrap()
            );
            conditions
        }),
        expected,
        "{bytes:02x?}"
    );
}

#[test]
fn owned_cfg_shared_positive_graphs_and_distinct_scalar_profiles() {
    // Conditional target == fallthrough keeps both edges; direct forward JMP
    // and near Jcc preserve the same complete all-head reachability policy.
    let prefixes: &[&[u8]] = &[
        &[],
        &[0x74, 0],
        &[0xeb, 0],
        &[0x0f, 0x84, 0, 0, 0, 0],
        &[0xe9, 0, 0, 0, 0],
    ];
    for prefix in prefixes {
        for first in CONDITIONS {
            let (bytes, site) = single(prefix, first);
            check_loop(&bytes, BASE, BASE + site as u64, Ok(first));
            for second in CONDITIONS {
                let (bytes, sites) = double(prefix, [first, second]);
                check_region(
                    &bytes,
                    BASE,
                    sites.map(|x| BASE + x as u64),
                    Ok([first, second]),
                );
            }
        }
    }

    // The old one-site loop admits memory/LEA and callee-saved GPRs, unlike
    // the scalar region. The region admits ADC/MOVZX, unlike the old loop.
    let wider_loop: &[&[u8]] = &[&[0x8b, 0], &[0x48, 0x8d, 0], &[0xbb, 1, 0, 0, 0]];
    let wider_region: &[&[u8]] = &[&[0x83, 0xd0, 1], &[0x0f, 0xb6, 0xc8]];
    for prefix in wider_loop {
        let (bytes, site) = single(prefix, Some(5));
        check_loop(&bytes, BASE, BASE + site as u64, Ok(Some(5)));
        let (bytes, sites) = double(prefix, [Some(5), Some(15)]);
        check_region(
            &bytes,
            BASE,
            sites.map(|x| BASE + x as u64),
            Err(ClockError::Source),
        );
    }
    for prefix in wider_region {
        let (bytes, site) = single(prefix, Some(5));
        check_loop(&bytes, BASE, BASE + site as u64, Err(ClockError::Source));
        let (bytes, sites) = double(prefix, [Some(5), Some(15)]);
        check_region(
            &bytes,
            BASE,
            sites.map(|x| BASE + x as u64),
            Ok([Some(5), Some(15)]),
        );
    }
}

#[test]
fn owned_cfg_shared_refusals_and_exact_backedge_rosters() {
    let forbidden: &[&[u8]] = &[
        &[0xe8, 0, 0, 0, 0], // Direct call: local continuation is not permission.
        &[0xff, 0xd0],
        &[0xff, 0xe0], // Indirect call and branch.
        &[0x50],
        &[0x58],
        &[0xc3],
        &[0x64, 0x8b, 0],
        &[0xf3, 0x90],
        &[0x0f, 0x05],
        &[0xcc],
        &[0x48, 0x89, 0xe0], // RSP operand.
        &[0xeb, 1, 0x90],    // Unreachable NOP is still forbidden here.
        &[0xeb, 1, 0xcc],    // Unreachable unsupported row is validated, not skipped.
        &[0xeb, 0xfe],
        &[0xe3, 0], // Self JMP; JRCXZ despite representable edges.
    ];
    for prefix in forbidden {
        let (bytes, site) = single(prefix, Some(5));
        check_loop(&bytes, BASE, BASE + site as u64, Err(ClockError::Source));
        let (bytes, sites) = double(prefix, [Some(5), Some(15)]);
        check_region(
            &bytes,
            BASE,
            sites.map(|x| BASE + x as u64),
            Err(ClockError::Source),
        );
    }
    let (bytes, site) = single(&[], Some(5));
    for pc in [
        BASE - 1,
        BASE,
        BASE + site as u64 + 1,
        BASE + bytes.len() as u64,
    ] {
        check_loop(&bytes, BASE, pc, Err(ClockError::Source));
    }
    for target in [-1, 1, site as i64, (site + 6) as i64] {
        let mut changed = bytes.clone();
        let displacement = i32::try_from(target - (site + 6) as i64).unwrap();
        changed[site + 2..site + 6].copy_from_slice(&displacement.to_le_bytes());
        check_loop(&changed, BASE, BASE + site as u64, Err(ClockError::Source));
    }
    let (bytes, sites) = double(&[], [Some(5), Some(15)]);
    for supplied in [
        [sites[0], sites[0]],
        [sites[1], sites[0]],
        [sites[0] + 1, sites[1]],
        [sites[0], sites[1] + 1],
    ] {
        check_region(
            &bytes,
            BASE,
            supplied.map(|x| BASE + x as u64),
            Err(ClockError::Source),
        );
    }
    for site in sites {
        let mut changed = bytes.clone();
        changed[site..site + 6].fill(0x90);
        check_region(
            &changed,
            BASE,
            sites.map(|x| BASE + x as u64),
            Err(ClockError::Source),
        );
        let mut changed = bytes.clone();
        changed[site + 1] = 0x84; // Backward JZ is outside both profiles.
        check_region(
            &changed,
            BASE,
            sites.map(|x| BASE + x as u64),
            Err(ClockError::Source),
        );
    }
}

#[test]
fn owned_cfg_shared_region_returnability_is_not_added_to_loop() {
    // All heads are reachable, but the NOP/JMP SCC cannot reach final RET.
    // The old one-backedge loop accepts this; do not silently add region policy.
    let single_no_exit = [
        0x85, 0xc9, 0x74, 6, 0x90, 0xe9, 0xfa, 0xff, 0xff, 0xff, 0xc3,
    ];
    check_loop(&single_no_exit, BASE, BASE + 5, Ok(None));
    let double_no_exit = [
        0x85, 0xc9, 0x74, 6, 0x90, 0xe9, 0xfa, 0xff, 0xff, 0xff, 0x90, 0x0f, 0x85, 0xf9, 0xff,
        0xff, 0xff, 0xc3,
    ];
    check_region(
        &double_no_exit,
        BASE,
        [BASE + 5, BASE + 11],
        Err(ClockError::Source),
    );
    for terminal in [&[0x90][..], &[0xc2, 0, 0], &[0xf3, 0xc3], &[0xc3, 0x90]] {
        let (mut bytes, site) = single(&[], Some(5));
        bytes.pop();
        bytes.extend(terminal);
        check_loop(&bytes, BASE, BASE + site as u64, Err(ClockError::Source));
        let (mut bytes, sites) = double(&[], [Some(5), Some(15)]);
        bytes.pop();
        bytes.extend(terminal);
        check_region(
            &bytes,
            BASE,
            sites.map(|x| BASE + x as u64),
            Err(ClockError::Source),
        );
    }
}

#[test]
fn owned_cfg_shared_size_address_and_supplied_scan_guards() {
    let (mut bytes, site) = single(&[], Some(5));
    bytes.pop();
    bytes.resize(255, 0x90);
    bytes.push(0xc3);
    check_loop(&bytes, BASE, BASE + site as u64, Ok(Some(5)));
    bytes.insert(255, 0x90);
    check_loop(&bytes, BASE, BASE + site as u64, Err(ClockError::Source));
    check_loop(&[], BASE, BASE, Err(ClockError::Source));
    let (mut bytes, sites) = double(&[], [Some(5), Some(15)]);
    bytes.pop();
    bytes.resize(79, 0x90);
    bytes.push(0xc3);
    check_region(
        &bytes,
        BASE,
        sites.map(|x| BASE + x as u64),
        Ok([Some(5), Some(15)]),
    );
    bytes.insert(79, 0x90);
    check_region(
        &bytes,
        BASE,
        sites.map(|x| BASE + x as u64),
        Err(ClockError::Source),
    );
    for small in [&[][..], &[0x90, 0x90, 0x90, 0xc3]] {
        check_region(small, BASE, [BASE, BASE + 1], Err(ClockError::Source));
    }
    let (bytes, site) = single(&[], Some(5));
    for base in [0, u64::MAX - 3] {
        check_loop(&bytes, base, site as u64, Err(ClockError::Source));
    }
    let (bytes, offsets) = double(&[], [Some(5), Some(15)]);
    let sites = offsets.map(|x| BASE + x as u64);
    for base in [0, u64::MAX - 3] {
        check_region(&bytes, base, sites, Err(ClockError::Source));
    }
    let scanner = InstructionScanner::default();
    let valid = scanner.scan(&bytes, BASE).unwrap();
    let wrong_base = scanner.scan(&bytes, BASE + 1).unwrap();
    let mut altered = bytes.clone();
    altered[1] = 0xe8; // Same-length SUB instead of ADD.
    let wrong_source = scanner.scan(&altered, BASE).unwrap();
    for scan in [&wrong_base, &wrong_source] {
        assert_eq!(
            super::admit_scan(&bytes, BASE, sites, scan),
            Err(ClockError::Source)
        );
    }
    for supplied_bytes in [&altered[..], &bytes[..bytes.len() - 1]] {
        assert_eq!(
            super::admit_scan(supplied_bytes, BASE, sites, &valid),
            Err(ClockError::Source)
        );
    }
    assert_eq!(
        super::admit_scan(&bytes, BASE, sites, &valid),
        Ok([Some(5), Some(15)])
    );
}
