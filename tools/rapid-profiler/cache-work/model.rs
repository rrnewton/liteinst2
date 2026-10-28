//! Fixed demand-read model for the original linked leaf: 64-byte lines,
//! four sets, two ways, true LRU, all invalid at each invocation. No prefetch,
//! instruction fetch, speculation, writes, translation or hardware-miss claim.
//! The final original RET operand uses its actual stack address in this cache.
use super::truth::{Case, INPUT_BYTES, Read, ReadKind, expected_misses};

const LINE: u64 = 64;
const SETS: usize = 4;
const WAYS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Address,
    Trace,
    Policy,
    Count,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    pub accesses: usize,
    pub hits: usize,
    pub misses: usize,
    pub hit_by_read: Vec<bool>,
}

// Each set stores MRU then LRU. Full line identifiers retain all address bits.
fn lru(lines: &[u64]) -> Vec<bool> {
    let mut sets = [[None; WAYS]; SETS];
    let mut hits = Vec::with_capacity(lines.len());
    for &line in lines {
        let set = &mut sets[(line % SETS as u64) as usize];
        let hit = set.contains(&Some(line));
        if set[0] != Some(line) {
            set[1] = set[0];
            set[0] = Some(line);
        }
        hits.push(hit);
    }
    hits
}

// Separate formulation: no mutable cache ways, ages or replacement order.
// Count distinct same-set competitors strictly since the previous same line.
fn reuse_distance(lines: &[u64]) -> Vec<bool> {
    lines
        .iter()
        .enumerate()
        .map(|(i, &line)| {
            let Some(previous) = lines[..i].iter().rposition(|&p| p == line) else {
                return false;
            };
            let competitors: std::collections::BTreeSet<_> = lines[previous + 1..i]
                .iter()
                .copied()
                .filter(|p| p % SETS as u64 == line % SETS as u64)
                .collect();
            competitors.len() < WAYS
        })
        .collect()
}

fn operand(read: &Read, kind: ReadKind, address: u64) -> bool {
    read.kind == kind && read.address == address && read.width == 8
}

/// Check the closed case's complete trace shape and every per-read cache result.
/// `reads` must already have been authenticated against actual original native
/// operands, literal instruction truth and independent expected_reads(). This
/// model does not authenticate execution, payload values or the saved RET value.
pub fn check(case: Case, data: u64, entry_rsp: u64, reads: &[Read]) -> Result<Summary, Error> {
    let end = data.checked_add(INPUT_BYTES as u64).ok_or(Error::Address)?;
    let stack_end = entry_rsp.checked_add(8).ok_or(Error::Address)?;
    let stack_line = entry_rsp / LINE;
    if data % LINE != 0
        || stack_line != (stack_end - 1) / LINE
        || (data / LINE..=(end - 1) / LINE).contains(&stack_line)
    {
        return Err(Error::Address);
    }
    let n = case.iterations();
    if reads.len() != 2 * n + 2 {
        return Err(Error::Trace);
    }
    for read in reads {
        let end = read
            .address
            .checked_add(u64::from(read.width))
            .ok_or(Error::Address)?;
        if read.width != 8 || read.address / LINE != (end - 1) / LINE {
            return Err(Error::Address);
        }
    }
    if !operand(&reads[0], ReadKind::Count, data + 16) || reads[0].value != n as u64 {
        return Err(Error::Trace);
    }
    let cycle = case.cycle();
    for j in 0..n {
        let node = cycle[j % cycle.len()];
        let next = cycle[(j + 1) % cycle.len()];
        if !operand(
            &reads[1 + 2 * j],
            ReadKind::Payload,
            data + (node * 64 + 8) as u64,
        ) || !operand(&reads[2 + 2 * j], ReadKind::Link, data + (node * 64) as u64)
            || reads[2 + 2 * j].value != (next * 64) as u64
        {
            return Err(Error::Trace);
        }
    }
    if !operand(&reads[2 * n + 1], ReadKind::ReturnWord, entry_rsp) {
        return Err(Error::Trace);
    }
    let lines: Vec<_> = reads.iter().map(|r| r.address / LINE).collect();
    let hit_by_read = lru(&lines);
    if hit_by_read != reuse_distance(&lines) {
        return Err(Error::Policy);
    }
    let hits = hit_by_read.iter().filter(|&&hit| hit).count();
    let misses = reads.len() - hits;
    if misses != expected_misses(case) {
        return Err(Error::Count);
    }
    Ok(Summary {
        accesses: reads.len(),
        hits,
        misses,
        hit_by_read,
    })
}

#[cfg(test)]
mod tests {
    use super::super::truth::{ALL, expected_reads};
    use super::*;
    const DATA: u64 = 0x2000;
    const STACK: u64 = 0x4008;
    fn reads(case: Case) -> Vec<Read> {
        expected_reads(case, 17, DATA, STACK, 0x5000).unwrap()
    }
    #[test]
    fn cache_model_literal_case_totals_and_set_rotation() {
        let expected = [
            (130, 125, 5),
            (34, 17, 17),
            (130, 121, 9),
            (130, 127, 3),
            (130, 65, 65),
            (130, 65, 65),
        ];
        for (case, (accesses, hits, misses)) in ALL.into_iter().zip(expected) {
            for rotation in 0..4 {
                let base = DATA + rotation * 64;
                let operands = expected_reads(case, 17, base, STACK, 0x5000).unwrap();
                let got = check(case, base, STACK, &operands).unwrap();
                assert_eq!(
                    (got.accesses, got.hits, got.misses),
                    (accesses, hits, misses)
                );
                assert_eq!(got.hit_by_read.first(), Some(&false)); // count read is compulsory
                assert_eq!(got.hit_by_read.last(), Some(&false)); // actual RET line participates
            }
        }
    }
    #[test]
    fn cache_model_literal_lru_policy_discriminator() {
        // All lines are in one set. FIFO would hit the final4; LRU must miss.
        // This is a model-only policy control, not a seventh native case.
        let lines = [0, 4, 0, 8, 4];
        let expected = [false, false, true, false, false];
        assert_eq!(lru(&lines), expected);
        assert_eq!(reuse_distance(&lines), expected);
        assert_eq!(lru(&[0, 4, 0, 4]), [false, false, true, true]);
        assert_eq!(lru(&[0, 4, 8, 0]), [false, false, false, false]);
    }
    #[test]
    fn cache_model_literal_per_operand_miss_positions() {
        let got = check(Case::Conflict3, DATA, STACK, &reads(Case::Conflict3)).unwrap();
        let mut expected = vec![false, true, true]; // header, first payload, first link
        for _ in 1..64 {
            expected.extend([false, true]);
        }
        expected.push(false); // distinct actual RET
        assert_eq!(got.hit_by_read, expected);
        let got = check(Case::Reuse4, DATA, STACK, &reads(Case::Reuse4)).unwrap();
        let mut expected = vec![false, true, true, false, true, false, true, false, true];
        expected.extend([true; 120]); // remaining60 complete payload/link pairs
        expected.push(false);
        assert_eq!(got.hit_by_read, expected);
    }
    #[test]
    fn cache_model_missing_duplicate_reordered_or_relabelled_reads_refused() {
        let original = reads(Case::Chase8);
        for index in [0, 1, 2, original.len() - 1] {
            let mut changed = original.clone();
            changed.remove(index);
            assert_eq!(
                check(Case::Chase8, DATA, STACK, &changed),
                Err(Error::Trace)
            );
            let mut changed = original.clone();
            changed.insert(index, original[index]);
            assert_eq!(
                check(Case::Chase8, DATA, STACK, &changed),
                Err(Error::Trace)
            );
        }
        let mut changed = original.clone();
        changed.swap(1, 2);
        assert_eq!(
            check(Case::Chase8, DATA, STACK, &changed),
            Err(Error::Trace)
        );
        assert_eq!(
            check(Case::Reuse4, DATA, STACK, &original),
            Err(Error::Trace)
        );
        for index in [0, 2] {
            let mut changed = original.clone();
            changed[index].value ^= 64;
            assert_eq!(
                check(Case::Chase8, DATA, STACK, &changed),
                Err(Error::Trace)
            );
        }
        let mut changed = original;
        changed[1].kind = ReadKind::Link;
        assert_eq!(
            check(Case::Chase8, DATA, STACK, &changed),
            Err(Error::Trace)
        );
    }
    #[test]
    fn cache_model_foreign_cross_line_width_and_wrap_refused() {
        let original = reads(Case::Fit2);
        let mut changed = original.clone();
        changed[1].address += 1024;
        assert_eq!(check(Case::Fit2, DATA, STACK, &changed), Err(Error::Trace));
        let mut changed = original.clone();
        changed[1].width = 4;
        assert_eq!(
            check(Case::Fit2, DATA, STACK, &changed),
            Err(Error::Address)
        );
        let mut changed = original.clone();
        changed[1].address = DATA + 60;
        assert_eq!(
            check(Case::Fit2, DATA, STACK, &changed),
            Err(Error::Address)
        );
        let mut changed = original.clone();
        changed[1].address = u64::MAX - 3;
        assert_eq!(
            check(Case::Fit2, DATA, STACK, &changed),
            Err(Error::Address)
        );
        for (data, stack) in [
            (DATA + 1, STACK),
            (u64::MAX - 63, STACK),
            (DATA, DATA + 8),
            (DATA, 0x403c),
            (DATA, u64::MAX - 3),
        ] {
            assert_eq!(
                check(Case::Fit2, data, stack, &original),
                Err(Error::Address)
            );
        }
    }
    #[test]
    fn cache_model_ret_uses_full_address_and_each_call_starts_invalid() {
        // Input and return addresses share low32 bits; the distinct actual
        // stack line must not be folded onto an existing input line.
        let high_stack = (1_u64 << 32) + DATA + 8;
        let operands = expected_reads(Case::Fit2, 17, DATA, high_stack, 0x5000).unwrap();
        let first = check(Case::Fit2, DATA, high_stack, &operands).unwrap();
        assert_eq!((first.misses, first.hits), (3, 127));
        assert_eq!(first.hit_by_read.last(), Some(&false));
        let second = check(Case::Fit2, DATA, high_stack, &operands).unwrap();
        assert_eq!(first, second);
        assert_eq!(second.hit_by_read.first(), Some(&false));
    }
}
