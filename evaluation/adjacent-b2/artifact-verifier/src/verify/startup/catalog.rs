//! Independent syntax decoder and joins. Production Catalog::decode/new and
//! catalog_from_plans are deliberately never called by this verifier.
use super::*;
const RECORDS: usize = 65_536;
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    records: usize,
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).ok_or("catalog range overflow")?;
        let bytes = self.bytes.get(self.at..end).ok_or("catalog truncated")?;
        self.at = end;
        Ok(bytes)
    }
    fn n(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(checked(self.take(8)?.try_into())?))
    }
    fn count(&mut self, cap: usize) -> Result<usize> {
        let n = host(self.n()?)?;
        require(n <= cap, "catalog count before allocation")?;
        Ok(n)
    }
    fn records(&mut self, cap: usize) -> Result<usize> {
        let n = self.count(cap)?;
        self.records = self.records.checked_sub(n).ok_or("catalog total records")?;
        Ok(n)
    }
    fn bytes(&mut self, cap: usize) -> Result<Vec<u8>> {
        let n = self.count(cap)?;
        Ok(self.take(n)?.to_vec())
    }
    fn span(&mut self) -> Result<boot::Span> {
        Ok(boot::Span {
            start: self.n()?,
            len: self.n()?,
        })
    }
    fn blob(&mut self) -> Result<boot::Blob> {
        Ok(boot::Blob {
            address: self.n()?,
            bytes: self.bytes(FILE)?,
        })
    }
    fn blobs(&mut self) -> Result<Vec<boot::Blob>> {
        let n = self.records(RECORDS)?;
        (0..n).map(|_| self.blob()).collect()
    }
    fn pairs(&mut self) -> Result<Vec<(u64, u64)>> {
        let n = self.records(RECORDS)?;
        (0..n).map(|_| Ok((self.n()?, self.n()?))).collect()
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<boot::Input> {
    decode_mode(bytes, None)
}
pub(super) fn decode_absolute_prerequisites(bytes: &[u8], policy: &Policy) -> Result<boot::Input> {
    require(
        policy.absolute_prerequisites.is_some(),
        "explicit absolute prerequisite catalog policy",
    )?;
    decode_mode(bytes, Some(policy))
}
fn decode_mode(bytes: &[u8], absolute: Option<&Policy>) -> Result<boot::Input> {
    // The existing W01 product-member bound remains 16 MiB, even though the
    // runtime codec also supports larger catalogs in other clients.
    require((56..=FILE).contains(&bytes.len()), "catalog W01 file cap")?;
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    require(
        ContentId::of(body).0.as_slice() == checksum,
        "catalog envelope checksum",
    )?;
    let mut r = Reader {
        bytes: body,
        at: 0,
        records: RECORDS,
    };
    require(
        r.take(8)? == b"LI2BOOT\0" && r.n()? == (if absolute.is_some() { 3 } else { 2 }),
        if absolute.is_some() {
            "catalog explicit v3 wire"
        } else {
            "catalog explicit v2 wire"
        },
    )?;
    let program = r.n()?;
    let roles = if absolute.is_some() {
        r.records = r.records.checked_sub(2).ok_or("catalog total records")?;
        Some([host(r.n()?)?, host(r.n()?)?])
    } else {
        None
    };
    let interpreter = r.bytes(4095)?;
    let bootstrap_dso = r.bytes(4095)?;
    let n = r.records(16)?;
    let mut dependencies = Vec::new();
    for _ in 0..n {
        dependencies.push(boot::Dependency {
            path: r.bytes(4095)?,
            identity: ContentId(checked(r.take(32)?.try_into())?),
        });
    }
    if let (Some(policy), Some(indices)) = (absolute, roles) {
        require(
            indices[0] != indices[1]
                && indices.iter().all(|&i| i < dependencies.len())
                && Some(indices) == policy.absolute_prerequisites,
            "catalog exact absolute prerequisite roster indices",
        )?;
    }
    let app_stack = r.span()?;
    let hook_pc = r.n()?;
    let hook_id = r.n()?;
    let qualification_contract = ContentId(checked(r.take(32)?.try_into())?);
    let mut state = boot::State {
        domain: r.n()?,
        format: r.n()?,
        allocation: r.n()?,
        image: r.n()?,
        mask: r.n()?,
        components: Vec::new(),
    };
    let n = r.records(64)?;
    for _ in 0..n {
        state.components.push((r.n()?, r.n()?, r.n()?));
    }
    let original = r.bytes(FILE)?;
    let main = r.bytes(FILE)?;
    let selection = r.bytes(TEXT)?;
    let metadata = r.bytes(TEXT)?;
    let target = r.bytes(POLICY_BYTES)?;
    let ledger = r.bytes(FILE)?;
    let n = r.records(107)?;
    let heads = (0..n).map(|_| r.n()).collect::<Result<Vec<_>>>()?;
    let n = r.records(4096)?;
    let mut steps = Vec::new();
    for _ in 0..n {
        let selected_id = r.n()?;
        let logical = r.n()?;
        let physical = r.n()?;
        let displaced = r.span()?;
        let tag = r.n()?;
        let kind = match tag {
            0 => boot::Kind::Relocation,
            1 | 2 => {
                let p = boot::Pun {
                    instruction_len: r.n()?,
                    prefixes: r.n()?,
                    consumed: r.span()?,
                    target_window: r.span()?,
                    store: r.span()?,
                };
                if tag == 1 {
                    boot::Kind::GeneralizedPun(p)
                } else {
                    boot::Kind::PrefixedPun(p)
                }
            }
            _ => return Err("catalog kind tag".into()),
        };
        let neighbor = match r.n()? {
            0 => None,
            1 => Some(boot::Neighbor {
                selected: r.n()?,
                selected_len: r.n()?,
                victim: r.n()?,
                victim_len: r.n()?,
                relay: r.n()?,
                rel8: checked(u8::try_from(r.n()?))? as i8,
                selected_target: r.n()?,
                victim_target: r.n()?,
            }),
            _ => return Err("catalog neighbor tag".into()),
        };
        let reads = r.blobs()?;
        let writes = r.blobs()?;
        let n = r.records(RECORDS)?;
        let dependencies = (0..n).map(|_| r.span()).collect::<Result<Vec<_>>>()?;
        let allocation = r.span()?;
        let image = r.n()?;
        let n = r.records(RECORDS)?;
        let mut obligations = Vec::new();
        for _ in 0..n {
            let original = r.n()?;
            let tag = r.n()?;
            let target = r.n()?;
            let generated = match (tag, target) {
                (0, 0) => None,
                (1, t) if t != 0 => Some(t),
                _ => return Err("catalog obligation tag".into()),
            };
            obligations.push(boot::Obligation {
                original,
                generated,
            });
        }
        steps.push(boot::Step {
            selected_id,
            logical,
            physical,
            displaced,
            kind,
            neighbor,
            reads,
            writes,
            dependencies,
            allocation,
            image,
            obligations,
        });
    }
    let n = r.records(4096)?;
    let mut images = Vec::new();
    for _ in 0..n {
        images.push(boot::Image {
            body: r.blob()?,
            entries: r.pairs()?,
            requirements: r.pairs()?,
        });
    }
    require(r.at == body.len(), "catalog exact end")?;
    Ok(boot::Input {
        program,
        policy: boot::Policy {
            interpreter,
            bootstrap_dso,
            dependencies,
            app_stack,
            hook_pc,
            hook_id,
            state,
            qualification_contract,
        },
        original,
        main,
        selection,
        metadata,
        target,
        ledger,
        heads,
        steps,
        images,
    })
}
fn span(r: Range) -> boot::Span {
    boot::Span {
        start: r.start,
        len: r.len(),
    }
}
fn blob((address, bytes): &(u64, Vec<u8>)) -> boot::Blob {
    boot::Blob {
        address: *address,
        bytes: bytes.clone(),
    }
}
fn image_for<'a>(plan: &'a ledger::Plan, step: &ledger::Step) -> Result<&'a ledger::Image> {
    let allocation = step.allocation.ok_or("catalog expected allocation")?;
    let matched: Vec<_> = plan
        .images
        .iter()
        .filter(|i| hull(i.entry, i.bytes.len()).ok() == Some(allocation))
        .collect();
    require(matched.len() == 1, "catalog exact step image owner")?;
    Ok(matched[0])
}
fn kind(step: &ledger::Step) -> Result<boot::Kind> {
    if step.kind == "relocation" {
        return Ok(boot::Kind::Relocation);
    }
    let (pc, write) = step.write.as_ref().ok_or("catalog expected source write")?;
    let prefixes = write.iter().take_while(|&&b| b == 0x2e).count();
    let instruction_len = host(step.displaced.len())?;
    require(
        prefixes < instruction_len
            && (1..=4).contains(&instruction_len)
            && write.get(prefixes) == Some(&0xe9),
        "catalog independent pun source geometry",
    )?;
    let consumed = Range::bytes(*pc, 5 + prefixes)?;
    let (read_pc, read) = step.read.as_ref().ok_or("catalog expected source read")?;
    let original = slice(
        read,
        pc.checked_sub(*read_pc)
            .ok_or("catalog consumed read address")?,
        consumed.len(),
    )?;
    let free = instruction_len - prefixes - 1;
    let mut fixed = [0; 4];
    fixed[free..].copy_from_slice(&original[instruction_len..]);
    let low = checked(u64::try_from(
        i128::from(consumed.end) + i128::from(i32::from_le_bytes(fixed)),
    ))?;
    let (store_pc, stored) = step.store.as_ref().ok_or("catalog expected live store")?;
    let pun = boot::Pun {
        instruction_len: instruction_len as u64,
        prefixes: prefixes as u64,
        consumed: span(consumed),
        target_window: boot::Span {
            start: low,
            len: 1u64 << (free * 8),
        },
        store: boot::Span {
            start: *store_pc,
            len: stored.len() as u64,
        },
    };
    match step.kind.as_str() {
        "generalized-pun" => {
            require(prefixes == 0, "catalog generalized prefix count")?;
            Ok(boot::Kind::GeneralizedPun(pun))
        }
        "prefixed-pun" => {
            require(prefixes > 0, "catalog prefixed prefix count")?;
            Ok(boot::Kind::PrefixedPun(pun))
        }
        _ => Err("catalog expected kind".into()),
    }
}
fn neighbor(
    plan: &ledger::Plan,
    selected_pc: u64,
    selected_len: u64,
) -> Result<Option<boot::Neighbor>> {
    if !plan.relay {
        return Ok(None);
    }
    let chosen = plan
        .steps
        .iter()
        .find(|s| s.logical == selected_pc)
        .ok_or("catalog neighbor selected")?;
    let victim = plan
        .steps
        .iter()
        .find(|s| s.logical != selected_pc)
        .ok_or("catalog neighbor victim")?;
    let relay = add(victim.physical, 5)?;
    Ok(Some(boot::Neighbor {
        selected: selected_pc,
        selected_len,
        victim: victim.physical,
        victim_len: victim.displaced.len(),
        relay,
        rel8: checked(i8::try_from(
            i128::from(relay) - i128::from(add(selected_pc, 2)?),
        ))?,
        selected_target: image_for(plan, chosen)?.entry,
        victim_target: image_for(plan, victim)?.entry,
    }))
}
pub(super) fn expected_records(
    facts: &Facts,
    joined: &ledger::Joined,
) -> Result<(Vec<boot::Step>, Vec<boot::Image>)> {
    let mut steps = Vec::new();
    let mut images = Vec::new();
    for plan in &joined.plans {
        let selected = &facts.selection.sites[host(plan.owner - 1)?];
        let neighbor = neighbor(plan, selected.pc, u64::from(selected.length))?;
        for s in &plan.steps {
            let read = s.read.as_ref().ok_or("catalog expected read")?;
            let mut writes = vec![blob(s.write.as_ref().ok_or("catalog expected write")?)];
            if let Some(store) = &s.store {
                writes.push(blob(store));
            }
            steps.push(boot::Step {
                selected_id: s.owner,
                logical: s.logical,
                physical: s.physical,
                displaced: span(s.displaced),
                kind: kind(s)?,
                neighbor,
                reads: vec![blob(read)],
                writes,
                dependencies: vec![boot::Span {
                    start: read.0,
                    len: read.1.len() as u64,
                }],
                allocation: span(s.allocation.ok_or("catalog expected allocation")?),
                image: image_for(plan, s)?.entry,
                obligations: s
                    .entries
                    .iter()
                    .map(|&(original, generated)| boot::Obligation {
                        original,
                        generated,
                    })
                    .collect(),
            });
        }
        for i in &plan.images {
            images.push(boot::Image {
                body: boot::Blob {
                    address: i.entry,
                    bytes: i.bytes.clone(),
                },
                entries: i.routes.iter().map(|(&a, &b)| (a, b)).collect(),
                requirements: i.requirements.clone(),
            });
        }
    }
    Ok((steps, images))
}
pub(super) struct Expected<'a> {
    pub policy: &'a Policy,
    pub original: &'a [u8],
    pub facts: &'a Facts,
    pub joined: &'a ledger::Joined,
    pub metadata: &'a [u8],
    pub candidate: &'a [u8],
    pub ledger: &'a [u8],
}
pub(super) fn join(x: &boot::Input, expected: Expected<'_>) -> Result<()> {
    let Expected {
        policy,
        original,
        facts,
        joined,
        metadata,
        candidate,
        ledger,
    } = expected;
    require(
        x.program == policy.program && x.policy == policy.runtime,
        "catalog complete independent policy",
    )?;
    require(
        x.original == original
            && x.main == candidate
            && x.selection == facts.full_selection
            && x.metadata == metadata
            && x.target == facts.target
            && x.ledger == ledger,
        "catalog complete source/main/selection/metadata/target/extended-ledger bytes",
    )?;
    require(
        x.heads == facts.heads.keys().copied().collect::<Vec<_>>(),
        "catalog complete original heads",
    )?;
    let (steps, images) = expected_records(facts, joined)?;
    require(
        x.steps.len() == steps.len(),
        "catalog complete selected and auxiliary steps",
    )?;
    for (actual, expected) in x.steps.iter().zip(&steps) {
        require(
            actual.selected_id == expected.selected_id
                && actual.logical == expected.logical
                && actual.physical == expected.physical
                && actual.displaced == expected.displaced,
            "catalog exact ordered step role and displaced geometry",
        )?;
        require(
            actual.kind == expected.kind,
            "catalog exact pun consumed/window/store geometry",
        )?;
        require(
            actual.neighbor == expected.neighbor,
            "catalog exact owned neighbor EB/E9 relay geometry",
        )?;
        require(
            actual.reads == expected.reads
                && actual.writes == expected.writes
                && actual.dependencies == expected.dependencies,
            "catalog exact overlay reads/writes/dependencies",
        )?;
        require(
            actual.allocation == expected.allocation && actual.image == expected.image,
            "catalog exact allocation/image bijection",
        )?;
        require(
            actual.obligations == expected.obligations,
            "catalog complete preserved and routed obligations",
        )?;
    }
    require(
        x.images.len() == images.len(),
        "catalog complete selected and auxiliary images",
    )?;
    for (actual, expected) in x.images.iter().zip(&images) {
        require(
            actual.body == expected.body,
            "catalog exact ordered image body",
        )?;
        require(
            actual.entries == expected.entries,
            "catalog exact image entry routes",
        )?;
        require(
            actual.requirements == expected.requirements,
            "catalog exact ordered unresolved requirements",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn step(length: usize, prefixes: usize) -> ledger::Step {
        let pc = 0x401000;
        let mut write = vec![0x2e; prefixes];
        write.push(0xe9);
        write.resize(length, 0x20);
        let mut store = vec![0; length.next_power_of_two()];
        store[..length].copy_from_slice(&write);
        ledger::Step {
            owner: 1,
            local: 0,
            kind: if prefixes == 0 {
                "generalized-pun"
            } else {
                "prefixed-pun"
            }
            .into(),
            logical: pc,
            physical: pc,
            displaced: Range::bytes(pc, length).unwrap(),
            read: Some((pc, vec![0; 16])),
            write: Some((pc, write)),
            store: Some((pc, store)),
            entries: vec![(pc, None)],
            allocation: Some(Range::bytes(0x600000, 4096).unwrap()),
            prerequisites: Some([true, true, false]),
            rank: 6,
        }
    }
    #[test]
    fn s10_every_pun_length_and_prefix_derives_exact_consumed_window_store() {
        for length in 1..=4 {
            for prefixes in 0..length {
                let source = step(length, prefixes);
                let value = kind(&source).unwrap();
                let p = match value {
                    boot::Kind::GeneralizedPun(p) | boot::Kind::PrefixedPun(p) => p,
                    _ => panic!("pun kind"),
                };
                assert_eq!(p.instruction_len, length as u64);
                assert_eq!(p.prefixes, prefixes as u64);
                assert_eq!(
                    p.consumed,
                    boot::Span {
                        start: 0x401000,
                        len: 5 + prefixes as u64
                    }
                );
                assert_eq!(
                    p.target_window,
                    boot::Span {
                        start: 0x401005 + prefixes as u64,
                        len: 1u64 << (8 * (length - prefixes - 1))
                    }
                );
                assert_eq!(
                    p.store,
                    boot::Span {
                        start: 0x401000,
                        len: length.next_power_of_two() as u64
                    }
                );
                assert_eq!(
                    matches!(value, boot::Kind::GeneralizedPun(_)),
                    prefixes == 0
                );
            }
        }
        let mut bad = step(3, 1);
        bad.kind = "generalized-pun".into();
        assert_eq!(
            kind(&bad).err(),
            Some("catalog generalized prefix count".into())
        );
        let mut bad = step(3, 0);
        bad.kind = "prefixed-pun".into();
        assert_eq!(
            kind(&bad).err(),
            Some("catalog prefixed prefix count".into())
        );
    }
    #[test]
    fn s12_neighbor_geometry_derivation_uses_both_owned_images() {
        // This isolates the derivation from already-checked ledger records. It
        // does not claim a complete T3 artifact: full ledger validity is a
        // separate precondition exercised by the existing source joins.
        let selected = 0x401020;
        let victim = 0x401000;
        let mut chosen = step(2, 0);
        chosen.kind = "relocation".into();
        chosen.logical = selected;
        chosen.physical = selected;
        chosen.displaced = Range::bytes(selected, 2).unwrap();
        chosen.allocation = Some(Range::bytes(0x600000, 4096).unwrap());
        let mut auxiliary = step(4, 0);
        auxiliary.kind = "relocation".into();
        auxiliary.local = 1;
        auxiliary.logical = victim;
        auxiliary.physical = victim;
        auxiliary.displaced = Range::bytes(victim, 6).unwrap();
        auxiliary.allocation = Some(Range::bytes(0x700000, 4096).unwrap());
        let image = |id, entry| ledger::Image {
            id,
            owner: 1,
            entry,
            bytes: vec![0x90],
            routes: BTreeMap::new(),
            boundaries: BTreeMap::new(),
            maps: Vec::new(),
            fields: Vec::new(),
            requirements: Vec::new(),
            rank: 0,
        };
        let mut plan = ledger::Plan {
            owner: 1,
            steps: vec![chosen, auxiliary],
            images: vec![image(0, 0x600000), image(1, 0x700000)],
            relay: true,
        };
        assert_eq!(
            neighbor(&plan, selected, 2).unwrap(),
            Some(boot::Neighbor {
                selected,
                selected_len: 2,
                victim,
                victim_len: 6,
                relay: victim + 5,
                rel8: -29,
                selected_target: 0x600000,
                victim_target: 0x700000
            })
        );
        plan.images.push(image(2, 0x700000));
        assert_eq!(
            neighbor(&plan, selected, 2).err(),
            Some("catalog exact step image owner".into())
        );
    }

    #[test]
    fn r3_catalog_total_records_equal_cap_and_next_record() {
        assert_eq!(RECORDS, 65536);
        let mut bytes = Vec::new();
        for n in [32768u64, 32768, 1] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        let mut r = Reader {
            bytes: &bytes,
            at: 0,
            records: RECORDS,
        };
        assert_eq!(r.records(RECORDS).unwrap(), 32768);
        assert_eq!(r.records(RECORDS).unwrap(), 32768);
        assert_eq!(r.records, 0);
        assert_eq!(
            r.records(RECORDS).err(),
            Some("catalog total records".into())
        );
        let count = (RECORDS as u64 + 1).to_le_bytes();
        let mut r = Reader {
            bytes: &count,
            at: 0,
            records: RECORDS,
        };
        assert_eq!(
            r.records(RECORDS).err(),
            Some("catalog count before allocation".into())
        );
    }
}
