use super::*;
#[path = "association.rs"]
mod association;
pub use association::Associations;

type EncodedField = (u64, usize, String, u64, i128, u64, Vec<u8>);
type SourceEdit = (u64, Vec<u8>);
type StepEdits = (Vec<Range>, Vec<SourceEdit>);

#[derive(Clone, Debug)]
struct Step {
    owner: u64,
    local: usize,
    kind: String,
    logical: u64,
    physical: u64,
    displaced: Range,
    read: Option<(u64, Vec<u8>)>,
    write: Option<(u64, Vec<u8>)>,
    store: Option<(u64, Vec<u8>)>,
    entries: Vec<(u64, Option<u64>)>,
    allocation: Option<Range>,
    prerequisites: Option<[bool; 3]>,
    rank: u8,
}
#[derive(Clone, Debug)]
struct Image {
    id: usize,
    owner: u64,
    entry: u64,
    bytes: Vec<u8>,
    routes: BTreeMap<u64, u64>,
    boundaries: BTreeMap<u64, u64>,
    maps: Vec<(Range, u64)>,
    fields: Vec<EncodedField>,
    requirements: Vec<(u64, u64)>,
    rank: u8,
}
struct Plan {
    owner: u64,
    steps: Vec<Step>,
    images: Vec<Image>,
    relay: bool,
}
pub struct Joined {
    pub associations: Associations,
    pub images: Vec<carrier::RxImage>,
    pub edits: Vec<carrier::DeclaredEdit>,
    pub dependencies: Vec<FileRange>,
}

fn ref_step<'a>(plans: &'a mut [Plan], row: &[&str], rank: u8) -> Result<&'a mut Step> {
    let plan = plans.last_mut().ok_or("step row without plan")?;
    require(
        plan.images.is_empty() && !plan.relay,
        "step row after image/relay",
    )?;
    let step = plan.steps.last_mut().ok_or("missing step")?;
    require(
        number(row[1])? == step.owner && host(number(row[2])?)? == step.local && rank >= step.rank,
        "step reference/order",
    )?;
    step.rank = rank;
    Ok(step)
}
fn ref_image<'a>(plans: &'a mut [Plan], row: &[&str], rank: u8) -> Result<&'a mut Image> {
    let image = plans
        .last_mut()
        .and_then(|p| p.images.last_mut())
        .ok_or("image row without image")?;
    require(
        host(number(row[1])?)? == image.id && rank >= image.rank,
        "image reference/order",
    )?;
    image.rank = rank;
    Ok(image)
}
fn row_range(a: &str, b: &str) -> Result<Range> {
    Range::new(number(a)?, number(b)?)
}
fn unique(map: &mut BTreeMap<u64, u64>, a: &str, b: &str) -> Result<()> {
    require(
        map.insert(number(a)?, number(b)?).is_none(),
        "duplicate original image map",
    )
}
fn parse(
    original: &[u8],
    f: &Facts,
    bytes: &[u8],
    files: &dyn Files,
) -> Result<(Vec<Plan>, Vec<Range>, Vec<FileRange>)> {
    let prefix = format!(
        "LI2LEDGER\t1\noriginal_sha256\t{}\nselection_sha256\t{}\nbias_policy\tcommon-additive-module-relative-v1\nbias_domain\t1\nqualification_complete\tfalse\nexecution_authority\tnone\ngrouping\tseparate-backing-only\nrequirement\t0\t101\tdeclared-entry-completeness-not-proven\nunresolved\tloader-abi-cpu-unwind-cet\nhook\t1\t4206592\t1\t{}\n",
        digest(original),
        digest(&f.full_selection),
        digest(&[0xc3])
    );
    require(
        bytes.starts_with(prefix.as_bytes()),
        "plan ledger exact prefix/hook",
    )?;
    let mut plans: Vec<Plan> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut next_image = 0;
    let mut locks = Vec::new();
    let mut deps = Vec::new();
    let mut footer = 0u8;
    for line in lines(&bytes[prefix.len()..])? {
        let row: Vec<_> = line.split('\t').collect();
        let tag = row.first().copied().ok_or("empty ledger row")?;
        if tag == "byte-lock" || tag == "original-file-dependency" {
            require(row.len() == 3 && !plans.is_empty(), "footer arity/plan")?;
            let r = row_range(row[1], row[2])?;
            if tag == "byte-lock" {
                require(footer <= 1, "lock after dependency")?;
                footer = 1;
                require(locks.len() < 1024, "lock count")?;
                locks.push(r);
            } else {
                footer = 2;
                require(deps.len() <= 64, "dependency count")?;
                deps.push(checked(FileRange::checked(FileOffset(r.start), r.len()))?);
            }
            continue;
        }
        require(footer == 0, "plan record after footer")?;
        match tag {
            "step" => {
                require(row.len() == 8, "step arity")?;
                let owner = number(row[1])?;
                let local = host(number(row[2])?)?;
                require(
                    owner > 0 && owner <= f.selection.sites.len() as u64 && local < 2,
                    "step owner/count",
                )?;
                if plans.last().is_none_or(|p| p.owner != owner) {
                    require(
                        local == 0 && seen.insert(owner),
                        "duplicate plan/nonzero first step",
                    )?;
                    plans.push(Plan {
                        owner,
                        steps: Vec::new(),
                        images: Vec::new(),
                        relay: false,
                    });
                }
                let p = plans.last_mut().ok_or("plan")?;
                require(
                    local == p.steps.len() && p.images.is_empty() && !p.relay,
                    "step order",
                )?;
                require(
                    matches!(row[3], "relocation" | "generalized-pun" | "prefixed-pun"),
                    "step kind",
                )?;
                p.steps.push(Step {
                    owner,
                    local,
                    kind: row[3].into(),
                    logical: number(row[4])?,
                    physical: number(row[5])?,
                    displaced: row_range(row[6], row[7])?,
                    read: None,
                    write: None,
                    store: None,
                    entries: Vec::new(),
                    allocation: None,
                    prerequisites: None,
                    rank: 0,
                });
            }
            "live-prerequisites-not-receipts" => {
                require(row.len() == 6, "prerequisite arity")?;
                let s = ref_step(&mut plans, &row, 1)?;
                require(s.prerequisites.is_none(), "duplicate prerequisites")?;
                let boolean = |s: &str| -> Result<bool> {
                    match s {
                        "true" => Ok(true),
                        "false" => Ok(false),
                        _ => Err("boolean spelling".into()),
                    }
                };
                s.prerequisites = Some([boolean(row[3])?, boolean(row[4])?, boolean(row[5])?]);
            }
            "step-read" | "semantic-write" | "live-store-span" => {
                require(row.len() == 5, "source byte row arity")?;
                let rank = match tag {
                    "step-read" => 2,
                    "semantic-write" => 3,
                    _ => 4,
                };
                let s = ref_step(&mut plans, &row, rank)?;
                let value = (number(row[3])?, unhex(row[4])?);
                require(
                    !value.1.is_empty() && value.1.len() <= TEXT,
                    "source byte record size",
                )?;
                let field = match tag {
                    "step-read" => &mut s.read,
                    "semantic-write" => &mut s.write,
                    _ => &mut s.store,
                };
                require(field.replace(value).is_none(), "duplicate source byte row")?;
            }
            "entry-preserved" | "entry-router-required" => {
                require(
                    row.len() == if tag == "entry-preserved" { 4 } else { 5 },
                    "entry arity",
                )?;
                let s = ref_step(&mut plans, &row, 5)?;
                require(s.entries.len() < 187, "entry count")?;
                s.entries.push((
                    number(row[3])?,
                    if row.len() == 5 {
                        Some(number(row[4])?)
                    } else {
                        None
                    },
                ));
            }
            "allocation" => {
                require(
                    row.len() == 6 && number(row[5])? == 4096,
                    "allocation arity/alignment",
                )?;
                let s = ref_step(&mut plans, &row, 6)?;
                require(
                    s.allocation.replace(row_range(row[3], row[4])?).is_none(),
                    "multiple step allocations",
                )?;
            }
            "source-relay-geometry-hex" => {
                require(row.len() == 3, "relay arity")?;
                let p = plans.last_mut().ok_or("relay plan")?;
                require(
                    p.owner == number(row[1])?
                        && !p.relay
                        && p.images.is_empty()
                        && !unhex(row[2])?.is_empty(),
                    "relay identity/order",
                )?;
                p.relay = true;
            }
            "image" => {
                require(row.len() == 7, "image arity")?;
                let id = host(number(row[1])?)?;
                let owner = number(row[2])?;
                require(
                    id == next_image && id < 32 && row[6] == format!("image-{id:04}.bin"),
                    "contiguous image identity",
                )?;
                let data = files.read(row[6], 131072)?;
                require(
                    !data.is_empty()
                        && data.len() as u64 == number(row[4])?
                        && digest(&data) == row[5],
                    "image bytes/size/hash",
                )?;
                let p = plans.last_mut().ok_or("image plan")?;
                require(
                    p.owner == owner && p.images.len() < 2,
                    "image selected owner/count",
                )?;
                p.images.push(Image {
                    id,
                    owner,
                    entry: number(row[3])?,
                    bytes: data,
                    routes: BTreeMap::new(),
                    boundaries: BTreeMap::new(),
                    maps: Vec::new(),
                    fields: Vec::new(),
                    requirements: Vec::new(),
                    rank: 0,
                });
                next_image += 1;
            }
            "route" | "restored-boundary" => {
                require(row.len() == 4, "route/boundary arity")?;
                let image = ref_image(&mut plans, &row, if tag == "route" { 1 } else { 2 })?;
                let map = if tag == "route" {
                    &mut image.routes
                } else {
                    &mut image.boundaries
                };
                require(map.len() < 187, "image route count")?;
                unique(map, row[2], row[3])?;
            }
            "pc-range" => {
                require(row.len() == 5, "PC range arity")?;
                let image = ref_image(&mut plans, &row, 3)?;
                require(image.maps.len() < image.bytes.len(), "PC range count")?;
                image
                    .maps
                    .push((row_range(row[2], row[3])?, number(row[4])?));
            }
            "field" => {
                require(row.len() == 10, "field arity")?;
                let image = ref_image(&mut plans, &row, 4)?;
                require(image.fields.len() < image.bytes.len(), "field count")?;
                let offset = number(row[2])?;
                let width = host(number(row[3])?)?;
                require(
                    matches!((row[4], width), ("Relative", 1 | 4) | ("Delta", 8)),
                    "field encoding/width",
                )?;
                let role = unhex(row[8])?;
                require(
                    !role.is_empty() && role.len() <= TEXT,
                    "bounded opaque field role",
                )?;
                image.fields.push((
                    offset,
                    width,
                    row[4].into(),
                    number(row[5])?,
                    signed(row[6])?,
                    number(row[7])?,
                    unhex(row[9])?,
                ));
            }
            "unmet-requirement" => {
                require(row.len() == 4, "requirement arity")?;
                let image = ref_image(&mut plans, &row, 5)?;
                require(image.requirements.len() < 8, "requirement count")?;
                image.requirements.push((number(row[2])?, number(row[3])?));
            }
            _ => return Err(format!("unsupported plan ledger row {tag}")),
        }
    }
    require(
        plans.len() == f.selection.sites.len() && footer == 2,
        "complete plans and footer",
    )?;
    Ok((plans, locks, deps))
}

pub fn requirements(has_hook: bool, hook: u64, routed: bool) -> Vec<(u64, u64)> {
    let mut r = vec![(1, 0), (2, 0), (3, 0), (4, 0), (7, 0), (8, 0)];
    if has_hook {
        r.push((5, hook));
    }
    if routed {
        r.push((6, 0));
    }
    r
}
fn associated<'a>(plan: &'a Plan, step: &Step, selected: u64, hook: u64) -> Result<&'a Image> {
    let allocation = step.allocation.ok_or("missing allocation")?;
    let candidates: Vec<_> = plan
        .images
        .iter()
        .enumerate()
        .filter(|(_, i)| hull(i.entry, i.bytes.len()).ok() == Some(allocation))
        .collect();
    require(candidates.len() == 1, "unique exact allocation/image hull")?;
    let (ordinal, image) = candidates[0];
    require(
        ordinal == step.local && image.owner == step.owner && step.owner == plan.owner,
        "step/image bijection and serialized order",
    )?;
    let routed = plan
        .steps
        .iter()
        .any(|s| s.entries.iter().any(|(_, to)| to.is_some()));
    require(
        image.requirements == requirements(step.logical == selected, hook, routed),
        "exact constructor-derived unmet requirements",
    )?;
    Ok(image)
}
fn resources(n: usize, steps: usize, images: usize, bytes: usize, page_bytes: u64) -> Result<()> {
    require(
        n <= 32 && steps <= 2 * n && images <= 32 && bytes <= 131072 && page_bytes <= 128 * 4096,
        "whole immutable-denominator resources",
    )
}
fn permitted(allocation: Range, policy: &li2core::quiescent::AllocationPolicy) -> Result<()> {
    require(
        policy.max_candidates > 0
            && policy.max_mappings >= 1
            && allocation.len() <= policy.max_mapped_bytes as u64
            && policy
                .ranges
                .iter()
                .any(|r| r.start() <= allocation.start && allocation.end <= r.end()),
        "complete allocation pages inside original role permit and backing cap",
    )
}

pub fn join(
    original: &[u8],
    f: &Facts,
    records: &[Site],
    bytes: &[u8],
    files: &dyn Files,
) -> Result<Joined> {
    let (plans, declared_locks, declared_dependencies) = parse(original, f, bytes, files)?;
    let associations = association::check(&plans, f, records, files)?;
    let elf = checked(Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: 128,
        },
    ))?;
    let mut current = original.to_vec();
    let mut locks: Vec<Range> = Vec::new();
    let mut allocations: Vec<Range> = Vec::new();
    let mut physical = BTreeSet::new();
    let mut all_images = Vec::new();
    let mut dependencies = vec![checked(FileRange::checked(
        FileOffset(original_offset(&elf, Range::new(0x403000, 0x403001)?)?),
        1,
    ))?];
    let mut page_bytes = 0u64;
    let mut image_bytes = 0usize;
    let mut steps = 0usize;
    let mut previous_owner_pc = u64::MAX;
    for plan in plans {
        let site = &f.selection.sites[host(plan.owner - 1)?];
        require(
            site.pc < previous_owner_pc,
            "descending selected plan order",
        )?;
        previous_owner_pc = site.pc;
        let Outcome::Rewritten(tactic) = records[host(plan.owner - 1)?].outcome else {
            return Err("nonrewritten plan owner".into());
        };
        let expected_steps =
            if matches!(tactic, Tactic::SuccessorEviction | Tactic::NeighborEviction) {
                2
            } else {
                1
            };
        require(
            plan.steps.len() == expected_steps
                && plan.images.len() == expected_steps
                && plan.relay == (tactic == Tactic::NeighborEviction),
            "source-derived plan/image/relay shape",
        )?;
        require(
            plan.steps.iter().filter(|s| s.logical == site.pc).count() == 1,
            "one independent selected-PC step",
        )?;
        let snapshot = Range::new(site.snapshot.start(), site.snapshot.end())?;
        let mut matched = BTreeSet::new();
        for (position, step) in plan.steps.iter().enumerate() {
            require(
                step.local == position
                    && step.owner == site.id
                    && step.displaced.start == step.physical
                    && step.displaced.contains(step.logical)
                    && snapshot.covers(step.displaced),
                "step original geometry",
            )?;
            require(
                physical.insert(step.physical),
                "duplicate physical source interception",
            )?;
            let allocation = step.allocation.ok_or("missing allocation")?;
            require(
                allocation.start % 4096 == 0
                    && allocation.end % 4096 == 0
                    && !allocations.iter().any(|r| r.overlaps(allocation)),
                "exclusive allocation pages",
            )?;
            permitted(
                allocation,
                if step.logical == site.pc {
                    &site.selected_allocation
                } else {
                    &site.victim_allocation
                },
            )?;
            let image = associated(&plan, step, site.pc, site.hook)?;
            require(matched.insert(image.id), "duplicate associated image")?;
            shape(
                step,
                &plan.steps,
                tactic,
                site.pc,
                usize::from(site.length),
                &f.heads,
            )?;
            image_joins(image, step, &f.heads)?;
            let displaced_offset = original_offset(&elf, step.displaced)?;
            require(
                slice(&current, displaced_offset, step.displaced.len())?
                    == slice(original, displaced_offset, step.displaced.len())?,
                "original displaced instruction identity",
            )?;
            let off = original_offset(&elf, snapshot)?;
            let expected_read = (
                snapshot.start,
                slice(&current, off, snapshot.len())?.to_vec(),
            );
            require(
                step.read.as_ref() == Some(&expected_read),
                "predecessor current-overlay read",
            )?;
            dependencies.push(checked(FileRange::checked(
                FileOffset(off),
                snapshot.len(),
            ))?);
            let expected_write = source_write(
                step,
                tactic,
                site.pc,
                &plan.steps,
                &plan.images,
                &current,
                &elf,
            )?;
            require(
                step.write.as_ref() == Some(&(step.physical, expected_write.clone())),
                "source redirect/image binding",
            )?;
            let (new_locks, edits) = step_edits(step, &expected_write, &current, &elf)?;
            for (address, data) in &edits {
                let r = Range::bytes(*address, data.len())?;
                require(snapshot.covers(r), "source write outside owned snapshot")?;
                let at = original_offset(&elf, r)?;
                for held in &locks {
                    if held.overlaps(r) {
                        let lo = held.start.max(r.start);
                        let hi = held.end.min(r.end);
                        require(
                            slice(data, lo - r.start, hi - lo)?
                                == slice(&current, add(at, lo - r.start)?, hi - lo)?,
                            "changed predecessor lock",
                        )?;
                    }
                }
            }
            for (address, data) in edits {
                let r = Range::bytes(address, data.len())?;
                let at = host(original_offset(&elf, r)?)?;
                current[at..at + data.len()].copy_from_slice(&data);
            }
            locks.extend(new_locks);
            for (pc, to) in &step.entries {
                if to.is_some() {
                    let at = original_offset(&elf, Range::new(*pc, add(*pc, 1)?)?)?;
                    if current[host(at)?] == 0x62 {
                        let fetch = Range::new(*pc, add(*pc, 15)?)?;
                        require(snapshot.covers(fetch), "routed fetch ownership")?;
                        locks.push(fetch);
                    }
                }
            }
            locks = merge(locks, true);
            allocations.push(allocation);
            page_bytes = add(page_bytes, allocation.len())?;
            image_bytes = image_bytes
                .checked_add(image.bytes.len())
                .ok_or("image bytes overflow")?;
            steps += 1;
            resources(
                f.selection.sites.len(),
                steps,
                allocations.len(),
                image_bytes,
                page_bytes,
            )?;
            for load in elf.segments(SegmentType::Load) {
                let occupied = Range::new(
                    load.vaddr.0 & !4095,
                    page(add(load.vaddr.0, load.memory_size)?)?,
                )?;
                require(
                    !allocation.overlaps(occupied),
                    "allocation overlaps original occupancy",
                )?;
            }
            require(
                !allocation.overlaps(Range::new(0x480000, add(0x480000, page(128 * 56 + 128)?)?)?),
                "allocation overlaps full carrier reservation",
            )?;
            all_images.push(carrier::RxImage {
                entry: ElfVaddr(image.entry),
                bytes: image.bytes.clone(),
            });
        }
        require(
            matched.len() == plan.images.len(),
            "complete image association",
        )?;
    }
    require(
        locks == declared_locks && dependencies == declared_dependencies,
        "exact independently derived locks/dependencies footer",
    )?;
    let first = allocations
        .iter()
        .map(|r| r.start)
        .min()
        .ok_or("no allocations")?;
    let end = allocations
        .iter()
        .map(|r| r.end)
        .max()
        .ok_or("no allocations")?;
    require(end - first <= 2147483648, "full generated hull")?;
    let hook = host(original_offset(&elf, Range::new(0x403000, 0x403001)?)?)?;
    require(current[hook] == 0xc3, "immutable original hook")?;
    let mut edits = Vec::new();
    for r in &f.snapshots {
        let off = original_offset(&elf, *r)?;
        let before = slice(original, off, r.len())?;
        let after = slice(&current, off, r.len())?;
        let mut at = 0;
        while at < before.len() {
            if before[at] == after[at] {
                at += 1;
                continue;
            }
            let start = at;
            while at < before.len() && before[at] != after[at] {
                at += 1;
            }
            edits.push(carrier::DeclaredEdit {
                offset: FileOffset(add(off, start as u64)?),
                expected: before[start..at].to_vec(),
                replacement: after[start..at].to_vec(),
            });
        }
    }
    edits.sort_by_key(|e| e.offset);
    Ok(Joined {
        associations,
        images: all_images,
        edits,
        dependencies,
    })
}

fn displaced_heads(step: &Step, heads: &BTreeMap<u64, Vec<u8>>) -> Result<Vec<u64>> {
    let mut at = step.displaced.start;
    let mut out = Vec::new();
    while at < step.displaced.end {
        let bytes = heads
            .get(&at)
            .ok_or("displaced interval is not whole original heads")?;
        out.push(at);
        at = add(at, bytes.len() as u64)?;
    }
    require(
        at == step.displaced.end,
        "displaced interval ends mid-instruction",
    )?;
    Ok(out)
}
fn prefix_count(step: &Step) -> Result<usize> {
    let data = &step.write.as_ref().ok_or("missing semantic write")?.1;
    let n = data.iter().take_while(|&&b| b == 0x2e).count();
    require(
        data.get(n) == Some(&0xe9)
            && n < host(step.displaced.len())?
            && ((step.kind == "generalized-pun" && n == 0)
                || (step.kind == "prefixed-pun" && n > 0)),
        "literal supported pun prefix",
    )?;
    Ok(n)
}
fn shape(
    step: &Step,
    steps: &[Step],
    tactic: Tactic,
    selected: u64,
    length: usize,
    heads: &BTreeMap<u64, Vec<u8>>,
) -> Result<()> {
    let displaced = displaced_heads(step, heads)?;
    let chosen = step.logical == selected;
    match tactic {
        Tactic::Relocation => require(
            chosen
                && step.kind == "relocation"
                && step.physical <= selected
                && step.displaced.len() >= 5,
            "B1 step shape",
        )?,
        Tactic::GeneralizedPun | Tactic::PrefixedPun => require(
            chosen
                && step.kind
                    == if tactic == Tactic::GeneralizedPun {
                        "generalized-pun"
                    } else {
                        "prefixed-pun"
                    },
            "B2/T1 step shape",
        )?,
        Tactic::SuccessorEviction => {
            require(
                steps.len() == 2
                    && steps[0].logical == add(selected, length as u64)?
                    && steps[1].logical == selected,
                "T2 exact predecessor order",
            )?;
            require(
                if chosen {
                    step.kind != "relocation"
                } else {
                    step.kind == "relocation" && step.displaced.len() >= 5
                },
                "T2 selected/auxiliary constructor shape",
            )?;
            require(
                displaced.len() == 1 && step.physical == step.logical,
                "T2 single original instruction",
            )?;
        }
        Tactic::NeighborEviction => {
            require(
                steps.len() == 2
                    && steps[0].physical > steps[1].physical
                    && !steps[0].displaced.overlaps(steps[1].displaced),
                "T3 descending disjoint source members",
            )?;
            require(
                step.kind == "relocation"
                    && displaced.len() == 1
                    && step.physical == step.logical
                    && if chosen {
                        (2..=4).contains(&length)
                    } else {
                        (6..=9).contains(&host(step.displaced.len())?)
                    },
                "T3 short-only typed selected/auxiliary shape",
            )?;
        }
    }
    if step.kind != "relocation" {
        require(
            step.physical == selected
                && step.displaced.len() == length as u64
                && (1..=4).contains(&length)
                && step.physical / 64 == (step.displaced.end - 1) / 64,
            "pun original instruction/cache-line geometry",
        )?;
        prefix_count(step)?;
    }
    let routed = step.entries.iter().any(|(_, to)| to.is_some());
    require(
        step.prerequisites == Some([true, true, routed]),
        "live prerequisites are required, never receipts",
    )
}
fn image_joins(image: &Image, step: &Step, heads: &BTreeMap<u64, Vec<u8>>) -> Result<()> {
    let originals = displaced_heads(step, heads)?;
    let keys: Vec<_> = image.routes.keys().copied().collect();
    require(
        keys == originals && image.boundaries.keys().copied().collect::<Vec<_>>() == originals,
        "complete observing original entry/restored coverage",
    )?;
    let extent = Range::bytes(image.entry, image.bytes.len())?;
    let mut prior = None;
    for (range, logical) in &image.maps {
        require(
            extent.covers(*range)
                && prior.is_none_or(|end| end <= range.start)
                && (heads.contains_key(logical) || *logical == step.displaced.end),
            "ordered PC range/original-or-continuation ownership",
        )?;
        prior = Some(range.end);
    }
    require(!image.maps.is_empty(), "missing generated PC ranges")?;
    let mut instruction_heads = BTreeSet::new();
    let mut instruction_ends = BTreeSet::new();
    for range in merge(image.maps.iter().map(|(range, _)| *range).collect(), true) {
        // The ledger distinguishes executable PC ranges from pointer data.
        // Decode adjacent maps together, without resetting inside an operand,
        // and never decode the gaps between complete declared code runs.
        // Entry/boundary coordinates must name whole instruction starts, even
        // when the operand contains no declared relocation field.
        let code = slice(&image.bytes, range.start - image.entry, range.len())?;
        let mut decoder =
            iced_x86::Decoder::with_ip(64, code, range.start, iced_x86::DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            require(
                !instruction.is_invalid(),
                "invalid or split generated instruction range",
            )?;
            instruction_heads.insert(instruction.ip());
            instruction_ends.insert(instruction.next_ip());
        }
        require(
            decoder.ip() == range.end,
            "complete generated instruction range",
        )?;
    }
    require(
        instruction_heads.contains(&image.entry),
        "source redirect entry lacks generated code",
    )?;
    for (range, _) in &image.maps {
        require(
            instruction_heads.contains(&range.start) && instruction_ends.contains(&range.end),
            "PC range splits a generated instruction",
        )?;
    }
    for map in [&image.routes, &image.boundaries] {
        for (original, generated) in map {
            require(
                extent.contains(*generated)
                    && image
                        .maps
                        .iter()
                        .filter(|(r, pc)| r.contains(*generated) && pc == original)
                        .count()
                        == 1,
                "entry/restored target joins unique generated PC range",
            )?;
            require(
                instruction_heads.contains(generated),
                "entry/restored target is not a generated instruction head",
            )?;
        }
    }
    let expected_entries = if step.kind == "relocation" {
        originals
            .iter()
            .map(|pc| {
                (
                    *pc,
                    if *pc == step.physical {
                        None
                    } else {
                        image.routes.get(pc).copied()
                    },
                )
            })
            .collect::<Vec<_>>()
    } else {
        let end = add(step.physical, 5 + prefix_count(step)? as u64)?;
        heads
            .range(step.physical..end)
            .map(|(pc, _)| (*pc, None))
            .collect()
    };
    require(
        step.entries == expected_entries,
        "complete source entry obligations and routes",
    )?;
    let mut occupied = Vec::new();
    for (offset, width, encoding, origin, target, domain, encoded) in &image.fields {
        let r = Range::new(*offset, add(*offset, *width as u64)?)?;
        require(
            r.end <= image.bytes.len() as u64
                && *origin <= image.bytes.len() as u64
                && *domain == 1
                && encoded.len() == *width
                && slice(&image.bytes, *offset, *width as u64)? == encoded
                && !occupied.iter().any(|old: &Range| old.overlaps(r)),
            "serialized fixup bounds/domain/actual bytes/uniqueness",
        )?;
        require(
            encoding != "Relative" || *origin >= r.end,
            "relative next-instruction origin",
        )?;
        let displacement = target
            .checked_sub(i128::from(image.entry))
            .and_then(|v| v.checked_sub(i128::from(*origin)))
            .ok_or("fixup arithmetic overflow")?;
        let expected = match *width {
            1 => checked(i8::try_from(displacement))?.to_le_bytes().to_vec(),
            4 => checked(i32::try_from(displacement))?.to_le_bytes().to_vec(),
            8 => checked(i64::try_from(displacement))?.to_le_bytes().to_vec(),
            _ => return Err("fixup width".into()),
        };
        require(*encoded == expected, "exact signed fixup arithmetic")?;
        occupied.push(r);
    }
    // A callable entry or restored original boundary cannot enter a declared
    // address field. A half-open code range may end where literal data starts;
    // the separate instruction decoder checks all PC-map boundaries above.
    // This is a structural join with the already checked declared fields; it
    // does not claim discovery of undeclared operands or instruction semantics.
    for generated in image
        .routes
        .values()
        .chain(image.boundaries.values())
        .copied()
    {
        let offset = generated
            .checked_sub(image.entry)
            .ok_or("generated boundary before image")?;
        require(
            !occupied.iter().any(|field| field.contains(offset)),
            "generated entry enters a declared address field",
        )?;
    }
    for (range, _) in &image.maps {
        let start = range.start - image.entry;
        let end = range.end - image.entry;
        require(
            !occupied
                .iter()
                .any(|field| field.contains(start) || (field.start < end && end < field.end)),
            "PC range enters or splits a declared address field",
        )?;
    }
    Ok(())
}
fn step_image<'a>(step: &Step, images: &'a [Image]) -> Result<&'a Image> {
    let a = step.allocation.ok_or("missing step allocation")?;
    let matches: Vec<_> = images
        .iter()
        .filter(|i| hull(i.entry, i.bytes.len()).ok() == Some(a))
        .collect();
    require(matches.len() == 1, "unique image for source redirect")?;
    Ok(matches[0])
}
fn near(address: u64, target: u64) -> Result<Vec<u8>> {
    let delta = checked(i32::try_from(
        i128::from(target) - i128::from(add(address, 5)?),
    ))?;
    let mut bytes = vec![0xe9];
    bytes.extend_from_slice(&delta.to_le_bytes());
    Ok(bytes)
}
// Exact legacy/EVEX single-byte #UD set from quiescent::candidate_target.
// D4/D5 are deliberately absent: newer ISA extensions can assign them prefixes.
const SINGLE_BYTE_UD: [u8; 14] = [
    0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
];
fn displacement_traps(step: &Step, bytes: &[u8]) -> Result<()> {
    for (pc, target) in &step.entries {
        if target.is_some() && *pc < add(step.physical, 5)? {
            let at = host(
                pc.checked_sub(step.physical)
                    .ok_or("route before physical source")?,
            )?;
            require(
                (1..5).contains(&at) && bytes.get(at).is_some_and(|b| SINGLE_BYTE_UD.contains(b)),
                "routed displacement byte is not guaranteed #UD",
            )?;
        }
    }
    Ok(())
}
fn source_write(
    step: &Step,
    tactic: Tactic,
    selected: u64,
    steps: &[Step],
    images: &[Image],
    current: &[u8],
    elf: &Elf64<'_>,
) -> Result<Vec<u8>> {
    let image = step_image(step, images)?;
    if tactic == Tactic::NeighborEviction {
        let victim = steps
            .iter()
            .find(|s| s.logical != selected)
            .ok_or("T3 victim")?;
        if step.logical == selected {
            return Ok(vec![
                0xeb,
                checked(i8::try_from(
                    i128::from(add(victim.physical, 5)?) - i128::from(add(selected, 2)?),
                ))? as u8,
            ]);
        }
        let chosen = steps
            .iter()
            .find(|s| s.logical == selected)
            .ok_or("T3 selected")?;
        let mut bytes = near(step.physical, image.entry)?;
        bytes.extend_from_slice(&near(
            add(step.physical, 5)?,
            step_image(chosen, images)?.entry,
        )?);
        let length = host(step.displaced.len())?;
        let tail = Range::new(step.displaced.end, add(step.physical, bytes.len() as u64)?)?;
        require(
            slice(current, original_offset(elf, tail)?, tail.len())? == &bytes[length..],
            "short T3 unchanged relay tail",
        )?;
        return Ok(bytes);
    }
    if step.kind != "relocation" {
        let prefix = prefix_count(step)?;
        let mut full = vec![0x2e; prefix];
        full.extend_from_slice(&near(add(step.physical, prefix as u64)?, image.entry)?);
        let length = host(step.displaced.len())?;
        let consumed = Range::bytes(step.physical, full.len())?;
        let off = original_offset(elf, consumed)?;
        require(
            slice(
                current,
                add(off, length as u64)?,
                (full.len() - length) as u64,
            )? == &full[length..],
            "exact unchanged consumed successor bytes",
        )?;
        return Ok(full[..length].to_vec());
    }
    if tactic == Tactic::SuccessorEviction {
        return near(step.physical, image.entry);
    }
    let off = original_offset(elf, step.displaced)?;
    let mut bytes = slice(current, off, step.displaced.len())?.to_vec();
    bytes[..5].copy_from_slice(&near(step.physical, image.entry)?);
    displacement_traps(step, &bytes)?;
    let (source_start, source) = step.read.as_ref().ok_or("source read")?;
    let source_end = add(*source_start, source.len() as u64)?;
    for (pc, to) in step.entries.iter().rev() {
        if to.is_some() && *pc >= add(step.physical, 5)? {
            let at = host(*pc - step.physical)?;
            require(at < bytes.len(), "interior trap outside displacement")?;
            bytes[at] = 0x62;
            let following = |delta: usize| {
                bytes
                    .get(at + delta)
                    .copied()
                    .or_else(|| source.get((*pc - *source_start) as usize + delta).copied())
            };
            if *pc % 4096 > 4096 - 15
                || source_end - *pc < 15
                || following(1).is_none()
                || !following(2).is_some_and(|p| p & 4 == 0)
            {
                bytes[at] = 0x60;
            }
        }
    }
    Ok(bytes)
}

fn step_edits(step: &Step, write: &[u8], current: &[u8], elf: &Elf64<'_>) -> Result<StepEdits> {
    let mut edits = vec![(step.physical, write.to_vec())];
    let mut locks = vec![Range::bytes(step.physical, write.len())?];
    if step.kind == "relocation" {
        require(
            step.store.is_none(),
            "relocation cannot declare live MOV store",
        )?;
        locks.push(step.displaced);
    } else {
        let consumed = Range::new(
            step.physical,
            add(step.physical, 5 + prefix_count(step)? as u64)?,
        )?;
        locks.push(consumed);
        let size = host(step.displaced.len())?.next_power_of_two();
        let address = step.physical.min((step.physical | 63) - (size as u64 - 1));
        let store = Range::bytes(address, size)?;
        let mut value = slice(current, original_offset(elf, store)?, size as u64)?.to_vec();
        let at = host(step.physical - address)?;
        value
            .get_mut(at..at + write.len())
            .ok_or("MOV store span")?
            .copy_from_slice(write);
        require(
            step.store.as_ref() == Some(&(address, value.clone())),
            "exact live store and preserved padding",
        )?;
        locks.push(store);
        edits.push((address, value));
    }
    Ok((locks, edits))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn member(
        owner: u64,
        local: usize,
        pc: u64,
        len: usize,
        address: u64,
        has_hook: bool,
    ) -> (Step, Image) {
        let step = Step {
            owner,
            local,
            kind: "relocation".into(),
            logical: pc,
            physical: pc,
            displaced: Range::bytes(pc, len).unwrap(),
            read: None,
            write: Some((pc, vec![0xe9; 5])),
            store: None,
            entries: vec![(pc, None)],
            allocation: Some(hull(address, 5).unwrap()),
            prerequisites: Some([true, true, false]),
            rank: 6,
        };
        let image = Image {
            id: local,
            owner,
            entry: address,
            bytes: vec![0x90; 5],
            routes: BTreeMap::from([(pc, address)]),
            boundaries: BTreeMap::from([(pc, address)]),
            maps: vec![(Range::bytes(address, 5).unwrap(), pc)],
            fields: Vec::new(),
            requirements: requirements(has_hook, 1, false),
            rank: 5,
        };
        (step, image)
    }
    #[test]
    fn f05_generated_entries_and_pc_ranges_require_complete_instruction_boundaries() {
        let pc = 0x401000;
        let entry = 0x600000;
        let (step, mut image) = member(1, 0, pc, 5, entry, true);
        // MOV's non-address immediate consists of independently valid NOPs.
        // No declared fixup can supply the boundary proof for this case.
        image.bytes = vec![0xb8, 0x90, 0x90, 0x90, 0x90, 0xc3];
        image.maps = vec![
            (Range::new(entry, entry + 5).unwrap(), pc),
            (Range::new(entry + 5, entry + 6).unwrap(), pc),
        ];
        let heads = BTreeMap::from([(pc, vec![0xb8, 0, 0, 0, 0])]);
        image_joins(&image, &step, &heads).unwrap();
        let valid = image.clone();
        image.maps = vec![(Range::new(entry + 5, entry + 6).unwrap(), pc)];
        image.routes.insert(pc, entry + 5);
        image.boundaries.insert(pc, entry + 5);
        assert_eq!(
            image_joins(&image, &step, &heads).err().as_deref(),
            Some("source redirect entry lacks generated code")
        );
        for delta in 1..5 {
            for restored in [false, true] {
                image = valid.clone();
                if restored {
                    image.boundaries.insert(pc, entry + delta);
                } else {
                    image.routes.insert(pc, entry + delta);
                }
                assert_eq!(
                    image_joins(&image, &step, &heads).err().as_deref(),
                    Some("entry/restored target is not a generated instruction head")
                );
            }
            image = valid.clone();
            image.maps[0].0.end = entry + delta;
            image.maps[1].0.start = entry + delta;
            assert_eq!(
                image_joins(&image, &step, &heads).err().as_deref(),
                Some("PC range splits a generated instruction")
            );
        }
        image = valid.clone();
        image.bytes[5] = 0xe9;
        assert_eq!(
            image_joins(&image, &step, &heads).err().as_deref(),
            Some("invalid or split generated instruction range")
        );
        // An unmapped literal gap is deliberately excluded from decoding.
        image = valid;
        image.bytes = vec![0x90, 0xff, 0xc3];
        image.maps = vec![
            (Range::new(entry, entry + 1).unwrap(), pc),
            (Range::new(entry + 2, entry + 3).unwrap(), pc),
        ];
        image_joins(&image, &step, &heads).unwrap();
        // The end of a half-open code range may equal a declared data field's
        // first byte. This is a structural contract control, not a claim that
        // the current artifact emitter uses a literal pool for Delta fields.
        image.bytes = vec![0x90];
        image.bytes.extend_from_slice(&1234i64.to_le_bytes());
        image.bytes.push(0xc3);
        image.maps = vec![
            (Range::new(entry, entry + 1).unwrap(), pc),
            (Range::new(entry + 9, entry + 10).unwrap(), pc),
        ];
        image.fields.push((
            1,
            8,
            "Delta".into(),
            0,
            i128::from(entry + 1234),
            1,
            1234i64.to_le_bytes().to_vec(),
        ));
        image_joins(&image, &step, &heads).unwrap();
        image.bytes = vec![0x90, 0x48, 0xb8];
        image.bytes.extend_from_slice(&[0x90; 8]);
        image.bytes.push(0xc3);
        image.fields = vec![(
            3,
            8,
            "Delta".into(),
            0,
            i128::from(entry) + i128::from(i64::from_le_bytes([0x90; 8])),
            1,
            vec![0x90; 8],
        )];
        image.maps = vec![(Range::new(entry, entry + 12).unwrap(), pc)];
        image_joins(&image, &step, &heads).unwrap();
        // A forged gap cannot hide MOV's opcode and restart decoding at its
        // immediate merely because all eight operand bytes decode as NOPs.
        image.maps = vec![
            (Range::new(entry, entry + 1).unwrap(), pc),
            (Range::new(entry + 3, entry + 12).unwrap(), pc),
        ];
        assert_eq!(
            image_joins(&image, &step, &heads).err().as_deref(),
            Some("PC range enters or splits a declared address field")
        );
    }
    #[test]
    fn f02_all_four_displacement_offsets_require_exact_single_byte_ud_set() {
        let (mut step, _) = member(1, 0, 0x401000, 5, 0x600000, true);
        for offset in 1..5 {
            step.entries = vec![
                (step.physical, None),
                (step.physical + offset, Some(0x600001)),
            ];
            for opcode in 0..=255u8 {
                let mut bytes = vec![0xe9, 0, 0, 0, 0];
                bytes[offset as usize] = opcode;
                assert_eq!(
                    displacement_traps(&step, &bytes).is_ok(),
                    matches!(
                        opcode,
                        0x06 | 0x07
                            | 0x0e
                            | 0x16
                            | 0x17
                            | 0x1e
                            | 0x1f
                            | 0x27
                            | 0x2f
                            | 0x37
                            | 0x3f
                            | 0x60
                            | 0x61
                            | 0xce
                    ),
                    "offset {offset} opcode {opcode:02x}"
                );
            }
        }
    }
    #[test]
    fn f02_suffix_evex_keeps_exact_fetch_and_p1_guards() {
        // The lower boundary is exactly a 15-byte same-page fetch. The next
        // three rows independently violate page room, snapshot room, and P1.
        for (pc, length, p1, marker) in [
            (0x401fec, 20, 0, 0x62),
            (0x401fed, 20, 0, 0x60),
            (0x401fec, 19, 0, 0x60),
            (0x401fec, 20, 4, 0x60),
        ] {
            let mut original = crate::verify::tests::original();
            let off = (pc - 0x400000) as usize;
            original[off + 7] = p1;
            let source = original[off..off + length].to_vec();
            let elf = Elf64::parse(&original, ParseLimits::default()).unwrap();
            let (mut step, image) = member(1, 0, pc, 6, 0x600000, true);
            step.read = Some((pc, source));
            step.entries.push((pc + 5, Some(0x600001)));
            let bytes = source_write(
                &step,
                Tactic::Relocation,
                pc,
                std::slice::from_ref(&step),
                &[image],
                &original,
                &elf,
            )
            .unwrap();
            assert_eq!(bytes[5], marker, "PC {pc:#x} source {length} P1 {p1}");
        }
    }
    #[test]
    fn g01_t3_both_orders_bijection_and_exact_roles_before_mutants() {
        for selected in [0x401000, 0x401020] {
            let victim = if selected == 0x401000 {
                0x401020
            } else {
                0x401000
            };
            let mut members = vec![
                member(1, 0, selected, 2, 0x600000, true),
                member(1, 1, victim, 6, 0x700000, false),
            ];
            members.sort_by_key(|(s, _)| std::cmp::Reverse(s.physical));
            let mut plan = Plan {
                owner: 1,
                steps: Vec::new(),
                images: Vec::new(),
                relay: true,
            };
            for (local, (mut s, mut i)) in members.into_iter().enumerate() {
                s.local = local;
                i.id = local;
                plan.steps.push(s);
                plan.images.push(i);
            }
            let heads = BTreeMap::from([
                (selected, vec![0x75, 0]),
                (victim, vec![0x69, 0xc0, 0, 0, 0, 0]),
            ]);
            for s in &plan.steps {
                shape(
                    s,
                    &plan.steps,
                    Tactic::NeighborEviction,
                    selected,
                    2,
                    &heads,
                )
                .unwrap();
                let image = associated(&plan, s, selected, 1).unwrap();
                image_joins(image, s, &heads).unwrap();
            }
            for at in 0..2 {
                let saved = plan.images[at].requirements.clone();
                plan.images[at].requirements = if saved.contains(&(5, 1)) {
                    requirements(false, 1, false)
                } else {
                    requirements(true, 1, false)
                };
                assert!(associated(&plan, &plan.steps[at], selected, 1).is_err());
                plan.images[at].requirements = saved;
            }
            plan.images.swap(0, 1);
            assert!(associated(&plan, &plan.steps[0], selected, 1).is_err());
            plan.images.swap(0, 1);
            let allocation = plan.steps[1].allocation;
            plan.steps[1].allocation = plan.steps[0].allocation;
            assert!(associated(&plan, &plan.steps[1], selected, 1).is_err());
            plan.steps[1].allocation = allocation;
            plan.images[0].owner = 2;
            assert!(associated(&plan, &plan.steps[0], selected, 1).is_err());
            plan.images[0].owner = 1;
            // Router bootstrap is plan-wide, including the callback-free image.
            plan.steps[0].entries.push((selected, Some(0x600000)));
            for image in &mut plan.images {
                image.requirements.push((6, 0));
            }
            for s in &plan.steps {
                associated(&plan, s, selected, 1).unwrap();
            }
            for at in 0..2 {
                plan.images[at].requirements.pop();
                assert!(associated(&plan, &plan.steps[at], selected, 1).is_err());
                plan.images[at].requirements.push((6, 0));
            }
        }
    }
    #[test]
    fn v03_full_denominator_resource_equal_caps_then_one_more() {
        resources(16, 32, 32, 131072, 128 * 4096).unwrap();
        assert!(resources(16, 33, 32, 131072, 128 * 4096).is_err());
        assert!(resources(16, 32, 33, 131072, 128 * 4096).is_err());
        assert!(resources(16, 32, 32, 131073, 128 * 4096).is_err());
        assert!(resources(16, 32, 32, 131072, 128 * 4096 + 1).is_err());
    }
    #[test]
    fn v03_complete_page_permit_boundaries_and_one_more() {
        let policy = li2core::quiescent::AllocationPolicy {
            ranges: vec![
                li2core::contracts::AddressRange::new(0x456000, 0x2a000).unwrap(),
                li2core::contracts::AddressRange::new(0x482000, 0x7ff7e000).unwrap(),
            ],
            preferred_address: None,
            max_candidates: 1,
            max_mappings: 1,
            max_mapped_bytes: 4096,
        };
        for start in [0x456000, 0x47f000, 0x482000, 0x803ff000] {
            permitted(Range::new(start, start + 4096).unwrap(), &policy).unwrap();
        }
        for r in [
            Range::new(0x455000, 0x456000).unwrap(),
            Range::new(0x480000, 0x481000).unwrap(),
            Range::new(0x80400000, 0x80401000).unwrap(),
            Range::new(0x482000, 0x483001).unwrap(),
        ] {
            assert!(permitted(r, &policy).is_err());
        }
    }
    #[test]
    fn g01_upstream_b1_and_prefixed_t1_roles_are_logical_not_physical() {
        let (mut step, mut image) = member(1, 0, 0x401000, 5, 0x600000, true);
        step.logical = 0x401001;
        step.entries.push((0x401001, Some(0x600002)));
        step.prerequisites = Some([true, true, true]);
        image.routes.insert(0x401001, 0x600002);
        image.boundaries.insert(0x401001, 0x600002);
        image.maps = vec![
            (Range::new(0x600000, 0x600002).unwrap(), 0x401000),
            (Range::new(0x600002, 0x600005).unwrap(), 0x401001),
        ];
        image.requirements = requirements(true, 1, true);
        let heads = BTreeMap::from([
            (0x401000, vec![0x90]),
            (0x401001, vec![0x66, 0x0f, 0x1f, 0x00]),
        ]);
        let mut plan = Plan {
            owner: 1,
            steps: vec![step],
            images: vec![image],
            relay: false,
        };
        shape(
            &plan.steps[0],
            &plan.steps,
            Tactic::Relocation,
            0x401001,
            4,
            &heads,
        )
        .unwrap();
        image_joins(&plan.images[0], &plan.steps[0], &heads).unwrap();
        associated(&plan, &plan.steps[0], 0x401001, 1).unwrap();
        plan.steps[0].logical = 0x401000;
        assert!(associated(&plan, &plan.steps[0], 0x401001, 1).is_err());
        let (mut step, image) = member(1, 0, 0x401000, 2, 0x600000, true);
        step.kind = "prefixed-pun".into();
        step.write = Some((0x401000, vec![0x2e, 0xe9]));
        step.entries.push((0x401002, None));
        let heads = BTreeMap::from([
            (0x401000, vec![0x75, 4]),
            (0x401002, vec![0x0f, 0x1f, 0x40, 0]),
        ]);
        let plan = Plan {
            owner: 1,
            steps: vec![step],
            images: vec![image],
            relay: false,
        };
        shape(
            &plan.steps[0],
            &plan.steps,
            Tactic::PrefixedPun,
            0x401000,
            2,
            &heads,
        )
        .unwrap();
        image_joins(&plan.images[0], &plan.steps[0], &heads).unwrap();
        associated(&plan, &plan.steps[0], 0x401000, 1).unwrap();
    }
}
