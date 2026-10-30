//! Stable pair prefixes are declarations only. Original geometry, greedy
//! grouping, actual step/image extents and complete ordinal joins supply proof.
use super::*;
use liteinst_rewrite::model::SelectedSite;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Family {
    Forward,
    Routed,
}
impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::Forward => "forward-jcc-b2-v1",
            Self::Routed => "jbe-routed-jmp-mov-r12-rdi-v1",
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Associations {
    pub forward: u64,
    pub routed: u64,
    pub attempts: Vec<u64>,
}
fn geometry(f: &Facts, lower: &SelectedSite, upper: &SelectedSite) -> Option<Family> {
    use li2core::{
        contracts::{EntryCompleteness, ResumeObligation},
        engine::Tactic as CoreTactic,
        planner::HookSemantics,
    };
    if lower.length != 2
        || upper.length != 2
        || lower.pc.checked_add(2) != Some(upper.pc)
        || lower.snapshot != upper.snapshot
        || lower.function != lower.snapshot
        || upper.function != upper.snapshot
        || lower.heads != upper.heads
        || lower.completeness != EntryCompleteness::AllInstructionHeads
        || upper.completeness != EntryCompleteness::AllInstructionHeads
        || lower.resumes != upper.resumes
        || lower.provenance != upper.provenance
        || lower.hook != upper.hook
        || lower.heads.iter().any(|h| h.requires_endbr)
    {
        return None;
    }
    for site in [lower, upper] {
        if site.search.max_sites == 0 || site.semantics != HookSemantics::Observe {
            return None;
        }
        if let ResumeObligation::Enumerated(pcs) = &site.resumes {
            if pcs.windows(2).any(|w| w[0] >= w[1]) {
                return None;
            }
        }
    }
    let a = f.heads.get(&lower.pc)?;
    let b = f.heads.get(&upper.pc)?;
    if a.len() != 2 || b.len() != 2 {
        return None;
    }
    let target =
        |pc: u64, byte: u8| u64::try_from(i128::from(pc) + 2 + i128::from(byte as i8)).ok();
    let ta = target(lower.pc, a[1])?;
    let tb = target(upper.pc, b[1])?;
    if [lower, upper].iter().all(|s| {
        s.forced.is_none_or(|t| t == CoreTactic::GeneralizedPun)
            && s.pc
                .checked_add(5)
                .is_some_and(|end| end <= s.snapshot.end())
            && s.pc / 64 == (s.pc + 1) / 64
    }) && (0x70..=0x7f).contains(&a[0])
        && (0x70..=0x7f).contains(&b[0])
        && [ta, tb]
            .iter()
            .all(|t| *t >= upper.pc + 2 && lower.snapshot.contains(*t) && f.heads.contains_key(t))
    {
        return Some(Family::Forward);
    }
    let suffix = upper.pc.checked_add(2)?;
    let end = upper.pc.checked_add(5)?;
    if a[0] != 0x76
        || b[0] != 0xeb
        || !matches!(
            f.heads.get(&suffix).map(Vec::as_slice),
            Some([0x4c, 0x89, 0xe7] | [0x49, 0x8b, 0xfc])
        )
        || !lower.snapshot.contains(end)
        || lower.pc / 64 != (upper.pc - 1) / 64
        || lower
            .forced
            .is_some_and(|t| t != CoreTactic::GeneralizedPun)
        || upper.forced.is_some_and(|t| t != CoreTactic::Relocation)
        || matches!(&lower.resumes, ResumeObligation::Unresolved)
        || ta >= lower.pc
        || tb < end
        || [ta, tb, suffix, end]
            .iter()
            .any(|pc| !lower.snapshot.contains(*pc) || !f.heads.contains_key(pc))
        || f.selection
            .sites
            .iter()
            .any(|s| s.pc < end && s.pc + u64::from(s.length) > suffix)
    {
        return None;
    }
    Some(Family::Routed)
}
fn greedy(f: &Facts) -> BTreeMap<u64, (u64, Family)> {
    let sites = &f.selection.sites;
    let mut at = sites.len();
    let mut out = BTreeMap::new();
    while at > 0 {
        let upper = &sites[at - 1];
        if at > 1 {
            let lower = &sites[at - 2];
            if let Some(family) = geometry(f, lower, upper) {
                out.insert(upper.id, (lower.id, family));
                at -= 2;
                continue;
            }
        }
        at -= 1;
    }
    out
}
fn control_transfer(bytes: &[u8]) -> bool {
    matches!(
        bytes.first(),
        Some(0x70..=0x7f | 0xe0..=0xe3 | 0xe8 | 0xe9 | 0xeb | 0xc2 | 0xc3 | 0xca | 0xcb)
    ) || matches!(
        bytes.get(..2),
        Some([0x0f, 0x80..=0x8f] | [0x0f, 0x05] | [0x0f, 0x0b])
    )
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Decl {
    family: Family,
    attempt: u64,
    member: u64,
    role: String,
    selected: u64,
    image: usize,
    step: usize,
}
fn declaration(raw: &[u8]) -> Result<Option<Decl>> {
    // Debug suffix is bounded opaque bytes; it may not be valid UTF-8.
    let mut rows = raw.splitn(3, |b| *b == b'\n');
    let first = rows.next().unwrap_or_default();
    if !first.starts_with(b"pair_family=") {
        require(
            !first.starts_with(b"adjacent_attempt="),
            "pair family missing",
        )?;
        return Ok(None);
    }
    let family = match first {
        b"pair_family=forward-jcc-b2-v1" => Family::Forward,
        b"pair_family=jbe-routed-jmp-mov-r12-rdi-v1" => Family::Routed,
        _ => return Err("pair family spelling".into()),
    };
    let row = checked(std::str::from_utf8(
        rows.next().ok_or("pair association line")?,
    ))?;
    let f: Vec<_> = row.split(' ').collect();
    let keys = [
        "adjacent_attempt",
        "member",
        "role",
        "selected_id",
        "image_start",
        "image_count",
        "step_start",
        "step_count",
    ];
    require(f.len() == keys.len(), "pair association arity")?;
    let mut values = Vec::new();
    for (cell, key) in f.iter().zip(keys) {
        let (name, value) = cell.split_once('=').ok_or("pair association cell")?;
        require(name == key, "pair association ordered key")?;
        values.push(value);
    }
    require(
        values[5] == "1" && values[7] == "1" && rows.next().is_some(),
        "pair exact member population and suffix",
    )?;
    Ok(Some(Decl {
        family,
        attempt: number(values[0])?,
        member: number(values[1])?,
        role: values[2].into(),
        selected: number(values[3])?,
        image: host(number(values[4])?)?,
        step: host(number(values[6])?)?,
    }))
}
pub fn check(
    plans: &[Plan],
    f: &Facts,
    records: &[Site],
    files: &dyn Files,
) -> Result<Associations> {
    let groups = greedy(f);
    let mut totals = Associations::default();
    let mut expected_lower: Option<Decl> = None;
    let mut step_start = 0;
    let mut image_start = 0;
    for plan in plans {
        let site = &f.selection.sites[host(plan.owner - 1)?];
        let raw = files.read(&format!("site-{}.diagnostics.txt", plan.owner), FILE)?;
        let declared = declaration(&raw)?;
        let routed = declared
            .as_ref()
            .is_some_and(|d| d.family == Family::Routed && d.member == 0);
        for step in &plan.steps {
            let heads = displaced_heads(step, &f.heads)?;
            let early = heads
                .iter()
                .take(heads.len().saturating_sub(1))
                .any(|pc| control_transfer(&f.heads[pc]));
            require(
                !early || routed,
                "early control transfer lacks exact routed pair authority",
            )?;
        }
        match declared {
            None => require(expected_lower.is_none(), "paired lower member omitted")?,
            Some(d) => {
                require(
                    plan.steps.len() == 1
                        && plan.images.len() == 1
                        && d.selected == site.id
                        && d.image == image_start
                        && d.step == step_start,
                    "actual pair owner/image/step offsets",
                )?;
                let step = &plan.steps[0];
                let image = &plan.images[0];
                require(
                    step.logical == site.pc
                        && step.physical == site.pc
                        && image.routes.get(&site.pc) == Some(&image.entry),
                    "pair selected source and observing entry",
                )?;
                if d.member == 0 {
                    require(
                        expected_lower.is_none()
                            && d.role == "upper"
                            && !totals.attempts.contains(&d.attempt),
                        "unique upper pair attempt",
                    )?;
                    let (lower, family) = groups
                        .get(&site.id)
                        .ok_or("pair outside original greedy groups")?;
                    require(
                        d.family == *family && d.family.name() == first_family(&raw)?,
                        "independent original family",
                    )?;
                    totals.attempts.push(d.attempt);
                    match family {
                        Family::Forward => totals.forward += 1,
                        Family::Routed => totals.routed += 1,
                    };
                    expected_lower = Some(Decl {
                        family: *family,
                        attempt: d.attempt,
                        member: 1,
                        role: "lower".into(),
                        selected: *lower,
                        image: image_start + 1,
                        step: step_start + 1,
                    });
                    if *family == Family::Routed {
                        let suffix = site.pc + 2;
                        let body = image.boundaries.get(&suffix).ok_or("routed suffix body")?;
                        require(
                            records[host(site.id - 1)?].outcome
                                == Outcome::Rewritten(Tactic::Relocation)
                                && step.kind == "relocation"
                                && step.displaced == Range::new(site.pc, site.pc + 5)?
                                && image.routes.get(&suffix) == Some(body)
                                && step.entries == [(site.pc, None), (suffix, Some(*body))]
                                && step.write.as_ref().is_some_and(|(_, b)| {
                                    b.len() == 5
                                        && b[0] == 0xe9
                                        && [
                                            0x60, 0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27,
                                            0x2f, 0x37, 0x3f, 0x61, 0xce,
                                        ]
                                        .contains(&b[2])
                                }),
                            "exact routed upper suffix route/marker",
                        )?;
                    } else {
                        require(
                            records[host(site.id - 1)?].outcome
                                == Outcome::Rewritten(Tactic::GeneralizedPun),
                            "forward upper tactic",
                        )?;
                    }
                } else {
                    require(
                        expected_lower.take().as_ref() == Some(&d)
                            && records[host(site.id - 1)?].outcome
                                == Outcome::Rewritten(Tactic::GeneralizedPun),
                        "complete exact lower pair association",
                    )?;
                }
            }
        }
        step_start += plan.steps.len();
        image_start += plan.images.len();
    }
    require(expected_lower.is_none(), "unfinished accepted pair")?;
    Ok(totals)
}
fn first_family(raw: &[u8]) -> Result<&str> {
    let first = raw.split(|b| *b == b'\n').next().ok_or("family")?;
    checked(std::str::from_utf8(
        first.strip_prefix(b"pair_family=").ok_or("family")?,
    ))
}
