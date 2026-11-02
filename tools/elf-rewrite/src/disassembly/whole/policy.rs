//! Input-independent construction of one explicitly bounded whole policy.
//! All supplied heads/premises and all planner/carrier refusals remain required.
use super::super::{Disassembly, append, check, rows};
use crate::carrier::elf64::{Elf64, ObjectType, ParseLimits, SegmentType};
use crate::model::{Error, Limits, SelectedSite};
use crate::{addr, carrier_table_reservation, ledger, round_page, selection};
use formats::ContentId;
use iced_x86::Code;
use li2core::contracts::AddressRange;
use li2core::trampoline::{SavedExtendedStateFormat, SavedExtendedStateLayout};
use std::fmt::Write as _;

pub const PROFILE: &str = "et-exec-whole-bounded-512m-v1";
const PAGE: u64 = 4096;
const LOW: u64 = 262144;
const HIGH: u64 = 536870912;
// Literal numerical ceilings of full_program_bounded_hull_policy.py.
const LIMITS: Limits = Limits {
    input_bytes: 1048576,
    sites: 4096,
    images: 2896,
    image_bytes: 11862016,
    new_load_pages: 2936,
    output_bytes: 12120064,
    added_file_bytes: 12026544,
    program_headers: 2910,
    virtual_span: HIGH,
};

#[derive(Clone, Copy, Debug)]
pub enum NullHook {
    LowestOriginalRet,
    Address(u64),
}
#[derive(Clone, Copy, Debug)]
pub enum Carrier {
    AfterLoads,
    Address(u64),
}

/// Explicit new-profile inputs; none grants loader, CPU or execution authority.
#[derive(Clone, Copy, Debug)]
pub struct PolicyOptions {
    pub domain: u64,
    pub hook: NullHook,
    pub carrier: Carrier,
    pub arena: AddressRange,
}
#[derive(Clone, Debug)]
pub struct RolePlacement {
    pub preferred: Option<u64>,
    pub permits: Vec<AddressRange>,
}
#[derive(Clone, Debug)]
pub struct SitePlacement {
    pub id: u64,
    pub selected: RolePlacement,
    pub victim: RolePlacement,
}
#[derive(Clone, Debug)]
pub struct WholePolicySpec {
    pub options: PolicyOptions,
    pub target: SavedExtendedStateLayout,
    /// Complete imported site order, including sites that may later refuse.
    pub sites: Vec<SitePlacement>,
}

fn geometry(
    imported: &Disassembly,
    original: &[u8],
    options: PolicyOptions,
) -> Result<(u64, u64), Error> {
    check(
        ContentId::of(original) == imported.original,
        "policy original identity",
    )?;
    check(original.len() <= LIMITS.input_bytes, "policy original size")?;
    let elf = Elf64::parse(
        original,
        ParseLimits {
            max_program_headers: LIMITS.program_headers,
        },
    )
    .map_err(|e| Error::new("policy-elf", e))?;
    check(
        elf.header().object_type == ObjectType::Executable,
        "policy requires ET_EXEC",
    )?;
    elf.check_load_page_congruence(PAGE)
        .map_err(|e| Error::new("policy-elf", e))?;
    let mut loads = Vec::new();
    for load in elf
        .segments(SegmentType::Load)
        .filter(|p| p.memory_size != 0)
    {
        let end = round_page(
            load.vaddr
                .0
                .checked_add(load.memory_size)
                .ok_or_else(|| Error::new("elf-range", "overflow"))?,
        )?;
        let start = load.vaddr.0 & !(PAGE - 1);
        loads.push(addr(start, end - start)?);
    }
    let after_loads = loads
        .iter()
        .map(|r| r.end())
        .max()
        .ok_or_else(|| Error::new("policy-elf", "no nonempty LOAD"))?;
    let carrier = match options.carrier {
        Carrier::AfterLoads => after_loads,
        Carrier::Address(pc) => pc,
    };
    check(carrier % PAGE == 0, "carrier page alignment")?;
    let reserved = addr(carrier, carrier_table_reservation(LIMITS.program_headers)?)?;
    let arena = options.arena;
    check(
        arena.start() >= LOW
            && arena.end() <= HIGH
            && arena.start() % PAGE == 0
            && arena.len() % PAGE == 0,
        "bounded page-aligned policy arena",
    )?;
    check(
        reserved.end() <= HIGH
            && !reserved.overlaps(arena)
            && loads
                .iter()
                .all(|r| !r.overlaps(reserved) && !r.overlaps(arena)),
        "LOAD/carrier/arena overlap or extent",
    )?;
    let is_hook = |pc| {
        imported
            .regions
            .iter()
            .flat_map(|r| &r.instructions)
            .any(|i| i.ip() == pc && i.code() == Code::Retnq && i.len() == 1)
    };
    let hook = match options.hook {
        NullHook::Address(pc) => pc,
        NullHook::LowestOriginalRet => imported
            .regions
            .iter()
            .flat_map(|r| &r.instructions)
            .filter(|i| i.code() == Code::Retnq && i.len() == 1)
            .map(|i| i.ip())
            .min()
            .ok_or_else(|| Error::new("policy-hook", "no original C3 head"))?,
    };
    check(is_hook(hook), "null hook is not an original C3 head")?;
    // The later prepare hook-ownership/relocation checks are not discharged here.
    Ok((hook, carrier))
}

fn header(
    imported: &Disassembly,
    options: PolicyOptions,
    target: &str,
    hook: u64,
    carrier: u64,
) -> String {
    format!(
        "LI2DISASM-WHOLE-POLICY 1\noriginal {}\nledger {}\n{target}\ndomain {}\ncarrier {carrier}\nlimits {} {} {} {} {} {} {} {} {}\nnull-hook {hook}\n",
        ledger::hex(&imported.original.0),
        ledger::hex(&ContentId::of(&imported.ledger).0),
        options.domain,
        LIMITS.input_bytes,
        LIMITS.sites,
        LIMITS.images,
        LIMITS.image_bytes,
        LIMITS.new_load_pages,
        LIMITS.output_bytes,
        LIMITS.added_file_bytes,
        LIMITS.program_headers,
        LIMITS.virtual_span
    )
}

fn target_record(target: SavedExtendedStateLayout) -> Result<String, Error> {
    if target.format() == SavedExtendedStateFormat::FXSAVE64 {
        return Ok("target fxsave64".to_owned());
    }
    check(
        target.format() == SavedExtendedStateFormat::XSAVE64_STANDARD,
        "policy target unavailable",
    )?;
    let mut text = format!("target xsave64 {}", target.mask());
    for component in target.components() {
        write!(
            text,
            " {}:{}:{}",
            component.xfeature(),
            component.offset(),
            component.size()
        )
        .unwrap();
    }
    Ok(text)
}

fn fixed_site(site: &SelectedSite) -> Result<(), Error> {
    check(
        site.forced.is_none()
            && site.search.max_upstream_bytes == 64
            && site.search.max_displaced_bytes == 256
            && site.search.max_sites == 64
            && site.forced_victim.is_none()
            && site.max_victims == 256
            && site.max_pairs == 4096,
        "unchanged bounded search tuple",
    )?;
    for allocation in [&site.selected_allocation, &site.victim_allocation] {
        check(
            allocation.max_candidates == 1
                && allocation.max_mappings == 1
                && allocation.max_mapped_bytes == 4096,
            "unchanged candidate/image limits",
        )?;
    }
    Ok(())
}

/// Decode target/search/allocation records through the existing whole binder.
/// This adds fixed-profile checks; it does not introduce another input grammar.
pub fn spec_from_records(
    imported: &Disassembly,
    original: &[u8],
    options: PolicyOptions,
    target: &[u8],
    records: &[u8],
) -> Result<WholePolicySpec, Error> {
    let (hook, carrier) = geometry(imported, original, options)?;
    let target_rows = rows(target)?;
    check(
        target_rows.len() == 1 && target_rows[0].starts_with("target "),
        "one target record",
    )?;
    let record_rows = rows(records)?;
    check(
        imported.jumps.len() <= LIMITS.sites && record_rows.len() == imported.jumps.len() * 3,
        "complete ordered policy records",
    )?;
    for (site, triple) in imported.jumps.iter().zip(record_rows.chunks_exact(3)) {
        for (row, (tag, role)) in triple.iter().zip([
            ("search", None),
            ("allocation", Some("selected")),
            ("allocation", Some("victim")),
        ]) {
            let fields: Vec<_> = row.split(' ').collect();
            check(
                fields.len() >= 3
                    && fields[0] == tag
                    && selection::num(fields[1])? == site.id
                    && role.is_none_or(|r| fields[2] == r),
                "policy site/role order",
            )?;
        }
    }
    let mut raw = header(imported, options, target_rows[0], hook, carrier);
    append(
        &mut raw,
        std::str::from_utf8(records).map_err(|e| Error::new("policy-text", e))?,
    )?;
    let selected = imported
        .clone()
        .bind_whole_program(raw.as_bytes(), ContentId::of(raw.as_bytes()))?;
    let mut sites = Vec::new();
    for site in &selected.selection.sites {
        fixed_site(site)?;
        let role = |a: &li2core::quiescent::AllocationPolicy| RolePlacement {
            preferred: a.preferred_address,
            permits: a.ranges.clone(),
        };
        sites.push(SitePlacement {
            id: site.id,
            selected: role(&site.selected_allocation),
            victim: role(&site.victim_allocation),
        });
    }
    Ok(WholePolicySpec {
        options,
        target: selected.selection.target,
        sites,
    })
}

fn clipped(role: &RolePlacement, arena: AddressRange) -> Result<Vec<AddressRange>, Error> {
    check(
        (1..=16).contains(&role.permits.len()),
        "existing 1..16 permit bound",
    )?;
    let mut kept = Vec::new();
    for permit in &role.permits {
        check(
            permit.start() % PAGE == 0 && permit.len() % PAGE == 0,
            "page-aligned permit",
        )?;
        let start = permit.start().max(arena.start());
        let end = permit.end().min(arena.end());
        if start < end {
            kept.push(addr(start, end - start)?);
        }
    }
    check(
        !kept.is_empty(),
        "no in-arena permit; complete policy refused",
    )?;
    Ok(kept)
}

/// Serialize a complete policy; preserve permit order/duplicates and preferences.
/// No placement search, emission, retry or executable qualification occurs here.
pub fn build_policy(
    imported: &Disassembly,
    original: &[u8],
    spec: &WholePolicySpec,
) -> Result<Vec<u8>, Error> {
    let (hook, carrier) = geometry(imported, original, spec.options)?;
    check(
        spec.sites.len() == imported.jumps.len() && spec.sites.len() <= LIMITS.sites,
        "complete policy site census",
    )?;
    let mut text = header(
        imported,
        spec.options,
        &target_record(spec.target)?,
        hook,
        carrier,
    );
    for (site, expected) in spec.sites.iter().zip(&imported.jumps) {
        check(site.id == expected.id, "complete policy site order")?;
        append(
            &mut text,
            &format!("search {} preferred 64 256 64 none 256 4096\n", site.id),
        )?;
        for (name, role) in [("selected", &site.selected), ("victim", &site.victim)] {
            let permits = clipped(role, spec.options.arena)?;
            let preferred = role
                .preferred
                .map_or_else(|| "none".into(), |v| v.to_string());
            let mut row = format!("allocation {} {name} {preferred} 1 4096", site.id);
            for permit in permits {
                write!(row, " {}:{}", permit.start(), permit.len()).unwrap();
            }
            row.push('\n');
            append(&mut text, &row)?;
        }
    }
    // Preserve all independently decoded heads and the complete existing binder.
    imported
        .clone()
        .bind_whole_program(text.as_bytes(), ContentId::of(text.as_bytes()))?;
    Ok(text.into_bytes())
}
