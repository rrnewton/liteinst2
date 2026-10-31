//! Strict version-one text input. Numeric fields are decimal or explicit 0x hex.
use crate::model::*;
use formats::ContentId;
use li2core::contracts::{AddressRange, EntryCompleteness, LegalEntry, ResumeObligation};
use li2core::engine::Tactic;
use li2core::planner::HookSemantics;
use li2core::quiescent::{AllocationPolicy, SearchPolicy, TacticPolicy};
use li2core::trampoline::SavedExtendedStateLayout;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Only the sealed complete-code importer supplies these independently decoded
/// regions and sites. A compact manifest cannot supply its own authority.
pub(crate) struct SharedRegion {
    pub range: AddressRange,
    pub heads: Arc<Vec<LegalEntry>>,
}
pub(crate) struct SharedEntries<'a> {
    pub original: ContentId,
    pub ledger: ContentId,
    pub regions: &'a [SharedRegion],
    pub sites: &'a [crate::disassembly::JumpSite],
    pub null_hook: u64,
}

pub fn parse(bytes: &[u8]) -> Result<Selection, Error> {
    if bytes.len() > 1024 * 1024 {
        return Err(bad("manifest exceeds 1 MiB"));
    }
    parse_records(bytes, None)
}

pub(crate) fn parse_shared_projection(
    bytes: &[u8],
    expected: &SharedEntries<'_>,
) -> Result<Selection, Error> {
    use crate::disassembly::whole::{HEAD_LIMIT, SELECTION_LIMIT, SITE_LIMIT};
    if bytes.len() > SELECTION_LIMIT {
        return Err(bad("shared manifest exceeds 2 MiB"));
    }
    let count = expected
        .regions
        .iter()
        .try_fold(0_usize, |n, r| n.checked_add(r.heads.len()));
    if expected.regions.is_empty()
        || count.is_none_or(|n| n == 0 || n > HEAD_LIMIT)
        || expected.sites.is_empty()
        || expected.sites.len() > SITE_LIMIT
    {
        return Err(bad("shared complete population bound"));
    }
    if bytes.last() != Some(&b'\n')
        || bytes
            .iter()
            .any(|b| *b != b'\n' && !(b' '..=b'~').contains(b))
        || bytes[..bytes.len().saturating_sub(1)]
            .split(|b| *b == b'\n')
            .any(|line| line.is_empty() || line.split(|b| *b == b' ').any(|part| part.is_empty()))
    {
        return Err(bad("shared canonical ASCII text"));
    }
    parse_records(bytes, Some(expected))
}

fn parse_records(bytes: &[u8], shared: Option<&SharedEntries<'_>>) -> Result<Selection, Error> {
    let text = std::str::from_utf8(bytes).map_err(|e| bad(e.to_string()))?;
    let mut lines = text.lines();
    let header = if shared.is_some() {
        "LI2TOOL-SHARED-REGIONS 1"
    } else {
        "LI2TOOL 1"
    };
    if lines.next() != Some(header) {
        return Err(bad("missing version-one header"));
    }
    let mut globals = BTreeMap::<&str, Vec<&str>>::new();
    let mut records = Vec::new();
    let mut keys = BTreeSet::new();
    let mut region_rows = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let f: Vec<_> = line.split_whitespace().collect();
        if f.is_empty() {
            return Err(bad("whitespace-only record"));
        }
        match f[0] {
            "profile" | "ledger" if shared.is_some() => {
                if globals.insert(f[0], f[1..].to_vec()).is_some() {
                    return Err(bad("duplicate shared global"));
                }
            }
            "region-entries" if shared.is_some() => region_rows.push(f),
            "entries-ref" if shared.is_some() => {
                exact(&f, 3)?;
                if !keys.insert((f[0], num(f[1])?, "")) {
                    return Err(bad("duplicate shared site reference"));
                }
                records.push(f);
            }
            "entries" if shared.is_some() => return Err(bad("expanded entries in shared profile")),
            "original" | "target" | "domain" | "carrier" | "limits" => {
                if globals.insert(f[0], f[1..].to_vec()).is_some() {
                    return Err(bad("duplicate global"));
                }
            }
            "hook" | "site" | "entries" | "resumes" | "search" | "allocation" => {
                if f.len() < 3 {
                    return Err(bad("short record"));
                }
                let key = (
                    f[0],
                    num(f[1])?,
                    if f[0] == "allocation" { f[2] } else { "" },
                );
                if !keys.insert(key) {
                    return Err(bad("duplicate site/hook record"));
                }
                records.push(f);
            }
            _ => return Err(bad("unknown record")),
        }
    }
    let get = |key| {
        globals
            .get(key)
            .ok_or_else(|| bad(format!("missing {key}")))
    };
    let original = get("original")?;
    exact(original, 1)?;
    if let Some(expected) = shared {
        use crate::disassembly::whole::PROFILE;
        if get("profile")?.as_slice() != [PROFILE]
            || get("ledger")?.len() != 1
            || id(get("ledger")?[0])? != expected.ledger
            || id(original[0])? != expected.original
            || region_rows.len() != expected.regions.len()
        {
            return Err(bad("shared profile/original/ledger/region census"));
        }
        for (index, (f, region)) in region_rows.iter().zip(expected.regions).enumerate() {
            if f.len() != 4 + region.heads.len()
                || num(f[1])? != index as u64 + 1
                || f[2] != "all-instruction-heads"
                || id(f[3])? != expected.ledger
            {
                return Err(bad("shared region shape/order/provenance"));
            }
            for (field, head) in f[4..].iter().zip(region.heads.iter()) {
                if *field != format!("{}:{}", head.address, usize::from(head.requires_endbr)) {
                    return Err(bad("shared independently decoded head/order/ENDBR"));
                }
            }
        }
    }
    if let Some(expected) = shared {
        let references: Vec<_> = records.iter().filter(|r| r[0] == "entries-ref").collect();
        if references.len() != expected.sites.len()
            || references
                .iter()
                .zip(expected.sites)
                .any(|(r, site)| num(r[1]).ok() != Some(site.id))
        {
            return Err(bad("shared complete reference census/order"));
        }
    }
    let domain = get("domain")?;
    exact(domain, 1)?;
    let carrier = get("carrier")?;
    exact(carrier, 1)?;
    let f = get("limits")?;
    exact(f, 9)?;
    let limits = Limits {
        input_bytes: size(f[0])?,
        sites: size(f[1])?,
        images: size(f[2])?,
        image_bytes: size(f[3])?,
        new_load_pages: num(f[4])?,
        output_bytes: num(f[5])?,
        added_file_bytes: num(f[6])?,
        program_headers: size(f[7])?,
        virtual_span: num(f[8])?,
    };
    let site_limit = if shared.is_some() {
        crate::disassembly::whole::SITE_LIMIT
    } else {
        1024
    };
    if limits.sites > site_limit
        || limits.input_bytes > 256 * 1024 * 1024
        || limits.output_bytes > 512 * 1024 * 1024
        || limits.images > 4096
        || limits.image_bytes > 64 * 1024 * 1024
        || limits.new_load_pages > 65536
        || limits.program_headers > 4096
    {
        return Err(bad("tool hard resource ceiling"));
    }
    let f = get("target")?;
    let target = match f.first().copied() {
        Some("fxsave64") => {
            exact(f, 1)?;
            SavedExtendedStateLayout::describe_target_fxsave64()
        }
        Some("xsave64") if f.len() >= 2 => {
            let components = f[2..]
                .iter()
                .map(|s| {
                    let p: Vec<_> = s.split(':').collect();
                    exact(&p, 3)?;
                    Ok((num(p[0])?, num(p[1])?, num(p[2])?))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            SavedExtendedStateLayout::describe_target_xsave64(num(f[1])?, &components)
                .map_err(|e| bad(e.to_string()))?
        }
        _ => return Err(bad("unknown target description")),
    };
    let mut hooks = Vec::new();
    let mut sites = Vec::new();
    for f in records.iter().filter(|f| f[0] == "hook") {
        exact(f, 5)?;
        hooks.push(Hook {
            id: num(f[1])?,
            pc: num(f[2])?,
            length: size(f[3])?,
            expected: id(f[4])?,
        });
    }
    if let Some(expected) = shared {
        if hooks.len() != 1
            || hooks[0].id != 1
            || hooks[0].pc != expected.null_hook
            || hooks[0].length != 1
            || hooks[0].expected != ContentId::of(&[0xc3])
        {
            return Err(bad("shared imported null hook"));
        }
    }
    for f in records.iter().filter(|f| f[0] == "site") {
        exact(f, 14)?;
        let site_id = num(f[1])?;
        if let Some(expected) = shared {
            let s = expected
                .sites
                .get(sites.len())
                .ok_or_else(|| bad("extra shared site"))?;
            if site_id != s.id
                || num(f[2])? != s.pc
                || size(f[3])? != s.length
                || num(f[4])? != s.file_offset
                || range(f[5], f[6])? != s.region
                || range(f[7], f[8])? != s.region
                || range(f[9], f[10])? != s.block
                || f[11] != "1"
                || f[12] != "observe"
            {
                return Err(bad("shared complete site geometry/order"));
            }
        }
        let lookup = |kind: &str, which: Option<&str>| -> Result<&Vec<&str>, Error> {
            records
                .iter()
                .find(|r| {
                    r[0] == kind
                        && num(r[1]).ok() == Some(site_id)
                        && which.is_none_or(|w| r[2] == w)
                })
                .ok_or_else(|| bad(format!("missing {kind} for {site_id}")))
        };
        let (heads, completeness) = if let Some(expected) = shared {
            let e = lookup("entries-ref", None)?;
            exact(e, 3)?;
            let index = size(e[2])?
                .checked_sub(1)
                .ok_or_else(|| bad("shared region zero"))?;
            let region = expected
                .regions
                .get(index)
                .ok_or_else(|| bad("unknown shared region"))?;
            if region.range != range(f[5], f[6])? {
                return Err(bad("cross-region shared head reference"));
            }
            (
                Arc::clone(&region.heads),
                EntryCompleteness::AllInstructionHeads,
            )
        } else {
            let e = lookup("entries", None)?;
            if e.len() < 5 {
                return Err(bad("entries require provenance and at least one head"));
            }
            let completeness = match e[2] {
                "complete" => EntryCompleteness::Complete,
                "unknown" => EntryCompleteness::Incomplete,
                _ => return Err(bad("entry completeness")),
            };
            let mut heads = Vec::new();
            for head in &e[4..] {
                let p: Vec<_> = head.split(':').collect();
                exact(&p, 2)?;
                let requires_endbr = match p[1] {
                    "0" => false,
                    "1" => true,
                    _ => return Err(bad("ENDBR flag")),
                };
                heads.push(LegalEntry {
                    address: num(p[0])?,
                    requires_endbr,
                });
            }
            if !heads.windows(2).all(|w| w[0].address < w[1].address) {
                return Err(bad("head ordering"));
            }
            (Arc::new(heads), completeness)
        };
        let r = lookup("resumes", None)?;
        let resumes = match r[2] {
            "none" => {
                exact(r, 3)?;
                ResumeObligation::NoneExist
            }
            "unknown" => {
                exact(r, 3)?;
                ResumeObligation::Unresolved
            }
            "enumerated" => ResumeObligation::Enumerated(
                r[3..].iter().map(|s| num(s)).collect::<Result<_, _>>()?,
            ),
            _ => return Err(bad("resume mode")),
        };
        if shared.is_some() && resumes != ResumeObligation::NoneExist {
            return Err(bad("shared private-image resume contract"));
        }
        let s = lookup("search", None)?;
        exact(s, 9)?;
        let forced = match s[2] {
            "preferred" => None,
            "B1" => Some(Tactic::Relocation),
            "B2" => Some(Tactic::GeneralizedPun),
            "T1" => Some(Tactic::PrefixedPun),
            "T2" => Some(Tactic::SuccessorEviction),
            "T3" => Some(Tactic::NeighborEviction),
            _ => return Err(bad("tactic")),
        };
        let allocation = |which| -> Result<AllocationPolicy, Error> {
            let a = lookup("allocation", Some(which))?;
            if a.len() < 7 {
                return Err(bad("allocation needs a range"));
            }
            let ranges = a[6..]
                .iter()
                .map(|r| {
                    let p: Vec<_> = r.split(':').collect();
                    exact(&p, 2)?;
                    range(p[0], p[1])
                })
                .collect::<Result<Vec<_>, Error>>()?;
            if ranges.len() > 16 {
                return Err(bad("too many permits"));
            }
            Ok(AllocationPolicy {
                ranges,
                preferred_address: optional(a[3])?,
                max_candidates: size(a[4])?,
                max_mappings: 1,
                max_mapped_bytes: size(a[5])?,
            })
        };
        let length = u8::try_from(num(f[3])?).map_err(|_| bad("instruction length"))?;
        if !(1..=15).contains(&length) {
            return Err(bad("instruction length"));
        }
        sites.push(SelectedSite {
            id: site_id,
            pc: num(f[2])?,
            length,
            file_offset: num(f[4])?,
            snapshot: range(f[5], f[6])?,
            function: range(f[7], f[8])?,
            block: range(f[9], f[10])?,
            hook: num(f[11])?,
            semantics: match f[12] {
                "observe" => HookSemantics::Observe,
                "replace" => HookSemantics::ReplaceFirst,
                _ => return Err(bad("semantics")),
            },
            forced,
            selected_allocation: allocation("selected")?,
            victim_allocation: allocation("victim")?,
            search: SearchPolicy {
                tactics: TacticPolicy::PreferGeneralizedPun,
                max_upstream_bytes: size(s[3])?,
                max_displaced_bytes: size(s[4])?,
                max_sites: size(s[5])?,
            },
            forced_victim: optional(s[6])?,
            max_victims: size(s[7])?,
            max_pairs: size(s[8])?,
            heads,
            completeness,
            resumes,
            provenance: match shared {
                Some(expected) => expected.ledger,
                None => id(lookup("entries", None)?[3])?,
            },
        });
        if f[13] != "original-decode" {
            return Err(bad("original decode assertion required"));
        }
    }
    if sites.is_empty()
        || sites.len() > limits.sites
        || hooks.is_empty()
        || hooks.len() > limits.sites
    {
        return Err(bad("site/hook count"));
    }
    if shared.is_some_and(|expected| sites.len() != expected.sites.len()) {
        return Err(bad("shared complete site census"));
    }
    sites.sort_by_key(|s| s.id);
    hooks.sort_by_key(|h| h.id);
    let known: BTreeSet<_> = sites.iter().map(|s| s.id).collect();
    if records
        .iter()
        .any(|r| r[0] != "hook" && !known.contains(&num(r[1]).unwrap()))
    {
        return Err(bad("orphan site record"));
    }
    if records
        .iter()
        .any(|r| r[0] == "allocation" && !["selected", "victim"].contains(&r[2]))
    {
        return Err(bad("allocation kind"));
    }
    if sites.iter().any(|s| {
        s.search.max_sites > 4096
            || s.search.max_displaced_bytes > 65536
            || s.search.max_upstream_bytes > 65536
            || s.max_victims > 65536
            || s.max_pairs > 1048576
            || [&s.selected_allocation, &s.victim_allocation]
                .iter()
                .any(|a| a.max_candidates > 65536 || a.max_mapped_bytes > 16 * 1024 * 1024)
    }) {
        return Err(bad("search hard resource ceiling"));
    }
    if sites.iter().any(|s| !hooks.iter().any(|h| h.id == s.hook)) {
        return Err(bad("missing hook"));
    }
    if hooks
        .iter()
        .any(|h| h.length == 0 || h.length > 65536 || !sites.iter().any(|s| s.hook == h.id))
    {
        return Err(bad("unused/invalid hook"));
    }
    Ok(Selection {
        original: id(original[0])?,
        manifest: bytes.to_vec(),
        target,
        bias_domain: num(domain[0])?,
        carrier_pc: num(carrier[0])?,
        limits,
        hooks,
        sites,
    })
}
/// Exact sealed-importer projection, not a public legacy-parser fallback.
/// The full input (including the family row) remains the selection identity.
pub(crate) fn parse_short_neighbor_projection(bytes: &[u8]) -> Result<Selection, Error> {
    if bytes.len() > 1024 * 1024 {
        return Err(bad("manifest exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| bad(e.to_string()))?;
    let mut rows = text.split_inclusive('\n');
    let header = rows.next().ok_or_else(|| bad("short projection header"))?;
    let original = rows
        .next()
        .ok_or_else(|| bad("short projection original"))?;
    let family = rows.next().ok_or_else(|| bad("short projection family"))?;
    if header != "LI2TOOL 1\n"
        || !original.starts_with("original ")
        || !original.ends_with('\n')
        || family != "neighbor-victims short-only\n"
    {
        return Err(bad("short projection family/order"));
    }
    let mut legacy = String::with_capacity(bytes.len() - family.len());
    legacy.push_str(header);
    legacy.push_str(original);
    for row in rows {
        if row.split_whitespace().next() == Some("neighbor-victims") {
            return Err(bad("duplicate short projection family"));
        }
        legacy.push_str(row);
    }
    let mut selection = parse(legacy.as_bytes())?;
    selection.manifest = bytes.to_vec();
    Ok(selection)
}

/// Version-three sealed projection. Both mode rows count toward the full bound
/// and remain in the identity; no public legacy replay or ownership callback.
pub(crate) fn parse_short_t3_ownership_projection(bytes: &[u8]) -> Result<Selection, Error> {
    if bytes.len() > 1024 * 1024 {
        return Err(bad("manifest exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| bad(e.to_string()))?;
    let mut rows = text.split_inclusive('\n');
    let header = rows
        .next()
        .ok_or_else(|| bad("owned short projection header"))?;
    let original = rows
        .next()
        .ok_or_else(|| bad("owned short projection original"))?;
    let family = rows
        .next()
        .ok_or_else(|| bad("owned short projection family"))?;
    let ownership = rows
        .next()
        .ok_or_else(|| bad("owned short projection ownership"))?;
    if header != "LI2TOOL 1\n"
        || !original.starts_with("original ")
        || !original.ends_with('\n')
        || family != "neighbor-victims short-only\n"
        || ownership != "neighbor-ownership inherited-t3\n"
    {
        return Err(bad("owned short projection mode/order"));
    }
    let mut legacy = String::with_capacity(bytes.len() - family.len() - ownership.len());
    legacy.push_str(header);
    legacy.push_str(original);
    for row in rows {
        if matches!(
            row.split_whitespace().next(),
            Some("neighbor-victims" | "neighbor-ownership")
        ) {
            return Err(bad("duplicate owned short projection mode"));
        }
        legacy.push_str(row);
    }
    let mut selection = parse(legacy.as_bytes())?;
    selection.manifest = bytes.to_vec();
    Ok(selection)
}

/// Version-four sealed projection. All three exact mode rows count toward the
/// full bound and identity; the private legacy view grants no replay authority.
pub(crate) fn parse_short_t3_pending_projection(bytes: &[u8]) -> Result<Selection, Error> {
    if bytes.len() > 1024 * 1024 {
        return Err(bad("manifest exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| bad(e.to_string()))?;
    let mut rows = text.split_inclusive('\n');
    let header = rows
        .next()
        .ok_or_else(|| bad("pending projection header"))?;
    let original = rows
        .next()
        .ok_or_else(|| bad("pending projection original"))?;
    let family = rows
        .next()
        .ok_or_else(|| bad("pending projection family"))?;
    let ownership = rows
        .next()
        .ok_or_else(|| bad("pending projection ownership"))?;
    let pending = rows
        .next()
        .ok_or_else(|| bad("pending projection selection"))?;
    if header != "LI2TOOL 1\n"
        || !original.starts_with("original ")
        || !original.ends_with('\n')
        || family != "neighbor-victims short-only\n"
        || ownership != "neighbor-ownership inherited-t3\n"
        || pending != "pending-selected full-instruction-ownership\n"
    {
        return Err(bad("pending projection mode/order"));
    }
    let mut legacy =
        String::with_capacity(bytes.len() - family.len() - ownership.len() - pending.len());
    legacy.push_str(header);
    legacy.push_str(original);
    for row in rows {
        if matches!(
            row.split_whitespace().next(),
            Some("neighbor-victims" | "neighbor-ownership" | "pending-selected")
        ) {
            return Err(bad("duplicate pending projection mode"));
        }
        legacy.push_str(row);
    }
    let mut selection = parse(legacy.as_bytes())?;
    selection.manifest = bytes.to_vec();
    Ok(selection)
}

fn bad(message: impl Into<String>) -> Error {
    Error {
        stage: "selection",
        detail: message.into(),
    }
}
fn exact(f: &[&str], n: usize) -> Result<(), Error> {
    if f.len() == n {
        Ok(())
    } else {
        Err(bad("record field count"))
    }
}
fn range(start: &str, len: &str) -> Result<AddressRange, Error> {
    AddressRange::new(num(start)?, size(len)?).map_err(|e| bad(e.to_string()))
}
pub fn num(s: &str) -> Result<u64, Error> {
    if let Some(s) = s.strip_prefix("0x") {
        u64::from_str_radix(s, 16)
    } else {
        s.parse()
    }
    .map_err(|_| bad("unsigned number"))
}
fn size(s: &str) -> Result<usize, Error> {
    usize::try_from(num(s)?).map_err(|_| bad("host size"))
}
fn optional(s: &str) -> Result<Option<u64>, Error> {
    if s == "none" {
        Ok(None)
    } else {
        num(s).map(Some)
    }
}
pub fn id(s: &str) -> Result<ContentId, Error> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("SHA-256"));
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| bad("SHA-256"))?;
    }
    Ok(ContentId(out))
}
