//! Named static-ET_EXEC startup products. Structural output is not execution authority.
use super::*;
use disassembly::adjacent_routed_jmp::AdjacentRoutedJmpDisassemblySelection;
use formats::startup as boot;

/// This producer always retains both authored program denominators.
pub const PROFILE: &str = "elf-disassembly-null-jumps-static-exec-router-bootstrap-v1";
/// A separate bounded policy freezes pathnames and runtime package identities.
pub const POLICY_LIMIT: usize = 64 * 1024;

/// Immutable checked binding. It contains no caller-authored route/image arrays.
#[derive(Clone, Debug)]
pub struct Bound {
    selected: AdjacentRoutedJmpDisassemblySelection,
    heads: Vec<u64>,
    program: u64,
    runtime: boot::Policy,
    startup: carrier::StartupLimits,
    policy: Vec<u8>,
}
impl Bound {
    /// Bind the full original decoder roster and all jumps before any planning.
    pub fn bind(
        original: &[u8],
        disassembly: &[u8],
        disassembly_id: ContentId,
        planning: &[u8],
        planning_id: ContentId,
        runtime: &[u8],
        runtime_id: ContentId,
    ) -> Result<Self, Error> {
        check(
            original.len() <= boot::MAX_FILE,
            "runtime original file bound",
        )?;
        let imported = disassembly::import(original, disassembly, disassembly_id)?;
        let heads = imported.original_heads();
        let selected = imported.bind_adjacent_routed_jmp(planning, planning_id)?;
        let (program, policy, startup) = parse_policy(
            runtime,
            runtime_id,
            original,
            disassembly_id,
            planning_id,
            &selected.base.selection,
        )?;
        let (nh, ns) = denominator(program)?;
        check(
            heads.len() == nh
                && heads.windows(2).all(|w| w[0] < w[1])
                && selected.base.selection.sites.len() == ns,
            "full original denominator",
        )?;
        Ok(Self {
            selected,
            heads,
            program,
            runtime: policy,
            startup,
            policy: runtime.to_vec(),
        })
    }
    /// Exact existing v6 manifest; neither planning limits nor source records change.
    pub fn manifest(&self) -> &[u8] {
        self.selected.manifest()
    }
    /// Full immutable binding evidence, also retained if downstream construction refuses.
    pub fn binding_files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut files = self.selected.base.files.clone();
        files.insert("selection.txt".into(), self.manifest().to_vec());
        files.insert("startup-policy.txt".into(), self.policy.clone());
        files.insert("startup-profile.tsv".into(),format!(
            "LI2STARTUP-PRODUCER\t1\nprofile\t{PROFILE}\nruntime_profile\t{}\nplanning_profile\t{}\nprogram\t{}\noriginal_heads\t{}\nselected_sites\t{}\nruntime_policy_sha256\t{}\nqualification_complete\tfalse\nexecution_authority\tnone\n",
            boot::PROFILE, self.selected.profile(), program_name(self.program), self.heads.len(), self.selected.base.selection.sites.len(), ledger::hex(&ContentId::of(&self.policy).0)).into_bytes());
        files
    }
}
fn denominator(program: u64) -> Result<(usize, usize), Error> {
    match program {
        1 => Ok((80, 16)),
        2 => Ok((107, 26)),
        _ => Err(Error::new("startup-policy", "program")),
    }
}
fn program_name(program: u64) -> &'static str {
    if program == 1 {
        "checksum"
    } else {
        "rle-roundtrip"
    }
}
fn check(ok: bool, detail: &'static str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::new("startup-policy", detail))
    }
}
fn number(s: &str) -> Result<u64, Error> {
    check(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0')),
        "canonical integer",
    )?;
    s.parse().map_err(|e| Error::new("startup-policy", e))
}
fn path(s: &str) -> Result<Vec<u8>, Error> {
    check(
        s.len() > 1
            && s.len() <= 4095
            && s.starts_with('/')
            && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
            && !s
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == ".."),
        "canonical absolute pathname",
    )?;
    Ok(s.as_bytes().to_vec())
}
fn fields<'a>(row: &'a str, tag: &str, n: usize) -> Result<Vec<&'a str>, Error> {
    let f = row.split(' ').collect::<Vec<_>>();
    check(
        f.len() == n && f[0] == tag && f.iter().all(|s| !s.is_empty()),
        "policy fields/order",
    )?;
    Ok(f)
}
fn id(s: &str) -> Result<ContentId, Error> {
    let id = selection::id(s)?;
    check(ledger::hex(&id.0) == s, "canonical identity")?;
    Ok(id)
}
fn parse_policy(
    bytes: &[u8],
    expected: ContentId,
    original: &[u8],
    disassembly: ContentId,
    planning: ContentId,
    selected: &Selection,
) -> Result<(u64, boot::Policy, carrier::StartupLimits), Error> {
    check(
        bytes.len() <= POLICY_LIMIT && ContentId::of(bytes) == expected,
        "runtime policy identity/size",
    )?;
    let text = std::str::from_utf8(bytes).map_err(|e| Error::new("startup-policy", e))?;
    check(
        text.ends_with('\n') && !text.contains('\r') && !text.contains('\t'),
        "canonical policy text",
    )?;
    let r = text.lines().collect::<Vec<_>>();
    check((12..=27).contains(&r.len()), "runtime policy cardinality")?;
    check(
        r[0] == "LI2BOOTSTRAP-POLICY 1" && r[1] == format!("profile {}", boot::PROFILE),
        "runtime profile",
    )?;
    let program = match fields(r[2], "program", 2)?[1] {
        "checksum" => 1,
        "rle-roundtrip" => 2,
        _ => return Err(Error::new("startup-policy", "program")),
    };
    for (row, tag, expected) in [
        (r[3], "original", ContentId::of(original)),
        (r[4], "disassembly", disassembly),
        (r[5], "planning-policy", planning),
    ] {
        check(
            id(fields(row, tag, 2)?[1])? == expected,
            "input identity join",
        )?;
    }
    let interpreter = path(fields(r[6], "interpreter", 2)?[1])?;
    let bootstrap_dso = path(fields(r[7], "bootstrap", 2)?[1])?;
    let a = fields(r[8], "app-stack", 3)?;
    let app_stack = boot::Span {
        start: number(a[1])?,
        len: number(a[2])?,
    };
    check(
        app_stack.len == 65536 && app_stack.start % 16 == 0 && app_stack.end().is_ok(),
        "fixed application stack",
    )?;
    let qualification_contract = id(fields(r[9], "qualification-contract", 2)?[1])?;
    check(
        qualification_contract.0 != [0; 32],
        "external qualification contract ID",
    )?;
    let f = fields(r[10], "startup-limits", 9)?;
    let caps = f[1..]
        .iter()
        .map(|s| number(s))
        .collect::<Result<Vec<_>, _>>()?;
    for (&n, cap) in caps
        .iter()
        .zip([4096, 4096, 4097, 112, 16384, 4096, 65536, 1048576])
    {
        check(n <= cap, "startup ceiling")?;
    }
    check(
        caps[0] > interpreter.len() as u64
            && caps[1] > bootstrap_dso.len() as u64
            && caps[2] >= bootstrap_dso.len() as u64 + 2
            && caps[3] == 112,
        "startup pathname/dynamic limits",
    )?;
    let startup = carrier::StartupLimits {
        max_interpreter_bytes: caps[0],
        max_needed_bytes: caps[1],
        max_string_table_bytes: caps[2],
        max_dynamic_bytes: caps[3],
        max_metadata_bytes: caps[4],
        max_input_sections: caps[5] as usize,
        max_input_symbols: caps[6] as usize,
        max_input_string_bytes: caps[7],
    };
    let mut dependencies = Vec::new();
    let mut previous: Option<Vec<u8>> = None;
    for row in &r[11..] {
        let f = fields(row, "dependency", 3)?;
        let p = path(f[1])?;
        let identity = id(f[2])?;
        check(
            identity.0 != [0; 32]
                && p != bootstrap_dso
                && previous.as_ref().is_none_or(|last| last < &p),
            "canonical dependency roster",
        )?;
        previous = Some(p.clone());
        dependencies.push(boot::Dependency { path: p, identity });
    }
    check(
        dependencies.iter().any(|d| d.path == interpreter),
        "interpreter dependency required",
    )?;
    check(
        selected.hooks.len() == 1
            && selected.hooks[0].length == 1
            && selected.hooks[0].expected == ContentId::of(&[0xc3])
            && selected
                .sites
                .iter()
                .all(|s| s.hook == selected.hooks[0].id),
        "one existing null hook",
    )?;
    let state = selected.target;
    let runtime = boot::Policy {
        interpreter,
        bootstrap_dso,
        dependencies,
        app_stack,
        hook_pc: selected.hooks[0].pc,
        hook_id: selected.hooks[0].id,
        state: boot::State {
            domain: selected.bias_domain,
            format: if state.format() == li2core::trampoline::SavedExtendedStateFormat::FXSAVE64 {
                1
            } else {
                2
            },
            allocation: state.len(),
            image: state.image_len(),
            mask: state.mask(),
            components: state
                .components()
                .iter()
                .map(|c| (c.xfeature(), c.offset(), c.size()))
                .collect(),
        },
        qualification_contract,
    };
    Ok((program, runtime, startup))
}

/// Plan each full program exactly once, with no old-profile fallback or partial
/// Product escape. Both calls run before any result dispatch. No subset API is
/// exported. The outer package/DSO build and every runtime gate remain separate.
pub fn prepare_programs(
    originals: [&[u8]; 2],
    selected: [&Bound; 2],
) -> Result<[Product; 2], Error> {
    prepare_programs_with_gate(originals, selected, |_, _| Ok(()))
}
fn prepare_programs_with_gate(
    originals: [&[u8]; 2],
    selected: [&Bound; 2],
    mut gate: impl FnMut(u64, &'static str) -> Result<(), Error>,
) -> Result<[Product; 2], Error> {
    check(
        selected[0].program == 1 && selected[1].program == 2,
        "fixed two-program order",
    )?;
    check(
        selected[0].runtime.bootstrap_dso != selected[1].runtime.bootstrap_dso,
        "distinct per-product DSO paths",
    )?;
    let first = prepare_one(originals[0], selected[0], |stage| gate(1, stage));
    let second = prepare_one(originals[1], selected[1], |stage| gate(2, stage));
    let mut failed = false;
    let mut outcomes = Vec::new();
    for (program, result) in [(1, &first), (2, &second)] {
        match result {
            Err(e) => {
                failed = true;
                outcomes.push(format!("{} terminal {e}", program_name(program)));
            }
            Ok(p) => {
                failed |= !p.candidate_complete();
                // Retain every local row honestly, including a complete local
                // result withheld when its peer fails. Neither Product escapes.
                outcomes.push(format!(
                    "{} local_candidate_complete={} report_hex={}",
                    program_name(program),
                    p.candidate_complete(),
                    ledger::hex(&p.files["report.tsv"])
                ));
            }
        }
    }
    if failed {
        return Err(Error::new("startup-whole-programs", outcomes));
    }
    match (first, second) {
        (Ok(a), Ok(b)) => Ok([a, b]),
        _ => unreachable!("failure collected above"),
    }
}
fn prepare_one(
    original: &[u8],
    selected: &Bound,
    gate: impl FnMut(&'static str) -> Result<(), Error>,
) -> Result<Product, Error> {
    let limits = selected.selected.limits;
    let mut product = prepare_selection_transaction(
        original,
        selected.selected.base.selection.clone(),
        false,
        disassembly::NeighborMode::ShortT3Pending,
        Some(disassembly::adjacent_b2::AdjacentB2Limits {
            upper: limits.upper,
            lower: limits.lower,
            joint: limits.joint,
        }),
        adjacent_b2_frontend::PairProfile::RoutedJmpUnion,
        TransactionHooks {
            addon: Some(selected),
            gate,
        },
    )?;
    product.files.remove("bundle-index.tsv");
    product.files.extend(selected.binding_files());
    product.files.insert(
        "bundle-index.tsv".into(),
        ledger::index(selected.selected.base.selection.original, &product.files),
    );
    Ok(product)
}
impl CandidateAddon for Bound {
    fn reservation(&self, legacy_bytes: u64) -> Result<u64, Error> {
        round_page(
            legacy_bytes
                .checked_add(self.startup.max_metadata_bytes)
                .ok_or_else(|| Error::new("startup-reservation", "overflow"))?,
        )
    }
    fn carrier(
        &self,
        elf: &Elf64<'_>,
        request: carrier::ImageRequest<'_>,
        edits: &[carrier::DeclaredEdit],
        policy: carrier::ImagePolicy,
    ) -> Result<carrier::CarrierOutput, carrier::Error> {
        carrier::append_static_exec_with_router_startup(
            elf,
            request,
            edits,
            policy,
            carrier::StaticExecStartup {
                interpreter: std::str::from_utf8(&self.runtime.interpreter)
                    .expect("bound ASCII path"),
                bootstrap_dso: std::str::from_utf8(&self.runtime.bootstrap_dso)
                    .expect("bound ASCII path"),
                limits: self.startup,
            },
        )
    }
    fn finish(
        &self,
        original: &[u8],
        selection: &Selection,
        accepted: &[(u64, ArtifactPlan)],
        files: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), Error> {
        let get = |name: &str| {
            files
                .get(name)
                .cloned()
                .ok_or_else(|| Error::new("startup-transaction", name))
        };
        let input = boot::Input {
            program: self.program,
            policy: self.runtime.clone(),
            original: original.to_vec(),
            main: get("candidate.elf")?,
            selection: selection.manifest.clone(),
            metadata: get("metadata.li2meta")?,
            target: get("target.tsv")?,
            ledger: get("ledger.tsv")?,
            heads: self.heads.clone(),
            steps: Vec::new(),
            images: Vec::new(),
        };
        let catalog = li2core::offline_router::catalog_from_plans(input, accepted)
            .map_err(|e| Error::new("startup-catalog", e))?;
        let bytes = catalog
            .encode()
            .map_err(|e| Error::new("startup-catalog-wire", e))?;
        files.insert("catalog.li2boot".into(), bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
