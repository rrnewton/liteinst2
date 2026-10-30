//! Additive, independent saved startup-main joins. This is never final package
//! acceptance: no DSO is built/loaded here, and every native gate remains open.
use super::*;
use formats::startup as boot;
#[path = "startup/catalog.rs"]
mod catalog;
#[path = "startup/dependencies.rs"]
mod dependencies;
#[path = "startup/layout.rs"]
pub(super) mod layout;
#[cfg(test)]
#[path = "startup/tests.rs"]
mod tests;

pub const PROFILE: &str = "elf-disassembly-null-jumps-static-exec-router-bootstrap-v1";
const RUNTIME_PROFILE: &str = "linux-x86-64-static-exec-router-bootstrap-v1";
pub const POLICY_BYTES: usize = 65_536;
#[derive(Clone)]
pub struct Inputs {
    pub policy: Vec<u8>,
    /// Bytes numbered in independently parsed, strictly sorted policy path order.
    /// No policy path is ever opened by this verifier.
    pub dependencies: Vec<Vec<u8>>,
}
#[derive(Clone, Debug)]
pub(super) struct Policy {
    pub program: u64,
    pub runtime: boot::Policy,
    pub caps: [u64; 8],
}
#[derive(Debug)]
pub struct Summary {
    pub original_heads: usize,
    pub catalog_sha256: String,
    pub startup_policy_sha256: String,
    pub dependency_roster_sha256: String,
}
pub fn verify(
    program: &str,
    original: &[u8],
    expected: &Expected,
    product: &dyn Files,
    input: &Inputs,
) -> Result<(super::Summary, Summary)> {
    let (summary, startup) = super::verify_mode(program, original, expected, product, Some(input))?;
    Ok((summary, startup.ok_or("missing startup summary")?))
}
fn words<'a>(line: &'a str, key: &str, count: usize) -> Result<Vec<&'a str>> {
    let f: Vec<_> = line.split(' ').collect();
    require(
        f.len() == count && f[0] == key && f.iter().all(|s| !s.is_empty()),
        "startup policy fields/order",
    )?;
    Ok(f)
}
fn path(s: &str) -> Result<Vec<u8>> {
    require(
        s.len() > 1
            && s.len() <= 4095
            && s.starts_with('/')
            && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
            && !s
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == ".."),
        "canonical startup absolute path",
    )?;
    Ok(s.as_bytes().to_vec())
}
fn id(s: &str) -> Result<ContentId> {
    Ok(ContentId(checked(unhex(s)?.try_into())?))
}
fn policy(
    program: &str,
    bytes: &[u8],
    original: &[u8],
    facts: &Facts,
    product: &dyn Files,
) -> Result<Policy> {
    require(
        bytes.len() <= POLICY_BYTES && !bytes.contains(&b'\t'),
        "startup policy text cap",
    )?;
    let r = lines(bytes)?;
    require(
        (12..=27).contains(&r.len())
            && r[0] == "LI2BOOTSTRAP-POLICY 1"
            && r[1] == format!("profile {RUNTIME_PROFILE}")
            && words(r[2], "program", 2)?[1] == program,
        "startup policy profile/program",
    )?;
    for (row, key, value) in [
        (r[3], "original", digest(original)),
        (
            r[4],
            "disassembly",
            digest(&product.read("disassembly.txt", TEXT)?),
        ),
        (
            r[5],
            "planning-policy",
            digest(&product.read("disassembly-policy.txt", TEXT)?),
        ),
    ] {
        require(
            words(row, key, 2)?[1] == value,
            "startup policy independent input identity",
        )?;
    }
    let interpreter = path(words(r[6], "interpreter", 2)?[1])?;
    let bootstrap_dso = path(words(r[7], "bootstrap", 2)?[1])?;
    let stack = words(r[8], "app-stack", 3)?;
    let app_stack = boot::Span {
        start: number(stack[1])?,
        len: number(stack[2])?,
    };
    require(
        app_stack
            == boot::Span {
                start: 0x446000,
                len: 65_536,
            },
        "exact authored application stack coordinates",
    )?;
    let qualification_contract = id(words(r[9], "qualification-contract", 2)?[1])?;
    require(
        qualification_contract.0 != [0; 32],
        "external contract identity is nonzero",
    )?;
    let limits = words(r[10], "startup-limits", 9)?;
    let caps: [u64; 8] = checked(
        limits[1..]
            .iter()
            .map(|s| number(s))
            .collect::<Result<Vec<_>>>()?
            .try_into(),
    )?;
    for (n, ceiling) in caps
        .iter()
        .zip([4096, 4096, 4097, 112, 16384, 4096, 65536, 1048576])
    {
        require(*n <= ceiling, "unchanged startup ceiling")?;
    }
    require(
        caps[0] > interpreter.len() as u64
            && caps[1] > bootstrap_dso.len() as u64
            && caps[2] >= bootstrap_dso.len() as u64 + 2
            && caps[3] == 112,
        "actual startup string/dynamic charge",
    )?;
    let mut dependencies = Vec::new();
    for row in &r[11..] {
        let f = words(row, "dependency", 3)?;
        let path = path(f[1])?;
        let identity = id(f[2])?;
        require(
            path != bootstrap_dso
                && identity.0 != [0; 32]
                && dependencies
                    .last()
                    .is_none_or(|d: &boot::Dependency| d.path < path),
            "startup sorted unique pinned dependency roster",
        )?;
        dependencies.push(boot::Dependency { path, identity });
    }
    require(
        (1..=16).contains(&dependencies.len())
            && dependencies.iter().any(|d| d.path == interpreter),
        "startup interpreter in bounded dependency roster",
    )?;
    let selection = &facts.selection;
    let state = selection.target;
    require(
        selection.hooks.len() == 1
            && selection
                .sites
                .iter()
                .all(|s| s.hook == selection.hooks[0].id),
        "startup complete selected hook join",
    )?;
    let runtime = boot::Policy {
        interpreter,
        bootstrap_dso,
        dependencies,
        app_stack,
        hook_pc: selection.hooks[0].pc,
        hook_id: selection.hooks[0].id,
        state: boot::State {
            domain: selection.bias_domain,
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
    Ok(Policy {
        program: match program {
            "checksum" => 1,
            "rle-roundtrip" => 2,
            _ => return Err("startup program".into()),
        },
        runtime,
        caps,
    })
}
fn profile(program: &str, facts: &Facts, policy: &[u8]) -> Vec<u8> {
    format!("LI2STARTUP-PRODUCER\t1\nprofile\t{PROFILE}\nruntime_profile\t{RUNTIME_PROFILE}\nplanning_profile\t{}\nprogram\t{program}\noriginal_heads\t{}\nselected_sites\t{}\nruntime_policy_sha256\t{}\nqualification_complete\tfalse\nexecution_authority\tnone\n",
        super::PROFILE, facts.heads.len(), facts.selection.sites.len(), digest(policy)).into_bytes()
}
fn bundle(original: &[u8], product: &dyn Files) -> Result<()> {
    let mut expected = format!(
        "LI2BUNDLE\t1\noriginal_sha256\t{}\nqualification_complete\tfalse\nconsumer_action\tRuntimeScan-while-gated-until-qualified\n",
        digest(original)
    );
    for name in product.names() {
        if name != "bundle-index.tsv" {
            let bytes = product.read(&name, FILE)?;
            writeln!(
                &mut expected,
                "file\t{name}\t{}\t{}",
                bytes.len(),
                digest(&bytes)
            )
            .unwrap();
        }
    }
    require(
        product.read("bundle-index.tsv", TEXT)? == expected.as_bytes(),
        "complete exact startup bundle index",
    )
}
fn reservation(policy: &Policy, facts: &Facts, joined: &ledger::Joined) -> Result<Range> {
    let headers = u64::try_from(facts.selection.limits.program_headers)
        .map_err(|_| "startup reservation header count")?;
    let table = headers
        .checked_mul(56)
        .ok_or("startup reservation table overflow")?;
    let legacy = page(add(table, 128)?)?;
    let bytes = page(add(legacy, policy.caps[4])?)?;
    let reserved = Range::new(
        facts.selection.carrier_pc,
        add(facts.selection.carrier_pc, bytes)?,
    )?;
    for plan in &joined.plans {
        for step in &plan.steps {
            require(
                !step
                    .allocation
                    .ok_or("startup allocation absent")?
                    .overlaps(reserved),
                "allocation overlaps full prospective startup reservation",
            )?;
        }
    }
    Ok(reserved)
}
pub(super) struct Artifact<'a> {
    pub program: &'a str,
    pub original: &'a [u8],
    pub facts: &'a Facts,
    pub joined: &'a ledger::Joined,
    pub metadata: &'a [u8],
    pub plan: &'a [u8],
    pub candidate: &'a [u8],
    pub ledger: &'a [u8],
    pub product: &'a dyn Files,
}
pub(super) fn join(artifact: Artifact<'_>, input: &Inputs) -> Result<Summary> {
    let Artifact {
        program,
        original,
        facts,
        joined,
        metadata,
        plan: _,
        candidate,
        ledger,
        product,
    } = artifact;
    require(
        product.read("startup-policy.txt", POLICY_BYTES)? == input.policy,
        "full independent startup policy bytes",
    )?;
    let policy = policy(program, &input.policy, original, facts, product)?;
    reservation(&policy, facts, joined)?;
    require(
        product.read("startup-profile.tsv", TEXT)? == profile(program, facts, &input.policy),
        "complete startup profile bytes",
    )?;
    bundle(original, product)?;
    candidate::join_startup(&artifact, &policy)?;
    let dependency_roster_sha256 = dependencies::join(&policy, &input.dependencies)?;
    let catalog_bytes = product.read("catalog.li2boot", FILE)?;
    let catalog = catalog::decode(&catalog_bytes)?;
    catalog::join(
        &catalog,
        catalog::Expected {
            policy: &policy,
            original,
            facts,
            joined,
            metadata,
            candidate,
            ledger,
        },
    )?;
    Ok(Summary {
        original_heads: facts.heads.len(),
        catalog_sha256: digest(&catalog_bytes),
        startup_policy_sha256: digest(&input.policy),
        dependency_roster_sha256,
    })
}
