//! Explicit new input identity. The two old argument paths remain unchanged.
use super::*;
use liteinst_rewrite::carrier::elf64::ObjectType;
use liteinst_rewrite::selection;

pub(super) const PROFILE: &str = "et-exec-whole-4096-v1";
pub(super) const JUMP_STACK_PROFILE: &str = "et-exec-jumps-gpr-stack64-v1";

#[derive(Debug)]
pub(super) struct Input {
    pub(super) args: Vec<String>,
    pub(super) expected: ContentId,
    pub(super) profile: Profile,
}

pub(super) fn arguments(args: &[String]) -> Result<Option<Input>> {
    if !args.get(1).is_some_and(|s| s == "--input-profile") {
        return Ok(None);
    }
    need(
        args.len() == 10
            && matches!(args[2].as_str(), PROFILE | JUMP_STACK_PROFILE)
            && args[3] == "--original-sha256"
            && args[5] == "--trusted-complete-code"
            && !args[6..].iter().any(|s| {
                (args[2] == JUMP_STACK_PROFILE
                    && (s.starts_with("--whole-program-") || s.starts_with("--short-neighbors-")))
                    || matches!(
                        s.as_str(),
                        "--input-profile"
                            | "--whole-program-4096"
                            | "--original-sha256"
                            | "--trusted-complete-code"
                            | "--policy-profile"
                    )
            }),
        "full_program_bridge --input-profile et-exec-whole-4096-v1 --original-sha256 SHA --trusted-complete-code ORIGINAL CSV CSV_SHA OUT",
    )?;
    let expected = selection::id(&args[4]).map_err(|e| e.to_string())?;
    let mut normalized = vec![args[0].clone()];
    normalized.extend_from_slice(&args[5..]);
    Ok(Some(Input {
        args: normalized,
        expected,
        profile: if args[2] == JUMP_STACK_PROFILE {
            Profile::JumpStack4096
        } else {
            Profile::Whole4096
        },
    }))
}

impl Input {
    pub(super) fn name(&self) -> &'static str {
        if self.profile == Profile::JumpStack4096 {
            JUMP_STACK_PROFILE
        } else {
            PROFILE
        }
    }

    pub(super) fn verify(&self, original: &[u8]) -> Result<()> {
        need(
            ContentId::of(original) == self.expected,
            "original first pin mismatch",
        )?;
        let elf = Elf64::parse(
            original,
            ParseLimits {
                max_program_headers: SECTION_LIMIT,
            },
        )
        .map_err(|e| format!("ELF: {e}"))?;
        need(
            elf.header().object_type == ObjectType::Executable,
            "input profile requires ET_EXEC",
        )
    }
}
