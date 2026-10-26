//! Fixed-size artifact fragments inserted after application flags/GPR save.
//!
//! These fragments are not complete trampolines or execution admission. Full
//! frame save/restore remains the shared emitter's responsibility; local fixup
//! offsets are rebased after final coalesced layout. Target CPU, loader, ABI and
//! the remaining artifact requirements must be qualified separately.

use crate::artifact_fixups::{Encoding, Fixup, Role, Target};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fragment {
    pub bytes: Vec<u8>,
    pub fields: Vec<Fixup>,
}

/// LEA RAX,[RIP+0]; MOV RDX,delta64; ADD RAX,RDX; PUSH RAX.
/// RAX/RDX and flags were saved already. The 64-bit immediate is an invariant
/// target-minus-anchor delta, not an absolute runtime pointer. This avoids a
/// second rel32-reach assumption from late instrumentation back to its source.
pub fn logical_pc(target: Target) -> Fragment {
    let mut bytes = vec![0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x48, 0xba];
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&[0x48, 0x01, 0xd0, 0x50]);
    Fragment {
        bytes,
        fields: vec![Fixup {
            offset: 9,
            encoding: Encoding::Delta64 { anchor: 7 },
            target,
            role: Role::LogicalPc,
            expected: vec![0; 8],
        }],
    }
}

/// Direct callback call, after full state save and RDI=context setup.
/// Carrier hook target must be same-module, initialized and ABI-qualified.
pub fn hook_call(target: Target) -> Fragment {
    transfer(0xe8, target, Role::HookCall)
}

/// Register-preserving direct rejoin, after full state restore.
/// A far target returns a typed link refusal; no absolute fallback is hidden.
pub fn return_jump(target: Target) -> Fragment {
    transfer(0xe9, target, Role::Return)
}

fn transfer(opcode: u8, target: Target, role: Role) -> Fragment {
    Fragment {
        bytes: vec![opcode, 0, 0, 0, 0],
        fields: vec![Fixup {
            offset: 1,
            encoding: Encoding::PcRelative32 { next: 5 },
            target,
            role,
            expected: vec![0; 4],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_fixups::{
        BiasDomain, ImageId, ImagePlacement, RelativeAddress, link_bias_invariant,
    };

    #[test]
    fn logical_pc_has_fixed_offsets_and_same_value_at_two_biases() {
        let domain = BiasDomain(1);
        let target = Target::Address(RelativeAddress {
            domain,
            offset: 0x4000,
        });
        let fragment = logical_pc(target);
        assert_eq!(fragment.bytes.len(), 21);
        assert_eq!(
            &fragment.bytes[..9],
            &[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x48, 0xba]
        );
        assert_eq!(&fragment.bytes[17..], &[0x48, 0x01, 0xd0, 0x50]);
        let image = ImageId(1);
        let linked = link_bias_invariant(
            image,
            &fragment.bytes,
            &fragment.fields,
            &[ImagePlacement {
                image,
                address: RelativeAddress {
                    domain,
                    offset: 0x8000,
                },
                len: 21,
            }],
        )
        .unwrap();
        let delta = i64::from_le_bytes(linked[9..17].try_into().unwrap());
        assert_eq!(delta, -0x4007);
        for bias in [0x400000_i128, 0x7000_0000_0000] {
            assert_eq!(bias + 0x8007 + i128::from(delta), bias + 0x4000);
        }
    }

    #[test]
    fn callback_and_rejoin_are_distinct_direct_transfer_roles() {
        let domain = BiasDomain(1);
        let target = Target::Address(RelativeAddress {
            domain,
            offset: 0x4000,
        });
        let call = hook_call(target);
        let jump = return_jump(target);
        assert_eq!(call.bytes, vec![0xe8, 0, 0, 0, 0]);
        assert_eq!(jump.bytes, vec![0xe9, 0, 0, 0, 0]);
        assert_eq!(call.fields[0].role, Role::HookCall);
        assert_eq!(jump.fields[0].role, Role::Return);
        assert_eq!(call.fields[0].encoding, Encoding::PcRelative32 { next: 5 });
        assert_eq!(jump.fields[0].encoding, Encoding::PcRelative32 { next: 5 });
    }
}
