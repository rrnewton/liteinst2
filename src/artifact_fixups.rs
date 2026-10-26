//! Checked arithmetic for linking encoder-owned artifact fields.
//!
//! This validates a supplied field ledger without allocating executable memory.
//! It does not prove that the ledger covers every address-bearing field or that
//! a target is ready to execute; artifact qualification remains explicit.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BiasDomain(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageId(pub u64);

/// Signed planning coordinate. A carrier separately checks ELF u64 PT_LOAD
/// geometry, runtime canonical addresses, load bias and interval ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelativeAddress {
    pub domain: BiasDomain,
    pub offset: i128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImagePlacement {
    pub image: ImageId,
    pub address: RelativeAddress,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    /// Original module address or an already resolved same-module hook/data.
    Address(RelativeAddress),
    /// Exact offset in another generated image, including its end boundary.
    Image { image: ImageId, offset: u64 },
    /// Symbol identity is not a build-process function pointer.
    UnresolvedSymbol(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    /// Base is the real next instruction, not necessarily the end of the field.
    PcRelative8 {
        next: u64,
    },
    PcRelative32 {
        next: u64,
    },
    /// Signed invariant delta from a captured in-image RIP anchor.
    Delta64 {
        anchor: u64,
    },
    /// Exportable live provenance, refused by the first offline PIC carrier.
    Absolute64,
}

impl Encoding {
    pub const fn width(self) -> usize {
        match self {
            Self::PcRelative8 { .. } => 1,
            Self::PcRelative32 { .. } => 4,
            Self::Delta64 { .. } | Self::Absolute64 => 8,
        }
    }

    fn origin(self) -> Option<u64> {
        match self {
            Self::PcRelative8 { next } | Self::PcRelative32 { next } => Some(next),
            Self::Delta64 { anchor } => Some(anchor),
            Self::Absolute64 => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    LogicalPc,
    HookCall,
    OriginalBranch { original_pc: u64 },
    OriginalRipOperand { original_pc: u64 },
    Return,
    OriginalAbsoluteOperand { original_pc: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fixup {
    pub offset: u64,
    pub encoding: Encoding,
    pub target: Target,
    pub role: Role,
    /// Encoder-produced original bytes at exactly this field; never a byte scan.
    pub expected: Vec<u8>,
}

impl Fixup {
    /// Move a fixed-size fragment to its final containing-image offset. Its
    /// target image identities stay intact; local RIP bases move with the field.
    pub fn rebased(&self, by: u64) -> Result<Self, Error> {
        let add = |value: u64| value.checked_add(by).ok_or(Error::ArithmeticOverflow);
        let encoding = match self.encoding {
            Encoding::PcRelative8 { next } => Encoding::PcRelative8 { next: add(next)? },
            Encoding::PcRelative32 { next } => Encoding::PcRelative32 { next: add(next)? },
            Encoding::Delta64 { anchor } => Encoding::Delta64 {
                anchor: add(anchor)?,
            },
            Encoding::Absolute64 => Encoding::Absolute64,
        };
        Ok(Self {
            offset: add(self.offset)?,
            encoding,
            ..self.clone()
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    ArithmeticOverflow,
    DuplicateImage(ImageId),
    UnknownImage(ImageId),
    ImageLengthMismatch {
        declared: u64,
        actual: u64,
    },
    ImageOffsetOutOfBounds {
        image: ImageId,
        offset: u64,
        len: u64,
    },
    FieldOutOfBounds {
        offset: u64,
        width: usize,
        len: u64,
    },
    OriginOutOfBounds {
        origin: u64,
        len: u64,
    },
    ExpectedWidth {
        offset: u64,
        expected: usize,
        required: usize,
    },
    TemplateMismatch {
        offset: u64,
    },
    OverlappingFields {
        earlier: u64,
        later: u64,
    },
    CrossBiasDomain {
        source: BiasDomain,
        target: BiasDomain,
    },
    UnresolvedSymbol(u64),
    RequiresRuntimeAbsoluteFixup {
        offset: u64,
        role: Role,
    },
    DisplacementOutOfRange {
        offset: u64,
        width: usize,
        displacement: i128,
    },
}

fn placement(placements: &[ImagePlacement], image: ImageId) -> Result<ImagePlacement, Error> {
    placements
        .iter()
        .copied()
        .find(|item| item.image == image)
        .ok_or(Error::UnknownImage(image))
}

fn target_address(placements: &[ImagePlacement], target: Target) -> Result<RelativeAddress, Error> {
    match target {
        Target::Address(value) => Ok(value),
        Target::UnresolvedSymbol(symbol) => Err(Error::UnresolvedSymbol(symbol)),
        Target::Image { image, offset } => {
            let target = placement(placements, image)?;
            if offset > target.len {
                return Err(Error::ImageOffsetOutOfBounds {
                    image,
                    offset,
                    len: target.len,
                });
            }
            Ok(RelativeAddress {
                domain: target.address.domain,
                offset: target
                    .address
                    .offset
                    .checked_add(i128::from(offset))
                    .ok_or(Error::ArithmeticOverflow)?,
            })
        }
    }
}

/// Link into a private output vector after validating every supplied field.
/// No partially linked image escapes on failure. Inputs are never mutated.
///
/// Same-domain subtraction proves load-bias cancellation algebraically; testing
/// two biases is additional evidence, not the proof. This routine deliberately
/// does not attach a completeness/PIC certificate to caller-supplied ledgers.
pub fn link_bias_invariant(
    image: ImageId,
    template: &[u8],
    fields: &[Fixup],
    placements: &[ImagePlacement],
) -> Result<Vec<u8>, Error> {
    for (index, item) in placements.iter().enumerate() {
        if placements[..index]
            .iter()
            .any(|prior| prior.image == item.image)
        {
            return Err(Error::DuplicateImage(item.image));
        }
        item.address
            .offset
            .checked_add(i128::from(item.len))
            .ok_or(Error::ArithmeticOverflow)?;
    }
    let current = placement(placements, image)?;
    let len = u64::try_from(template.len()).map_err(|_| Error::ArithmeticOverflow)?;
    if current.len != len {
        return Err(Error::ImageLengthMismatch {
            declared: current.len,
            actual: len,
        });
    }
    let mut ordered: Vec<_> = fields.iter().collect();
    ordered.sort_by_key(|field| field.offset);
    let mut previous: Option<(u64, u64)> = None;
    let mut writes = Vec::with_capacity(fields.len());
    for field in ordered {
        let width = field.encoding.width();
        let end = field
            .offset
            .checked_add(width as u64)
            .ok_or(Error::ArithmeticOverflow)?;
        if end > len {
            return Err(Error::FieldOutOfBounds {
                offset: field.offset,
                width,
                len,
            });
        }
        if let Some((earlier, previous_end)) = previous {
            if field.offset < previous_end {
                return Err(Error::OverlappingFields {
                    earlier,
                    later: field.offset,
                });
            }
        }
        previous = Some((field.offset, end));
        if field.expected.len() != width {
            return Err(Error::ExpectedWidth {
                offset: field.offset,
                expected: field.expected.len(),
                required: width,
            });
        }
        // Conversion is safe after end <= actual template.len().
        let start = field.offset as usize;
        if template[start..end as usize] != field.expected {
            return Err(Error::TemplateMismatch {
                offset: field.offset,
            });
        }
        let Some(origin) = field.encoding.origin() else {
            return Err(Error::RequiresRuntimeAbsoluteFixup {
                offset: field.offset,
                role: field.role,
            });
        };
        if origin > len {
            return Err(Error::OriginOutOfBounds { origin, len });
        }
        let target = target_address(placements, field.target)?;
        if target.domain != current.address.domain {
            return Err(Error::CrossBiasDomain {
                source: current.address.domain,
                target: target.domain,
            });
        }
        let base = current
            .address
            .offset
            .checked_add(i128::from(origin))
            .ok_or(Error::ArithmeticOverflow)?;
        let displacement = target
            .offset
            .checked_sub(base)
            .ok_or(Error::ArithmeticOverflow)?;
        let range_error = || Error::DisplacementOutOfRange {
            offset: field.offset,
            width,
            displacement,
        };
        let bytes = match field.encoding {
            Encoding::PcRelative8 { .. } => i8::try_from(displacement)
                .map_err(|_| range_error())?
                .to_le_bytes()
                .to_vec(),
            Encoding::PcRelative32 { .. } => i32::try_from(displacement)
                .map_err(|_| range_error())?
                .to_le_bytes()
                .to_vec(),
            Encoding::Delta64 { .. } => i64::try_from(displacement)
                .map_err(|_| range_error())?
                .to_le_bytes()
                .to_vec(),
            Encoding::Absolute64 => unreachable!(),
        };
        writes.push((start, bytes));
    }
    let mut linked = template.to_vec();
    for (start, bytes) in writes {
        linked[start..start + bytes.len()].copy_from_slice(&bytes);
    }
    Ok(linked)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: BiasDomain = BiasDomain(1);
    const IMAGE: ImageId = ImageId(1);

    fn address(offset: i128) -> Target {
        Target::Address(RelativeAddress {
            domain: DOMAIN,
            offset,
        })
    }

    fn field(encoding: Encoding, target: Target) -> Fixup {
        Fixup {
            offset: 1,
            expected: vec![0; encoding.width()],
            encoding,
            target,
            role: Role::Return,
        }
    }

    fn link(bytes: &[u8], fields: &[Fixup]) -> Result<Vec<u8>, Error> {
        link_bias_invariant(
            IMAGE,
            bytes,
            fields,
            &[ImagePlacement {
                image: IMAGE,
                address: RelativeAddress {
                    domain: DOMAIN,
                    offset: 0x1000,
                },
                len: bytes.len() as u64,
            }],
        )
    }

    #[test]
    fn exact_rel8_and_rel32_endpoints_do_not_widen() {
        for (encoding, next, low, high) in [
            (
                Encoding::PcRelative8 { next: 2 },
                2,
                i128::from(i8::MIN),
                i128::from(i8::MAX),
            ),
            (
                Encoding::PcRelative32 { next: 5 },
                5,
                i128::from(i32::MIN),
                i128::from(i32::MAX),
            ),
        ] {
            let bytes = vec![0; 1 + encoding.width()];
            for delta in [low, high] {
                let linked =
                    link(&bytes, &[field(encoding, address(0x1000 + next + delta))]).unwrap();
                let expected = if encoding.width() == 1 {
                    (delta as i8).to_le_bytes().to_vec()
                } else {
                    (delta as i32).to_le_bytes().to_vec()
                };
                assert_eq!(&linked[1..], expected);
            }
            for delta in [low - 1, high + 1] {
                assert!(
                    matches!(link(&bytes, &[field(encoding, address(0x1000 + next + delta))]), Err(Error::DisplacementOutOfRange { displacement, .. }) if displacement == delta)
                );
            }
        }
    }

    #[test]
    fn rip_operand_base_includes_a_trailing_immediate() {
        // ADD dword ptr [RIP+disp32], 1: next-IP is 7, field ends at 6.
        let bytes = [0x83, 0x05, 0, 0, 0, 0, 1];
        let fixup = Fixup {
            offset: 2,
            encoding: Encoding::PcRelative32 { next: 7 },
            target: address(0x2000),
            role: Role::OriginalRipOperand {
                original_pc: 0x3000,
            },
            expected: vec![0; 4],
        };
        let linked = link(&bytes, &[fixup]).unwrap();
        assert_eq!(i32::from_le_bytes(linked[2..6].try_into().unwrap()), 0xff9);
        assert_eq!(linked[6], 1);
    }

    #[test]
    fn logical_delta64_keeps_two_biases_exact_without_an_absolute_slot() {
        let bytes = [0; 9];
        let linked = link(
            &bytes,
            &[field(
                Encoding::Delta64 { anchor: 0 },
                address(0x1_0000_4000),
            )],
        )
        .unwrap();
        let delta = i64::from_le_bytes(linked[1..9].try_into().unwrap());
        assert_eq!(delta, 0x1_0000_3000);
        for bias in [0x400000_i128, 0x7000_0000_0000] {
            assert_eq!(bias + 0x1000 + i128::from(delta), bias + 0x1_0000_4000);
        }
    }

    #[test]
    fn fragments_rebase_both_field_and_rip_origin() {
        let original = field(Encoding::PcRelative32 { next: 5 }, address(0x2000));
        let moved = original.rebased(10).unwrap();
        assert_eq!(moved.offset, 11);
        assert_eq!(moved.encoding, Encoding::PcRelative32 { next: 15 });
        let linked = link(&[0; 15], &[moved]).unwrap();
        assert_eq!(
            i32::from_le_bytes(linked[11..15].try_into().unwrap()),
            0xff1
        );
        assert_eq!(original.offset, 1);
        assert_eq!(original.rebased(u64::MAX), Err(Error::ArithmeticOverflow));
    }

    #[test]
    fn field_bounds_templates_overlap_and_origins_are_checked() {
        let good = field(Encoding::PcRelative32 { next: 5 }, address(0x2000));
        assert!(matches!(
            link(&[0; 4], std::slice::from_ref(&good)),
            Err(Error::FieldOutOfBounds { .. })
        ));
        assert!(matches!(
            link(&[1; 5], std::slice::from_ref(&good)),
            Err(Error::TemplateMismatch { offset: 1 })
        ));
        assert_eq!(
            link(&[0; 5], &[good.clone(), good.clone()]),
            Err(Error::OverlappingFields {
                earlier: 1,
                later: 1
            })
        );
        let mut invalid = good.clone();
        invalid.expected.pop();
        assert!(matches!(
            link(&[0; 5], &[invalid]),
            Err(Error::ExpectedWidth { .. })
        ));
        let mut invalid = good;
        invalid.encoding = Encoding::PcRelative32 { next: 6 };
        assert_eq!(
            link(&[0; 5], &[invalid]),
            Err(Error::OriginOutOfBounds { origin: 6, len: 5 })
        );
    }

    #[test]
    fn equal_numeric_bias_does_not_authorize_cross_module_binding() {
        let target = Target::Address(RelativeAddress {
            domain: BiasDomain(2),
            offset: 0x2000,
        });
        assert_eq!(
            link(
                &[0; 5],
                &[field(Encoding::PcRelative32 { next: 5 }, target)]
            ),
            Err(Error::CrossBiasDomain {
                source: DOMAIN,
                target: BiasDomain(2)
            })
        );
        assert_eq!(
            link(
                &[0; 5],
                &[field(
                    Encoding::PcRelative32 { next: 5 },
                    Target::UnresolvedSymbol(7)
                )]
            ),
            Err(Error::UnresolvedSymbol(7))
        );
        assert_eq!(
            link(&[0; 9], &[field(Encoding::Absolute64, address(0x2000))]),
            Err(Error::RequiresRuntimeAbsoluteFixup {
                offset: 1,
                role: Role::Return
            })
        );
    }

    #[test]
    fn exact_image_targets_use_their_own_placement_and_identity() {
        let first = ImagePlacement {
            image: IMAGE,
            address: RelativeAddress {
                domain: DOMAIN,
                offset: -0x1000,
            },
            len: 5,
        };
        let second = ImagePlacement {
            image: ImageId(2),
            address: RelativeAddress {
                domain: DOMAIN,
                offset: 0x3000,
            },
            len: 8,
        };
        let target = |offset| {
            field(
                Encoding::PcRelative32 { next: 5 },
                Target::Image {
                    image: second.image,
                    offset,
                },
            )
        };
        let linked = link_bias_invariant(IMAGE, &[0; 5], &[target(8)], &[first, second]).unwrap();
        assert_eq!(i32::from_le_bytes(linked[1..5].try_into().unwrap()), 0x4003);
        assert_eq!(
            link_bias_invariant(IMAGE, &[0; 5], &[target(9)], &[first, second]),
            Err(Error::ImageOffsetOutOfBounds {
                image: second.image,
                offset: 9,
                len: 8
            })
        );
        assert_eq!(
            link_bias_invariant(IMAGE, &[0; 5], &[target(0)], &[first]),
            Err(Error::UnknownImage(second.image))
        );
        assert_eq!(
            link_bias_invariant(IMAGE, &[0; 5], &[], &[first, first]),
            Err(Error::DuplicateImage(IMAGE))
        );
        assert_eq!(
            link_bias_invariant(IMAGE, &[0; 4], &[], &[first]),
            Err(Error::ImageLengthMismatch {
                declared: 5,
                actual: 4
            })
        );
    }

    #[test]
    fn later_failure_leaves_original_template_unchanged() {
        let bytes = [0; 10];
        let original = bytes;
        let first = field(Encoding::PcRelative32 { next: 5 }, address(0x2000));
        let second = first.rebased(5).unwrap();
        let mut bad = second;
        bad.target = Target::UnresolvedSymbol(99);
        assert_eq!(
            link(&bytes, &[first, bad]),
            Err(Error::UnresolvedSymbol(99))
        );
        assert_eq!(bytes, original);
    }
}
