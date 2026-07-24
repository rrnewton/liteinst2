//! Conservative intra-function control-flow analysis and patch-site selection.
//!
//! The PLDI 2017 backtracking rule moves a probe upstream only within its
//! current basic block. That prevents a five-byte patch from consuming bytes
//! in a successor block or the next function. This module applies that rule to
//! one caller-declared, half-open function range in a complete [`ScanResult`].
//!
//! Direct iced-x86 branch targets are treated as block leaders. Returns, jumps,
//! interrupts, exceptions, transactions, and `HLT` end blocks; calls follow the
//! original LiteInst analysis and do not end a block. Indirect and external
//! entries cannot be recovered from a linear scan, so callers must exclude
//! hidden entry points from the supplied function range.
//!
//! The current trampoline relocates one instruction, so candidates must be a
//! single instruction at least five bytes long; multi-instruction puns remain
//! unsupported and fail closed.

use std::collections::BTreeSet;
use std::fmt;

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind};

use crate::patcher::NEAR_JUMP_BYTES;
use crate::scanner::ScanResult;

/// One half-open basic-block address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BasicBlock {
    start: u64,
    end: u64,
}

impl BasicBlock {
    /// Returns the first instruction address in the block.
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the first address after the block.
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Returns whether `address` lies inside this block.
    pub const fn contains(self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
}

/// A CFG-approved location for a five-byte direct-jump patch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedPatchSite {
    requested_address: u64,
    patch_address: u64,
    block: BasicBlock,
}

impl SelectedPatchSite {
    /// Returns the instruction address originally requested by the caller.
    pub const fn requested_address(self) -> u64 {
        self.requested_address
    }

    /// Returns the upstream instruction address selected for patching.
    pub const fn patch_address(self) -> u64 {
        self.patch_address
    }

    /// Returns the containing basic block.
    pub const fn block(self) -> BasicBlock {
        self.block
    }

    /// Returns the number of bytes moved upstream from the requested site.
    pub const fn backtracked_bytes(self) -> u64 {
        self.requested_address - self.patch_address
    }

    /// Returns whether selection moved upstream.
    pub const fn was_backtracked(self) -> bool {
        self.requested_address != self.patch_address
    }

    /// Returns the first address after the five-byte patch.
    pub const fn patch_end(self) -> u64 {
        self.patch_address + NEAR_JUMP_BYTES as u64
    }
}

/// Fail-closed errors from function CFG construction or site selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CfgError {
    /// A function must contain at least one byte.
    InvalidFunctionRange {
        /// Requested function start.
        start: u64,
        /// Requested function end.
        end: u64,
    },
    /// The declared function start is not a decoded instruction head.
    FunctionStartNotInstructionHead {
        /// Requested function start.
        start: u64,
    },
    /// The declared function end cuts through an instruction or a scan gap.
    FunctionEndNotInstructionBoundary {
        /// Requested function end.
        end: u64,
    },
    /// Instruction address arithmetic overflowed.
    AddressRangeOverflow {
        /// Instruction address.
        address: u64,
        /// Decoded instruction length.
        instruction_len: usize,
    },
    /// One decoded instruction crosses the declared function end.
    InstructionCrossesFunctionBoundary {
        /// Instruction address.
        address: u64,
        /// First address after the instruction.
        instruction_end: u64,
        /// Declared function end.
        function_end: u64,
    },
    /// A direct branch enters the middle of a decoded instruction.
    DirectBranchTargetNotInstructionHead {
        /// Address of the branch instruction.
        branch_address: u64,
        /// Invalid target inside the function range.
        target_address: u64,
    },
    /// The requested address is not an instruction head in this function.
    RequestedSiteNotFound {
        /// Requested address.
        address: u64,
    },
    /// No instruction in the same block can contain a five-byte patch.
    NoSafePatchSite {
        /// Requested address.
        address: u64,
        /// Containing block start.
        block_start: u64,
        /// Containing block end.
        block_end: u64,
    },
}

impl fmt::Display for CfgError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidFunctionRange { start, end } => {
                write!(
                    formatter,
                    "function range {start:#x}..{end:#x} is empty or reversed"
                )
            }
            Self::FunctionStartNotInstructionHead { start } => {
                write!(
                    formatter,
                    "function start {start:#x} is not an instruction head"
                )
            }
            Self::FunctionEndNotInstructionBoundary { end } => {
                write!(
                    formatter,
                    "function end {end:#x} is not an instruction boundary"
                )
            }
            Self::AddressRangeOverflow {
                address,
                instruction_len,
            } => write!(
                formatter,
                "{instruction_len}-byte instruction at {address:#x} overflows the address space"
            ),
            Self::InstructionCrossesFunctionBoundary {
                address,
                instruction_end,
                function_end,
            } => write!(
                formatter,
                "instruction at {address:#x} ends at {instruction_end:#x}, past function end {function_end:#x}"
            ),
            Self::DirectBranchTargetNotInstructionHead {
                branch_address,
                target_address,
            } => write!(
                formatter,
                "direct branch at {branch_address:#x} targets non-head {target_address:#x}"
            ),
            Self::RequestedSiteNotFound { address } => {
                write!(
                    formatter,
                    "requested site {address:#x} is not in this function"
                )
            }
            Self::NoSafePatchSite {
                address,
                block_start,
                block_end,
            } => write!(
                formatter,
                "no five-byte instruction at or before {address:#x} in block {block_start:#x}..{block_end:#x}"
            ),
        }
    }
}

impl std::error::Error for CfgError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CfgInstruction {
    address: u64,
    len: usize,
}

/// Conservative CFG for one caller-declared function range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionCfg {
    function_start: u64,
    function_end: u64,
    instructions: Vec<CfgInstruction>,
    blocks: Vec<BasicBlock>,
}

impl FunctionCfg {
    /// Analyzes `function_start..function_end` within a complete linear scan.
    ///
    /// Both range endpoints must be instruction boundaries. Direct targets
    /// inside the function must also be decoded heads; ambiguous targets fail
    /// construction instead of weakening block-boundary guarantees.
    pub fn analyze(
        scan: &ScanResult,
        function_start: u64,
        function_end: u64,
    ) -> Result<Self, CfgError> {
        if function_start >= function_end {
            return Err(CfgError::InvalidFunctionRange {
                start: function_start,
                end: function_end,
            });
        }
        if scan.site(function_start).is_none() {
            return Err(CfgError::FunctionStartNotInstructionHead {
                start: function_start,
            });
        }

        let mut instructions = Vec::new();
        for scanned in scan.instructions() {
            let address = scanned.address();
            if address < function_start {
                continue;
            }
            if address >= function_end {
                break;
            }
            let instruction_end = checked_instruction_end(address, scanned.len())?;
            if instruction_end > function_end {
                return Err(CfgError::InstructionCrossesFunctionBoundary {
                    address,
                    instruction_end,
                    function_end,
                });
            }
            instructions.push(CfgInstruction {
                address,
                len: scanned.len(),
            });
        }

        let Some(last) = instructions.last() else {
            return Err(CfgError::FunctionStartNotInstructionHead {
                start: function_start,
            });
        };
        if checked_instruction_end(last.address, last.len)? != function_end {
            return Err(CfgError::FunctionEndNotInstructionBoundary { end: function_end });
        }

        let instruction_heads: BTreeSet<_> = instructions
            .iter()
            .map(|instruction| instruction.address)
            .collect();
        let mut block_starts = BTreeSet::from([function_start]);
        for scanned in scan.instructions().iter().filter(|instruction| {
            function_start <= instruction.address() && instruction.address() < function_end
        }) {
            let address = scanned.address();
            let instruction_end = checked_instruction_end(address, scanned.len())?;

            if let Some(target_address) = direct_near_branch_target(scanned.instruction()) {
                if function_start <= target_address && target_address < function_end {
                    if !instruction_heads.contains(&target_address) {
                        return Err(CfgError::DirectBranchTargetNotInstructionHead {
                            branch_address: address,
                            target_address,
                        });
                    }
                    block_starts.insert(target_address);
                }
            }
            if ends_basic_block(scanned.instruction()) && instruction_end < function_end {
                block_starts.insert(instruction_end);
            }
        }

        let starts: Vec<_> = block_starts.into_iter().collect();
        let blocks = starts
            .iter()
            .enumerate()
            .map(|(index, &start)| BasicBlock {
                start,
                end: starts.get(index + 1).copied().unwrap_or(function_end),
            })
            .collect();

        Ok(Self {
            function_start,
            function_end,
            instructions,
            blocks,
        })
    }

    /// Returns the declared function start.
    pub const fn function_start(&self) -> u64 {
        self.function_start
    }

    /// Returns the first address after the declared function.
    pub const fn function_end(&self) -> u64 {
        self.function_end
    }

    /// Returns basic blocks in address order.
    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    /// Selects the nearest upstream instruction that safely contains a jump.
    ///
    /// Search stops at the containing block's start. Failure therefore requests
    /// a trap fallback or caller policy; it never crosses a predecessor block
    /// or function boundary.
    ///
    /// A successful patch range is always wholly contained in the returned
    /// [`BasicBlock`].
    pub fn select_patch_site(&self, requested_address: u64) -> Result<SelectedPatchSite, CfgError> {
        let requested_index = self
            .instructions
            .binary_search_by_key(&requested_address, |instruction| instruction.address)
            .map_err(|_| CfgError::RequestedSiteNotFound {
                address: requested_address,
            })?;
        let block = self
            .blocks
            .iter()
            .copied()
            .find(|block| block.contains(requested_address))
            .ok_or(CfgError::RequestedSiteNotFound {
                address: requested_address,
            })?;

        for instruction in self.instructions[..=requested_index].iter().rev() {
            if instruction.address < block.start {
                break;
            }
            let patch_end = instruction
                .address
                .checked_add(NEAR_JUMP_BYTES as u64)
                .ok_or(CfgError::AddressRangeOverflow {
                    address: instruction.address,
                    instruction_len: NEAR_JUMP_BYTES,
                })?;
            if instruction.len >= NEAR_JUMP_BYTES && patch_end <= block.end {
                return Ok(SelectedPatchSite {
                    requested_address,
                    patch_address: instruction.address,
                    block,
                });
            }
        }

        Err(CfgError::NoSafePatchSite {
            address: requested_address,
            block_start: block.start,
            block_end: block.end,
        })
    }
}

fn checked_instruction_end(address: u64, instruction_len: usize) -> Result<u64, CfgError> {
    address
        .checked_add(instruction_len as u64)
        .ok_or(CfgError::AddressRangeOverflow {
            address,
            instruction_len,
        })
}

fn direct_near_branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target())
        }
        _ => None,
    }
}

fn ends_basic_block(instruction: &Instruction) -> bool {
    instruction.mnemonic() == Mnemonic::Hlt
        || matches!(
            instruction.flow_control(),
            FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::ConditionalBranch
                | FlowControl::Return
                | FlowControl::Interrupt
                | FlowControl::XbeginXabortXend
                | FlowControl::Exception
        )
}

#[cfg(test)]
mod tests {
    use super::{CfgError, FunctionCfg};
    use crate::scanner::InstructionScanner;

    #[test]
    fn backtracks_to_a_long_instruction_in_the_same_block() {
        let base = 0x10_0000_u64;
        let code = [0xB8, 1, 0, 0, 0, 0x90, 0x90, 0xC3];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let cfg = FunctionCfg::analyze(&scan, base, base + code.len() as u64).unwrap();

        let selected = cfg.select_patch_site(base + 6).unwrap();

        assert_eq!(selected.requested_address(), base + 6);
        assert_eq!(selected.patch_address(), base);
        assert_eq!(selected.backtracked_bytes(), 6);
        assert!(selected.was_backtracked());
        assert_eq!(selected.patch_end(), base + 5);
        assert!(selected.patch_end() <= selected.block().end());
        assert!(selected.block().end() <= cfg.function_end());
    }

    #[test]
    fn direct_jump_target_starts_a_new_block() {
        let base = 0x20_0000_u64;
        // mov eax, 0; jmp base+8; nop; nop; ret
        let code = [0xB8, 0, 0, 0, 0, 0xEB, 0x01, 0x90, 0x90, 0xC3];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let cfg = FunctionCfg::analyze(&scan, base, base + code.len() as u64).unwrap();

        assert_eq!(
            cfg.blocks()
                .iter()
                .map(|block| (block.start(), block.end()))
                .collect::<Vec<_>>(),
            vec![
                (base, base + 7),
                (base + 7, base + 8),
                (base + 8, base + 10)
            ]
        );
        assert!(matches!(
            cfg.select_patch_site(base + 8),
            Err(CfgError::NoSafePatchSite {
                address,
                block_start,
                block_end,
            }) if address == base + 8 && block_start == base + 8 && block_end == base + 10
        ));
    }

    #[test]
    fn backtracking_stops_at_the_current_block_start() {
        let base = 0x30_0000_u64;
        // jmp base+7; five unreachable nops; mov eax, 0; nop; ret
        let code = [
            0xEB, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 0, 0, 0, 0, 0x90, 0xC3,
        ];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let cfg = FunctionCfg::analyze(&scan, base, base + code.len() as u64).unwrap();

        let selected = cfg.select_patch_site(base + 12).unwrap();

        assert_eq!(selected.patch_address(), base + 7);
        assert_eq!(selected.block().start(), base + 7);
        assert_eq!(selected.block().end(), base + 14);
    }

    #[test]
    fn backtracking_does_not_cross_a_function_boundary() {
        let base = 0x40_0000_u64;
        // First function: mov eax, 0; ret. Second function: nop; ret.
        let code = [0xB8, 0, 0, 0, 0, 0xC3, 0x90, 0xC3];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let second = FunctionCfg::analyze(&scan, base + 6, base + 8).unwrap();

        assert!(matches!(
            second.select_patch_site(base + 6),
            Err(CfgError::NoSafePatchSite {
                address,
                block_start,
                block_end,
            }) if address == base + 6 && block_start == base + 6 && block_end == base + 8
        ));
    }

    #[test]
    fn rejects_a_direct_target_in_the_middle_of_an_instruction() {
        let base = 0x50_0000_u64;
        // mov eax, 0; jmp base+1
        let code = [0xB8, 0, 0, 0, 0, 0xEB, 0xFA];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();

        assert!(matches!(
            FunctionCfg::analyze(&scan, base, base + code.len() as u64),
            Err(CfgError::DirectBranchTargetNotInstructionHead {
                branch_address,
                target_address,
            }) if branch_address == base + 5 && target_address == base + 1
        ));
    }

    #[test]
    fn rejects_a_function_end_inside_an_instruction() {
        let base = 0x60_0000_u64;
        let code = [0xB8, 0, 0, 0, 0, 0xC3];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();

        assert!(matches!(
            FunctionCfg::analyze(&scan, base, base + 4),
            Err(CfgError::InstructionCrossesFunctionBoundary {
                address,
                instruction_end,
                function_end,
            }) if address == base && instruction_end == base + 5 && function_end == base + 4
        ));
    }

    #[test]
    fn five_byte_patch_may_end_exactly_at_a_block_boundary() {
        let base = 0x70_0000_u64;
        // jmp to an address outside this declared function.
        let code = [0xE9, 0, 0, 0, 0x7F];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let cfg = FunctionCfg::analyze(&scan, base, base + code.len() as u64).unwrap();

        let selected = cfg.select_patch_site(base).unwrap();

        assert_eq!(selected.patch_address(), base);
        assert!(!selected.was_backtracked());
        assert_eq!(selected.patch_end(), selected.block().end());
        assert_eq!(selected.block().end(), cfg.function_end());
    }

    #[test]
    fn requested_site_must_be_an_instruction_head() {
        let base = 0x80_0000_u64;
        let code = [0xB8, 0, 0, 0, 0, 0xC3];
        let scan = InstructionScanner::default().scan(&code, base).unwrap();
        let cfg = FunctionCfg::analyze(&scan, base, base + code.len() as u64).unwrap();

        assert!(matches!(
            cfg.select_patch_site(base + 1),
            Err(CfgError::RequestedSiteNotFound { address }) if address == base + 1
        ));
    }
}
