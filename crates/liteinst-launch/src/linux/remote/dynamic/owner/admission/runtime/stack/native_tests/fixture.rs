use super::*;
pub(super) const BASE: u64 = 0x400000;
pub(super) const CALLEE: u64 = BASE + 0x1100;
pub(super) const MARK: u64 = 0x1122_3344_5566_7788;
pub(super) const MARKER: [u8; 12] = [
    0x49, 0xbc, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xeb, 0xfe,
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InitialStackPreparation {
    Unchanged,
    SeedInitialCallWord,
}
pub(super) struct Program {
    pub(super) fixture: Fixture,
    pub(super) entry: u64,
    pub(super) call_pc: u64,
    pub(super) target: u64,
    pub(super) next: u64,
    pub(super) setup: usize,
    pub(super) encoding: [u8; 5],
    pub(super) preparation: InitialStackPreparation,
}
impl Program {
    pub(super) fn call(entry: usize, unaligned: bool) -> Self {
        let setup: &[u8] = if unaligned {
            &[
                // AND RSP,-4096; ADD RSP,4100. The upper boundary lies
                // in the fixed kernel-written argc/argv table, not below it.
                0x48, 0x81, 0xe4, 0x00, 0xf0, 0xff, 0xff, 0x48, 0x81, 0xc4, 0x04, 0x10, 0x00, 0x00,
            ]
        } else {
            &[]
        };
        let call_offset = entry + setup.len();
        let next = BASE + call_offset as u64 + 5;
        let mut encoding = [0xe8, 0, 0, 0, 0];
        encoding[1..].copy_from_slice(
            &i32::try_from(CALLEE as i64 - next as i64)
                .unwrap()
                .to_le_bytes(),
        );
        let mut start = setup.to_vec();
        start.extend_from_slice(&encoding);
        let fixture = Fixture::stack_code(
            entry,
            &[
                (entry, &start),
                (call_offset + 5, &MARKER),
                (0x1100, &[0xc3]),
                (0x1101, &MARKER),
            ],
        );
        Self {
            fixture,
            entry: BASE + entry as u64,
            call_pc: BASE + call_offset as u64,
            target: CALLEE,
            next,
            setup: usize::from(unaligned) * 2,
            encoding,
            preparation: InitialStackPreparation::Unchanged,
        }
    }
    pub(super) fn with_initial_call_word_seed(mut self) -> Self {
        assert_eq!(self.preparation, InitialStackPreparation::Unchanged);
        assert_eq!(self.setup, 0);
        assert_eq!(self.encoding[0], 0xe8);
        assert_eq!(self.next, self.call_pc.checked_add(5).unwrap());
        self.preparation = InitialStackPreparation::SeedInitialCallWord;
        self
    }
    pub(super) fn cross_page_stack(&self) -> bool {
        match self.setup {
            0 => false,
            2 => true,
            _ => panic!("unexpected positive stack fixture setup"),
        }
    }
    pub(super) fn literal(entry: usize, code: &[u8]) -> Self {
        Self {
            fixture: Fixture::stack_code(entry, &[(entry, code)]),
            entry: BASE + entry as u64,
            call_pc: BASE + entry as u64,
            target: 0,
            next: 0,
            setup: 0,
            encoding: [0; 5],
            preparation: InitialStackPreparation::Unchanged,
        }
    }
}
