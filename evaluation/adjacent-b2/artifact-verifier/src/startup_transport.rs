//! Explicit V2 transport. The legacy schema/argv retain their original bounds.
use super::*;
use verify::startup;
const MEMBERS: usize = 279;
const BODY: usize = 198 * TEXT + startup::POLICY_BYTES;
const FRAMING: usize = (MEMBERS + 2) * 256;
pub const BYTES: usize = BODY + FRAMING;
pub fn complete_bound(bytes: u64) -> Result<()> {
    require(
        bytes <= BYTES as u64,
        "startup complete transport framing bound",
    )
}
fn member_count(count: usize) -> Result<()> {
    require(
        (8..=MEMBERS).contains(&count),
        "startup transport member bound before allocation",
    )
}
#[derive(Default)]
struct Accounting {
    product_bytes: usize,
    product_members: usize,
    dependency_bytes: usize,
    dependency_members: usize,
    body_bytes: usize,
    framing_bytes: usize,
}
impl Accounting {
    fn product(&mut self, length: usize) -> Result<()> {
        self.product_bytes = self
            .product_bytes
            .checked_add(length)
            .ok_or("startup product overflow")?;
        require(
            self.product_bytes <= 64 * TEXT && self.product_members < 256,
            "startup unchanged product aggregate/member caps",
        )?;
        self.product_members += 1;
        Ok(())
    }
    fn dependency(&mut self, leaf: &str, length: usize) -> Result<()> {
        require(
            self.dependency_members < 16 && leaf == format!("{:04}", self.dependency_members),
            "startup contiguous dependency member ordinal",
        )?;
        self.dependency_bytes = self
            .dependency_bytes
            .checked_add(length)
            .ok_or("startup dependency overflow")?;
        require(
            self.dependency_bytes <= 128 * TEXT,
            "startup dependency aggregate cap",
        )?;
        self.dependency_members += 1;
        Ok(())
    }
    fn body(&mut self, length: usize) -> Result<()> {
        self.body_bytes = self
            .body_bytes
            .checked_add(length)
            .ok_or("startup body overflow")?;
        require(self.body_bytes <= BODY, "startup body aggregate cap")
    }
    fn framing(&mut self, length: usize) -> Result<()> {
        self.framing_bytes = self
            .framing_bytes
            .checked_add(length)
            .ok_or("startup framing overflow")?;
        require(
            self.framing_bytes <= FRAMING,
            "startup framing aggregate cap",
        )
    }
    fn line(&mut self, input: &mut impl Read) -> Result<String> {
        let row = line(input)?;
        self.framing(row.len() + 1)?;
        Ok(row)
    }
}
pub type Decoded = (String, Vec<u8>, Expected, Memory, startup::Inputs);
pub fn decode(input: &mut impl Read) -> Result<Decoded> {
    let mut accounting = Accounting::default();
    let header = accounting.line(input)?;
    let f = fields(&header, 5)?;
    require(
        f[..3] == ["LI2W01-INPUT", "2", startup::PROFILE],
        "explicit startup transport schema/profile",
    )?;
    verify::denominator(f[3])?;
    let program = f[3].to_string();
    let count = host(number(f[4])?)?;
    member_count(count)?;
    let mut original = None;
    let mut expected = BTreeMap::new();
    let mut product = BTreeMap::new();
    let mut policy = None;
    let mut dependencies = Vec::new();
    let mut prior = String::new();

    for _ in 0..count {
        let row = accounting.line(input)?;
        let f = fields(&row, 3)?;
        let name = f[0];
        let length = host(number(f[1])?)?;
        require(
            name > prior.as_str()
                && name.len() <= 160
                && f[2].len() == 64
                && verify::unhex(f[2])?.len() == 32,
            "startup ordered unique transport member/digest",
        )?;
        prior = name.into();
        let (group, leaf) = name.split_once('/').ok_or("startup transport namespace")?;
        require(
            !leaf.is_empty()
                && leaf.len() <= 128
                && leaf != "."
                && leaf != ".."
                && leaf
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            "startup transport filename",
        )?;
        let cap = match group {
            "input" => {
                require(
                    leaf == "original" && original.is_none(),
                    "startup one original",
                )?;
                TEXT
            }
            "expected" if leaf == "startup-policy.txt" => {
                require(policy.is_none(), "startup one independent policy")?;
                startup::POLICY_BYTES
            }
            "expected" => {
                require(
                    verify::EXPECTED_FILES.contains(&leaf),
                    "startup expected roster",
                )?;
                TEXT
            }
            "product" => {
                accounting.product(length)?;
                FILE
            }
            "dependency" => {
                accounting.dependency(leaf, length)?;
                FILE
            }
            _ => return Err("startup transport namespace".into()),
        };
        require(length <= cap, "startup per-file bound before allocation")?;
        accounting.body(length)?;
        let mut bytes = vec![0; length];
        checked(input.read_exact(&mut bytes))?;
        require(digest(&bytes) == f[2], "startup transport member identity")?;
        match group {
            "input" => original = Some(bytes),
            "expected" if leaf == "startup-policy.txt" => policy = Some(bytes),
            "expected" => {
                require(
                    expected.insert(leaf.into(), bytes).is_none(),
                    "startup duplicate expectation",
                )?;
            }
            "product" => {
                require(
                    product.insert(leaf.into(), bytes).is_none(),
                    "startup duplicate product",
                )?;
            }
            "dependency" => dependencies.push(bytes),
            _ => unreachable!(),
        }
    }
    require(accounting.line(input)? == "END", "startup transport end")?;
    let mut tail = [0];
    require(
        checked(input.read(&mut tail))? == 0,
        "startup transport trailing bytes",
    )?;
    require(!dependencies.is_empty(), "startup dependencies required")?;
    Ok((
        program.clone(),
        original.ok_or("startup original missing")?,
        Expected {
            program,
            files: expected,
        },
        Memory(product),
        startup::Inputs {
            policy: policy.ok_or("startup policy missing")?,
            dependencies,
        },
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn s01_old_transport_cannot_select_startup_implicitly() {
        let old = b"LI2W01-INPUT\t1\tchecksum\t6\n";
        assert_eq!(decode(&mut old.as_slice()).err(), Some("row arity".into()));
        let wrong = b"LI2W01-INPUT\t2\twrong\tchecksum\t8\n";
        assert_eq!(
            decode(&mut wrong.as_slice()).err(),
            Some("explicit startup transport schema/profile".into())
        );
    }
    #[test]
    fn s02_namespace_caps_precede_member_allocation() {
        for (name, size, why) in [
            (
                "expected/startup-policy.txt",
                startup::POLICY_BYTES + 1,
                "startup per-file bound before allocation",
            ),
            (
                "product/catalog.li2boot",
                FILE + 1,
                "startup per-file bound before allocation",
            ),
            (
                "dependency/0001",
                1,
                "startup contiguous dependency member ordinal",
            ),
            (
                "dependency/0000",
                FILE + 1,
                "startup per-file bound before allocation",
            ),
        ] {
            let input = format!(
                "LI2W01-INPUT\t2\t{}\tchecksum\t8\n{name}\t{size}\t{}\n",
                startup::PROFILE,
                "0".repeat(64)
            );
            assert_eq!(decode(&mut input.as_bytes()).err(), Some(why.into()));
        }
    }
    #[test]
    fn r3_namespace_accounting_equal_caps_and_one_more() {
        assert_eq!((TEXT, FILE), (1048576, 16777216));
        let mut a = Accounting::default();
        for _ in 0..256 {
            a.product(1).unwrap();
        }
        assert_eq!(a.product_members, 256);
        assert_eq!(
            a.product(1).err(),
            Some("startup unchanged product aggregate/member caps".into())
        );
        let mut a = Accounting::default();
        for _ in 0..4 {
            a.product(FILE).unwrap();
        }
        assert_eq!(a.product_bytes, 64 * TEXT);
        assert_eq!(
            a.product(1).err(),
            Some("startup unchanged product aggregate/member caps".into())
        );
        let mut a = Accounting::default();
        for i in 0..16 {
            a.dependency(&format!("{i:04}"), 1).unwrap();
        }
        assert_eq!(a.dependency_members, 16);
        assert_eq!(
            a.dependency("0016", 1).err(),
            Some("startup contiguous dependency member ordinal".into())
        );
        let mut a = Accounting::default();
        for i in 0..8 {
            a.dependency(&format!("{i:04}"), FILE).unwrap();
        }
        assert_eq!(a.dependency_bytes, 128 * TEXT);
        assert_eq!(
            a.dependency("0008", 1).err(),
            Some("startup dependency aggregate cap".into())
        );
    }
    #[test]
    fn r3_v2_body_framing_total_and_member_equal_caps_then_one_more() {
        assert_eq!(
            (BODY, FRAMING, BYTES, MEMBERS),
            (207683584, 71936, 207755520, 279)
        );
        let mut a = Accounting::default();
        a.body(BODY).unwrap();
        assert_eq!(a.body_bytes, BODY);
        assert_eq!(a.body(1).err(), Some("startup body aggregate cap".into()));
        let mut a = Accounting::default();
        a.framing(FRAMING).unwrap();
        assert_eq!(a.framing_bytes, FRAMING);
        assert_eq!(
            a.framing(1).err(),
            Some("startup framing aggregate cap".into())
        );
        complete_bound(BYTES as u64).unwrap();
        assert_eq!(
            complete_bound(BYTES as u64 + 1).err(),
            Some("startup complete transport framing bound".into())
        );
        member_count(MEMBERS).unwrap();
        assert_eq!(
            member_count(MEMBERS + 1).err(),
            Some("startup transport member bound before allocation".into())
        );
        let mut a = Accounting::default();
        let valid = format!("{}\n", "x".repeat(255));
        assert_eq!(a.line(&mut valid.as_bytes()).unwrap().len(), 255);
        let invalid = format!("{}\n", "x".repeat(256));
        assert_eq!(
            a.line(&mut invalid.as_bytes()).err(),
            Some("bounded transport line".into())
        );
    }
}
