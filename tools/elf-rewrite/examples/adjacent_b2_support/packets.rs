//! Bounded packet admission and closure. Shapes are selected by the caller stage.
use super::{Packet, digest, f, name, read_bound, write_new};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::path::Path;

pub(super) const BINDING_LIMIT: usize = 65536;
#[derive(Clone, Copy, Debug)]
pub(super) enum Tree {
    Single,
    Campaign,
    Artifact,
    Captures,
    Request(f::Request),
    Row(f::Request, usize, bool, usize),
    Phase(f::Request, usize, bool, usize, usize),
}
impl Tree {
    pub(super) fn children(self) -> BTreeMap<String, Self> {
        let mut out = BTreeMap::new();
        match self {
            Self::Campaign | Self::Captures => {
                for req in f::Request::ALL {
                    out.insert(
                        req.name(),
                        if matches!(self, Self::Campaign) {
                            Self::Artifact
                        } else {
                            Self::Request(req)
                        },
                    );
                }
            }
            Self::Request(req) => {
                for seed in 0..2 {
                    for zf in [false, true] {
                        for head in 0..4 {
                            out.insert(
                                format!("seed-{seed}-zf-{}-head-{head}", u8::from(zf)),
                                Self::Row(req, seed, zf, head),
                            );
                        }
                    }
                }
            }
            Self::Row(req, seed, zf, head) => {
                for phase in 0..3 {
                    out.insert(
                        format!("phase-{phase}"),
                        Self::Phase(req, seed, zf, head, phase),
                    );
                }
            }
            _ => {}
        }
        out
    }
    pub(super) fn files(self) -> Option<BTreeSet<String>> {
        let fixed: &[&str] = match self {
            Self::Single => return None,
            Self::Campaign | Self::Captures => &["campaign.tsv"],
            Self::Artifact => &[
                "request.tsv",
                "target.tsv",
                "plan.tsv",
                "ledger.tsv",
                "actual-plan.txt",
                "planner-controls.tsv",
                "upper.bin",
                "lower.bin",
                "phase-0.elf",
                "phase-1.elf",
                "phase-2.elf",
            ],
            Self::Request(_) => &["phase-0.elf", "phase-1.elf", "phase-2.elf", "result.tsv"],
            Self::Row(..) => &[],
            Self::Phase(req, seed, zf, head, phase) => {
                let mut names: BTreeSet<String> = [
                    "exec.maps",
                    "exec.map-files",
                    "exec.auxv",
                    "startup-pcs.bin",
                    "loaded.bin",
                    "terminal.maps",
                    "terminal.map-files",
                    "terminal.auxv",
                    "states.bin",
                    "journal.bin",
                    "result.tsv",
                ]
                .into_iter()
                .map(str::to_string)
                .collect();
                if phase == 0 && seed == 0 && !zf && head == 0 {
                    names.extend(["state-controls.tsv".into(), "immutable-controls.tsv".into()]);
                }
                if phase == 1 {
                    let calls = req
                        .visits(head, zf)
                        .iter()
                        .filter(|&&pc| pc == f::B || pc == f::B + 2)
                        .count();
                    for ordinal in 0..calls {
                        names.insert(format!("hook-{ordinal}.bin"));
                    }
                    if seed == 0 && zf && head == 0 {
                        names.insert("journal-controls.tsv".into());
                    }
                }
                return Some(names);
            }
        };
        Some(fixed.iter().map(|s| (*s).to_string()).collect())
    }
    fn root_nodes(self) -> usize {
        match self {
            Self::Single => 1,
            Self::Campaign => 5,
            Self::Captures => 261,
            _ => panic!("root shape required"),
        }
    }
    fn root_payload(self) -> usize {
        match self {
            Self::Single => f::LIMIT,
            Self::Campaign => 4 * f::LIMIT,
            Self::Captures => 256 * f::LIMIT,
            _ => panic!("root shape required"),
        }
    }
}

/// Each node reserves its entire 64-KiB binding allowance BEFORE any read or
/// descent. Actual binding bytes are bounded by that reservation; unused bytes
/// are not transferred to another node. Payload reservations are independent.
pub(super) struct Budget {
    pub payload: usize,
    pub nodes: usize,
    pub binding: usize,
}
impl Budget {
    pub fn for_tree(tree: Tree) -> Self {
        let nodes = tree.root_nodes();
        Self {
            payload: tree.root_payload(),
            nodes,
            binding: nodes * BINDING_LIMIT,
        }
    }
    fn node(&mut self) {
        assert!(self.nodes > 0, "global binding-node budget");
        assert!(self.binding >= BINDING_LIMIT, "global binding-byte budget");
        self.nodes -= 1;
        self.binding -= BINDING_LIMIT;
    }
    fn payload(&mut self, len: usize) {
        assert!(len <= self.payload, "global payload budget");
        self.payload -= len;
    }
}
fn shape(tree: Tree, files: &BTreeSet<String>, children: &BTreeSet<String>) {
    assert!(files.len() <= 16 && children.len() <= 16 && files.len() + children.len() <= 24);
    if let Some(expected) = tree.files() {
        assert_eq!(*files, expected, "stage file shape");
    }
    assert_eq!(
        *children,
        tree.children().keys().cloned().collect::<BTreeSet<_>>(),
        "stage child shape"
    );
}
/// Never collect an unbounded listing. Unexpected names fail at their first
/// occurrence, and the total count is charged before the next entry is retained.
fn names(directory: &Path, expected: &BTreeSet<String>) -> BTreeSet<String> {
    assert!(expected.len() <= 25);
    let mut seen = BTreeSet::new();
    for entry in std::fs::read_dir(directory).unwrap() {
        assert!(seen.len() < 25, "directory entry budget");
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        assert!(
            expected.contains(&name),
            "unlisted filesystem entry: {name}"
        );
        assert!(seen.insert(name), "duplicate filesystem entry");
    }
    assert_eq!(&seen, expected, "missing filesystem entry");
    seen
}
pub(super) fn binding(packet: &Packet, children: &BTreeMap<String, (usize, String)>) -> Vec<u8> {
    assert!(
        packet.files.len() <= 16
            && packet.children.len() <= 16
            && packet.files.len() + packet.children.len() <= 24
    );
    assert!(packet.files.values().map(Vec::len).sum::<usize>() <= f::LIMIT);
    let mut out = String::from("LI2ADJCLOSED\t2\n");
    for (n, b) in &packet.files {
        name(n);
        assert!(b.len() <= f::LIMIT);
        writeln!(out, "file\t{n}\t{}\t{}", b.len(), digest(b)).unwrap();
    }
    for (n, (len, sha)) in children {
        name(n);
        assert!(!packet.files.contains_key(n));
        writeln!(out, "packet\t{n}\t{len}\t{sha}").unwrap();
    }
    out.push_str("END\n");
    assert!(out.len() <= BINDING_LIMIT);
    out.into_bytes()
}
fn close_node(
    packet: &Packet,
    directory: &Path,
    tree: Tree,
    depth: usize,
    budget: &mut Budget,
    existing_empty: bool,
) -> String {
    assert!(depth <= 4);
    budget.node();
    shape(
        tree,
        &packet.files.keys().cloned().collect(),
        &packet.children.keys().cloned().collect(),
    );
    assert!(packet.files.values().map(Vec::len).sum::<usize>() <= f::LIMIT);
    if existing_empty {
        names(directory, &BTreeSet::new());
    } else {
        std::fs::create_dir(directory).unwrap();
    }
    let kinds = tree.children();
    let mut children = BTreeMap::new();
    for (n, p) in &packet.children {
        name(n);
        let sha = close_node(p, &directory.join(n), kinds[n], depth + 1, budget, false);
        children.insert(n.clone(), (p.total(), sha));
    }
    for (n, b) in &packet.files {
        name(n);
        assert!(b.len() <= f::LIMIT);
        budget.payload(b.len());
        write_new(&directory.join(n), b);
    }
    let complete = binding(packet, &children);
    write_new(&directory.join("binding.tsv"), &complete);
    File::open(directory).unwrap().sync_all().unwrap();
    digest(&complete)
}
pub(super) fn close_packet(packet: &Packet, directory: &Path, tree: Tree) -> String {
    let mut budget = Budget::for_tree(tree);
    let sha = close_node(packet, directory, tree, 0, &mut budget, false);
    assert_eq!(budget.nodes, 0, "complete stage node denominator");
    sha
}
pub(super) fn close_in_empty(packet: &Packet, directory: &Path) -> String {
    let mut budget = Budget::for_tree(Tree::Single);
    let sha = close_node(packet, directory, Tree::Single, 0, &mut budget, true);
    assert_eq!(budget.nodes, 0);
    sha
}
pub(super) fn read_packet(
    directory: &Path,
    expected: &str,
    tree: Tree,
    depth: usize,
    budget: &mut Budget,
) -> Packet {
    assert!(depth <= 4 && expected.len() == 64 && f::unhex(expected).len() == 32);
    budget.node(); // Before metadata, opening binding.tsv, or descent.
    assert!(std::fs::symlink_metadata(directory).unwrap().is_dir());
    let b = read_bound(&directory.join("binding.tsv"), BINDING_LIMIT);
    assert_eq!(digest(&b), expected, "closed binding identity");
    let mut lines = Vec::new();
    for line in std::str::from_utf8(&b).unwrap().lines() {
        assert!(lines.len() < 26, "binding row budget");
        lines.push(line);
    }
    assert_eq!(lines.first(), Some(&"LI2ADJCLOSED\t2"));
    assert_eq!(lines.last(), Some(&"END"));
    assert!((2..=26).contains(&lines.len()));
    let mut rows = Vec::new();
    let mut files = BTreeSet::new();
    let mut children = BTreeSet::new();
    let mut local_payload = 0_usize;
    for line in &lines[1..lines.len() - 1] {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4);
        name(fields[1]);
        assert!(
            !files.contains(fields[1]) && !children.contains(fields[1]),
            "duplicate binding name"
        );
        let len: usize = fields[2].parse().unwrap();
        assert_eq!(len.to_string(), fields[2]);
        assert_eq!(fields[3].len(), 64);
        assert_eq!(f::unhex(fields[3]).len(), 32);
        match fields[0] {
            "file" => {
                assert!(len <= f::LIMIT);
                local_payload = local_payload.checked_add(len).unwrap();
                files.insert(fields[1].to_string());
            }
            "packet" => {
                children.insert(fields[1].to_string());
            }
            _ => panic!("unknown closed member kind"),
        }
        rows.push((fields[0], fields[1], len, fields[3]));
    }
    assert!(local_payload <= f::LIMIT, "per-node payload budget");
    shape(tree, &files, &children); // Close topology before descending into any child.
    let expected_names = files
        .iter()
        .chain(&children)
        .cloned()
        .chain(["binding.tsv".into()])
        .collect();
    names(directory, &expected_names);
    let mut packet = Packet::default();
    let mut child_ids = BTreeMap::new();
    let kinds = tree.children();
    for (kind, n, len, sha) in rows {
        if kind == "file" {
            budget.payload(len); // Declared exact cap is charged before opening/reading.
            let bytes = read_bound(&directory.join(n), len);
            assert_eq!(bytes.len(), len);
            assert_eq!(digest(&bytes), sha, "member digest");
            packet.files.insert(n.into(), bytes);
        } else {
            let child = read_packet(&directory.join(n), sha, kinds[n], depth + 1, budget);
            assert_eq!(child.total(), len);
            child_ids.insert(n.into(), (len, sha.into()));
            packet.children.insert(n.into(), child);
        }
    }
    assert_eq!(binding(&packet, &child_ids), b, "canonical closed set");
    packet
}
pub(super) fn read_campaign(directory: &Path, expected: &str) -> Packet {
    let mut budget = Budget::for_tree(Tree::Campaign);
    let packet = read_packet(directory, expected, Tree::Campaign, 0, &mut budget);
    assert_eq!(budget.nodes, 0, "five-node artifact campaign");
    packet
}
fn capture_node(
    directory: &Path,
    tree: Tree,
    depth: usize,
    budget: &mut Budget,
) -> (String, usize) {
    assert!(depth <= 4);
    budget.node();
    let kinds = tree.children();
    let files = tree.files().expect("capture shape has fixed files");
    shape(tree, &files, &kinds.keys().cloned().collect());
    let expected = files.iter().chain(kinds.keys()).cloned().collect();
    names(directory, &expected);
    let mut packet = Packet::default();
    let mut child_ids = BTreeMap::new();
    let mut payload = 0_usize;
    let mut local_payload = 0_usize;
    for (n, child_tree) in kinds {
        assert!(
            std::fs::symlink_metadata(directory.join(&n))
                .unwrap()
                .is_dir()
        );
        let (sha, len) = capture_node(&directory.join(&n), child_tree, depth + 1, budget);
        payload = payload.checked_add(len).unwrap();
        child_ids.insert(n.clone(), (len, sha));
        packet.children.insert(n, Packet::default());
    }
    for n in files {
        let path = directory.join(&n);
        let stat = std::fs::symlink_metadata(&path).unwrap();
        assert!(stat.is_file() && stat.len() <= f::LIMIT as u64);
        let len = usize::try_from(stat.len()).unwrap();
        local_payload = local_payload.checked_add(len).unwrap();
        assert!(local_payload <= f::LIMIT, "per-node capture payload budget");
        budget.payload(len);
        let bytes = read_bound(&path, len);
        assert_eq!(bytes.len(), len);
        File::open(&path).unwrap().sync_all().unwrap();
        payload = payload.checked_add(len).unwrap();
        packet.files.insert(n, bytes);
    }
    let b = binding(&packet, &child_ids);
    write_new(&directory.join("binding.tsv"), &b);
    File::open(directory).unwrap().sync_all().unwrap();
    (digest(&b), payload)
}
pub(super) fn close_captures_with_budget(directory: &Path, budget: &mut Budget) -> String {
    let (sha, _) = capture_node(directory, Tree::Captures, 0, budget);
    sha
}
pub(super) fn close_captures(directory: &Path) -> String {
    let mut budget = Budget::for_tree(Tree::Captures);
    let sha = close_captures_with_budget(directory, &mut budget);
    assert_eq!(budget.nodes, 0, "261-node native capture denominator");
    sha
}
