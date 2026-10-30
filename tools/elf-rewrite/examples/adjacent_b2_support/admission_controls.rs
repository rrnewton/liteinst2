//! Explicit filesystem controls. Every path is below a fresh owned scratch root;
//! all positive assertions run with the normal panic hook. No original input is mutated.
use super::{
    Budget, Packet, Tree, close_captures, close_packet, digest, f, name, packets, read_bound,
    read_campaign, read_packet, rejected, verify_campaign, write_new,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::Path;

fn raw_binding(p: &Packet, children: &BTreeMap<String, (usize, String)>) -> Vec<u8> {
    // Hostile fixture writer only: at most one above the production row/member
    // limits is permitted here so the REAL admission boundary can reject it.
    assert!(p.files.len() <= 17 && children.len() <= 17);
    let mut b = String::from("LI2ADJCLOSED\t2\n");
    for (n, bytes) in &p.files {
        name(n);
        assert!(bytes.len() <= f::LIMIT + 1);
        writeln!(b, "file\t{n}\t{}\t{}", bytes.len(), digest(bytes)).unwrap();
    }
    for (n, (len, sha)) in children {
        name(n);
        writeln!(b, "packet\t{n}\t{len}\t{sha}").unwrap();
    }
    b.push_str("END\n");
    assert!(b.len() <= packets::BINDING_LIMIT);
    b.into_bytes()
}
fn materialize(
    p: &Packet,
    path: &Path,
    depth: usize,
    nodes: &mut usize,
    payload: &mut usize,
    closed: bool,
) -> String {
    assert!(depth <= 4 && *nodes < 262);
    *nodes += 1;
    std::fs::create_dir(path).unwrap();
    let mut children = BTreeMap::new();
    for (n, child) in &p.children {
        name(n);
        let sha = materialize(child, &path.join(n), depth + 1, nodes, payload, closed);
        children.insert(n.clone(), (child.total(), sha));
    }
    for (n, bytes) in &p.files {
        name(n);
        *payload = payload.checked_add(bytes.len()).unwrap();
        assert!(*payload <= 4 * f::LIMIT + 1, "bounded control fixtures");
        write_new(&path.join(n), bytes);
    }
    let b = raw_binding(p, &children);
    if closed {
        write_new(&path.join("binding.tsv"), &b);
    }
    digest(&b)
}
fn write_case(p: &Packet, path: &Path, closed: bool) -> String {
    let mut nodes = 0;
    let mut payload = 0;
    materialize(p, path, 0, &mut nodes, &mut payload, closed)
}
fn replace(path: &Path, bytes: &[u8]) {
    assert!(bytes.len() <= f::LIMIT + 1);
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn read_exact(p: &Packet, directory: &Path, sha: &str, tree: Tree) {
    let mut budget = Budget::for_tree(tree);
    let admitted = read_packet(directory, sha, tree, 0, &mut budget);
    assert_eq!(budget.nodes, 0);
    assert!(
        admitted.files == p.files && admitted.children == p.children,
        "authentic filesystem round trip"
    );
}
fn skeleton(tree: Tree) -> Packet {
    let files = tree
        .files()
        .expect("fixed topology")
        .into_iter()
        .map(|n| (n, Vec::new()))
        .collect();
    let children = tree
        .children()
        .into_iter()
        .map(|(n, t)| (n, skeleton(t)))
        .collect();
    Packet { files, children }
}
fn positive(p: &Packet, tree: Tree, output: &Path, label: &str, report: &mut String) {
    let directory = output.join(label);
    let sha = close_packet(p, &directory, tree);
    read_exact(p, &directory, &sha, tree);
    writeln!(report, "filesystem-positive\t{label}").unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
pub(super) fn run(p: &Packet, output: &Path, report: &mut String) {
    // The exact authentic verified campaign must pass the actual path parser and
    // independent semantic verifier before any filesystem refusal is attempted.
    let authentic = output.join("admission-positive");
    let sha = close_packet(p, &authentic, Tree::Campaign);
    let admitted = read_campaign(&authentic, &sha);
    verify_campaign(&admitted, true);
    writeln!(report, "filesystem-positive\tauthentic-verified-campaign").unwrap();
    std::fs::remove_dir_all(authentic).unwrap();
    let first = &p.children[&f::Request::ALL[0].name()];
    let mut single = Packet::default();
    single
        .files
        .insert("target.tsv".into(), first.file("target.tsv").to_vec());
    positive(&single, Tree::Single, output, "target-one-node", report);
    let mut pair = single.clone();
    pair.files
        .insert("copy.tsv".into(), first.file("target.tsv").to_vec());
    positive(&pair, Tree::Single, output, "canonical-two-members", report);
    let mut maximum = Packet::default();
    maximum.files.insert("member.bin".into(), vec![0; f::LIMIT]);
    positive(
        &maximum,
        Tree::Single,
        output,
        "member-and-leaf-limit",
        report,
    );
    let mut sixteen = Packet::default();
    for i in 0..16 {
        sixteen.files.insert(format!("member-{i:02}"), Vec::new());
    }
    positive(&sixteen, Tree::Single, output, "sixteen-file-limit", report);
    let mut payload = skeleton(Tree::Campaign);
    for child in payload.children.values_mut() {
        child.files.insert("upper.bin".into(), vec![0; f::LIMIT]);
    }
    positive(
        &payload,
        Tree::Campaign,
        output,
        "four-MiB-payload-five-bindings",
        report,
    );

    let simple = [
        "malformed-header",
        "missing-end",
        "unknown-member-kind",
        "missing-member",
        "unlisted-file",
        "unlisted-directory",
        "duplicate-name",
        "noncanonical-order",
        "noncanonical-length",
        "noncanonical-digest",
        "escaped-name",
        "absolute-name",
        "symlink-member",
        "hardlink-member",
        "member-hash",
        "oversize-binding",
        "oversize-member",
        "leaf-payload-overflow",
        "file-count-overflow",
        "single-child-forbidden",
    ];
    for label in simple {
        let case = output.join("admission-case");
        std::fs::create_dir(&case).unwrap();
        let directory = case.join("packet");
        let mut mutant = if label == "noncanonical-order" {
            pair.clone()
        } else {
            single.clone()
        };
        match label {
            "oversize-member" => {
                mutant
                    .files
                    .insert("target.tsv".into(), vec![0; f::LIMIT + 1]);
            }
            "leaf-payload-overflow" => {
                mutant.files.insert("target.tsv".into(), vec![0; f::LIMIT]);
                mutant.files.insert("extra.bin".into(), vec![0]);
            }
            "file-count-overflow" => {
                mutant = sixteen.clone();
                mutant.files.insert("member-16".into(), Vec::new());
            }
            "single-child-forbidden" => {
                mutant.children.insert("nested".into(), single.clone());
            }
            _ => {}
        }
        let mut sha = write_case(&mutant, &directory, true);
        let binding_path = directory.join("binding.tsv");
        let mut b = String::from_utf8(read_bound(&binding_path, packets::BINDING_LIMIT)).unwrap();
        let mut binding_changed = true;
        match label {
            "malformed-header" => b = b.replacen("LI2ADJCLOSED", "INVALID", 1),
            "missing-end" => b.truncate(b.len() - 4),
            "unknown-member-kind" => b = b.replacen("file\t", "unknown\t", 1),
            "duplicate-name" => {
                let row = b.lines().nth(1).unwrap().to_string();
                b = b.replace("END\n", &(row + "\nEND\n"));
            }
            "noncanonical-order" => {
                let rows: Vec<_> = b.lines().collect();
                b = format!("{}\n{}\n{}\nEND\n", rows[0], rows[2], rows[1]);
            }
            "noncanonical-length" => {
                let len = mutant.file("target.tsv").len();
                b = b.replacen(&format!("\t{len}\t"), &format!("\t0{len}\t"), 1);
            }
            "noncanonical-digest" => {
                let id = digest(mutant.file("target.tsv"));
                let upper = format!("A{}", &id[1..]);
                b = b.replacen(&id, &upper, 1);
            }
            "escaped-name" => b = b.replacen("target.tsv", "../target.tsv", 1),
            "absolute-name" => b = b.replacen("target.tsv", "/target.tsv", 1),
            "oversize-binding" => b = "X".repeat(packets::BINDING_LIMIT + 1),
            _ => binding_changed = false,
        }
        if binding_changed {
            replace(&binding_path, b.as_bytes());
            sha = digest(b.as_bytes());
        }
        match label {
            "missing-member" => std::fs::remove_file(directory.join("target.tsv")).unwrap(),
            "unlisted-file" => write_new(&directory.join("unlisted.bin"), b"x"),
            "unlisted-directory" => std::fs::create_dir(directory.join("unlisted")).unwrap(),
            "symlink-member" => {
                std::fs::rename(directory.join("target.tsv"), case.join("saved")).unwrap();
                symlink("../saved", directory.join("target.tsv")).unwrap();
            }
            "hardlink-member" => {
                std::fs::hard_link(directory.join("target.tsv"), case.join("alias")).unwrap()
            }
            "member-hash" => {
                let mut bytes = mutant.file("target.tsv").to_vec();
                bytes[0] ^= 1;
                replace(&directory.join("target.tsv"), &bytes);
            }
            _ => {}
        }
        rejected(
            &format!("filesystem-{label}"),
            || {
                let mut budget = Budget::for_tree(Tree::Single);
                read_packet(&directory, &sha, Tree::Single, 0, &mut budget);
            },
            report,
        );
        std::fs::remove_dir_all(case).unwrap();
    }
    for label in [
        "symlink-child",
        "child-binding-hash",
        "artifact-grandchild",
        "campaign-payload-overflow",
        "global-node-budget",
        "global-binding-byte-budget",
        "global-payload-budget",
    ] {
        let case = output.join("admission-case");
        std::fs::create_dir(&case).unwrap();
        let directory = case.join("packet");
        let mut mutant = if label.contains("payload") {
            payload.clone()
        } else {
            p.clone()
        };
        if label == "artifact-grandchild" {
            mutant
                .children
                .values_mut()
                .next()
                .unwrap()
                .children
                .insert("nested".into(), single.clone());
        }
        if label == "campaign-payload-overflow" {
            mutant.files.insert("campaign.tsv".into(), vec![0]);
        }
        let sha = write_case(&mutant, &directory, true);
        let child = directory.join(f::Request::ALL[0].name());
        if label == "symlink-child" {
            std::fs::rename(&child, case.join("saved-child")).unwrap();
            symlink("../saved-child", &child).unwrap();
        }
        if label == "child-binding-hash" {
            let path = child.join("binding.tsv");
            let mut bytes = read_bound(&path, packets::BINDING_LIMIT);
            bytes[0] ^= 1;
            replace(&path, &bytes);
        }
        rejected(
            &format!("filesystem-{label}"),
            || {
                let mut budget = Budget::for_tree(Tree::Campaign);
                match label {
                    "global-node-budget" => budget.nodes -= 1,
                    "global-binding-byte-budget" => budget.binding -= 1,
                    "global-payload-budget" => budget.payload -= 1,
                    _ => {}
                }
                read_packet(&directory, &sha, Tree::Campaign, 0, &mut budget);
            },
            report,
        );
        std::fs::remove_dir_all(case).unwrap();
    }

    // A structural capture tree has authentic bindings but no native-outcome
    // meaning. It exercises the same 261-node closure/parser with zero payload.
    let capture = skeleton(Tree::Captures);
    let directory = output.join("capture-positive");
    write_case(&capture, &directory, false);
    let sha = close_captures(&directory);
    read_exact(&capture, &directory, &sha, Tree::Captures);
    writeln!(
        report,
        "filesystem-positive\tcapture-261-node-closure-and-parser"
    )
    .unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    for label in [
        "capture-node-budget",
        "capture-binding-byte-budget",
        "capture-payload-budget",
        "capture-unlisted-entry",
        "capture-leaf-payload",
        "capture-member-size",
    ] {
        let directory = output.join("capture-case");
        let mut mutant = capture.clone();
        let request = mutant.children.values_mut().next().unwrap();
        let row = request.children.values_mut().next().unwrap();
        let phase = row.children.get_mut("phase-0").unwrap();
        match label {
            "capture-payload-budget" => {
                phase.files.insert("loaded.bin".into(), vec![0]);
            }
            "capture-leaf-payload" => {
                phase.files.insert("loaded.bin".into(), vec![0; f::LIMIT]);
                phase.files.insert("states.bin".into(), vec![0]);
            }
            "capture-member-size" => {
                phase
                    .files
                    .insert("loaded.bin".into(), vec![0; f::LIMIT + 1]);
            }
            _ => {}
        }
        write_case(&mutant, &directory, false);
        if label == "capture-unlisted-entry" {
            std::fs::create_dir(directory.join("unexpected")).unwrap();
        }
        rejected(
            &format!("filesystem-{label}"),
            || {
                let mut budget = Budget::for_tree(Tree::Captures);
                match label {
                    "capture-node-budget" => budget.nodes -= 1,
                    "capture-binding-byte-budget" => budget.binding -= 1,
                    "capture-payload-budget" => budget.payload = 0,
                    _ => {}
                }
                packets::close_captures_with_budget(&directory, &mut budget);
            },
            report,
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
    writeln!(
        report,
        "filesystem-negative-count\t33\nfilesystem-positive-count\t7"
    )
    .unwrap();
}
