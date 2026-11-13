//! Every acceptance criterion in the spec has a test named
//! `s5d_ac_<use_case>_<acceptance>` (non-alphanumerics → `_`, lowercase).
//! The list is derived from the spec file, not hard-coded.

const SPEC: &str = include_str!("../.s5d/packages/feat.agentslam-core__20261112.s5d.yaml");

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Line scan of the `use_cases` block: `  - id: uc.*` opens a use case,
/// `    - id: <x>` under its `acceptance:` adds a criterion.
fn expected_test_names() -> Vec<String> {
    let mut names = Vec::new();
    let mut uc: Option<String> = None;
    let mut in_acceptance = false;
    for line in SPEC.lines() {
        if let Some(id) = line.strip_prefix("  - id: ") {
            in_acceptance = false;
            uc = id.starts_with("uc.").then(|| id.trim().to_string());
            continue;
        }
        if line.starts_with("    acceptance:") {
            in_acceptance = uc.is_some();
            continue;
        }
        if line.starts_with("  invariants:") || line.starts_with("  contracts:") {
            uc = None;
            in_acceptance = false;
        }
        if in_acceptance && let (Some(u), Some(id)) = (&uc, line.strip_prefix("    - id: ")) {
            names.push(format!("s5d_ac_{}_{}", sanitize(u), sanitize(id.trim())));
        }
    }
    names
}

#[test]
fn every_acceptance_criterion_has_a_test() {
    let expected = expected_test_names();
    assert_eq!(
        expected.len(),
        35,
        "spec acceptance count changed: {expected:?}"
    );
    let sources = [
        include_str!("connect.rs"),
        include_str!("rooms.rs"),
        include_str!("messaging.rs"),
        include_str!("sessions.rs"),
        include_str!("web.rs"),
    ]
    .concat();
    let missing: Vec<&String> = expected
        .iter()
        .filter(|n| !sources.contains(&format!("async fn {n}()")))
        .collect();
    assert!(missing.is_empty(), "acceptance tests missing: {missing:?}");
}
