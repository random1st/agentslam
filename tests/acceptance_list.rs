//! Every acceptance criterion in the spec has a test named
//! `s5d_ac_<use_case>_<acceptance>` (non-alphanumerics → `_`, lowercase).
//! The list is derived from the spec file, not hard-coded. The spec lives in
//! the private S5D change-control tree (`.s5d/`), which the public repository
//! does not carry; there the test reports a skip instead of failing to build.

const SPEC_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/.s5d/packages/feat.agentslam-core__20261112.s5d.yaml"
);

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
fn expected_test_names(spec: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut uc: Option<String> = None;
    let mut in_acceptance = false;
    for line in spec.lines() {
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

/// Criteria implemented in a later step of the current change. Anything
/// missing that is not listed here fails the test. Must be empty at the end.
const PLANNED: &[&str] = &[
    // Next: room_decide via MCP elicitation and the service-token CLI.
    "s5d_ac_uc_agentslam_orgs_decide_elicitation",
    "s5d_ac_uc_agentslam_orgs_service_token_cli",
];

#[test]
fn every_acceptance_criterion_has_a_test() {
    let Ok(spec) = std::fs::read_to_string(SPEC_PATH) else {
        eprintln!("skipped: {SPEC_PATH} is not in this tree (public mirror)");
        return;
    };
    let expected = expected_test_names(&spec);
    assert_eq!(
        expected.len(),
        62,
        "spec acceptance count changed: {expected:?}"
    );
    for p in PLANNED {
        assert!(
            expected.iter().any(|e| e == p),
            "planned {p} is not in the spec"
        );
    }
    let sources = [
        include_str!("connect.rs"),
        include_str!("rooms.rs"),
        include_str!("messaging.rs"),
        include_str!("sessions.rs"),
        include_str!("web.rs"),
        include_str!("orgs.rs"),
        include_str!("pair.rs"),
    ]
    .concat();
    let missing: Vec<&String> = expected
        .iter()
        .filter(|n| !sources.contains(&format!("async fn {n}()")))
        .filter(|n| !PLANNED.contains(&n.as_str()))
        .collect();
    assert!(missing.is_empty(), "acceptance tests missing: {missing:?}");
    let done_but_planned: Vec<&&str> = PLANNED
        .iter()
        .filter(|p| sources.contains(&format!("async fn {p}()")))
        .collect();
    assert!(
        done_but_planned.is_empty(),
        "remove from PLANNED, now implemented: {done_but_planned:?}"
    );
}
