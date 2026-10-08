use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};

pub const SUPPORTED_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityChain {
    pub version: u32,
    pub task_id: String,
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub constraints: Constraints,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub purposes: Vec<String>,
    #[serde(default)]
    pub data_classes: Vec<String>,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub transmissions: Vec<String>,
    pub max_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Violation,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub grant_index: Option<usize>,
    pub grant_id: Option<String>,
    pub field: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub valid: bool,
    pub version: u32,
    pub task_id: String,
    pub evaluated_at: DateTime<Utc>,
    pub document_sha256: String,
    pub grant_count: usize,
    pub violation_count: usize,
    pub warning_count: usize,
    pub findings: Vec<Finding>,
}

/// Audit a capability chain at a caller-supplied instant.
///
/// Supplying the instant makes CI and incident replay deterministic. The SHA-256
/// covers the exact input bytes, while semantic checks operate on parsed JSON.
pub fn audit(chain: &CapabilityChain, source: &[u8], evaluated_at: DateTime<Utc>) -> AuditReport {
    let mut findings = Vec::new();

    if chain.version != SUPPORTED_VERSION {
        findings.push(global_violation(
            "UNSUPPORTED_VERSION",
            "version",
            format!(
                "document version {} is unsupported; expected {SUPPORTED_VERSION}",
                chain.version
            ),
        ));
    }

    if chain.task_id.trim().is_empty() {
        findings.push(global_violation(
            "EMPTY_TASK_ID",
            "task_id",
            "task_id must not be empty".to_owned(),
        ));
    }

    if chain.grants.is_empty() {
        findings.push(global_violation(
            "EMPTY_CHAIN",
            "grants",
            "at least one grant is required".to_owned(),
        ));
    }

    let mut ids = HashSet::new();
    for (index, grant) in chain.grants.iter().enumerate() {
        audit_grant(grant, index, evaluated_at, &mut findings);

        if !ids.insert(&grant.id) {
            findings.push(grant_violation(
                grant,
                index,
                "DUPLICATE_GRANT_ID",
                "id",
                format!("grant id {:?} is duplicated", grant.id),
            ));
        }

        if let Some(parent) = index.checked_sub(1).and_then(|i| chain.grants.get(i)) {
            audit_hop(parent, grant, index, &mut findings);
        }
    }

    findings.sort_by(|left, right| {
        left.grant_index
            .cmp(&right.grant_index)
            .then_with(|| left.code.cmp(right.code))
            .then_with(|| left.field.cmp(right.field))
            .then_with(|| left.message.cmp(&right.message))
    });

    let violation_count = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Violation)
        .count();
    let warning_count = findings.len() - violation_count;

    AuditReport {
        valid: violation_count == 0,
        version: chain.version,
        task_id: chain.task_id.clone(),
        evaluated_at,
        document_sha256: hex_sha256(source),
        grant_count: chain.grants.len(),
        violation_count,
        warning_count,
        findings,
    }
}

fn audit_grant(
    grant: &Grant,
    index: usize,
    evaluated_at: DateTime<Utc>,
    findings: &mut Vec<Finding>,
) {
    for (field, value) in [
        ("id", grant.id.as_str()),
        ("issuer", grant.issuer.as_str()),
        ("subject", grant.subject.as_str()),
    ] {
        if value.trim().is_empty() {
            findings.push(grant_violation(
                grant,
                index,
                "EMPTY_IDENTITY_FIELD",
                field,
                format!("{field} must not be empty"),
            ));
        }
    }

    if grant.expires_at <= grant.issued_at {
        findings.push(grant_violation(
            grant,
            index,
            "INVALID_TIME_WINDOW",
            "expires_at",
            "expires_at must be later than issued_at".to_owned(),
        ));
    }

    if grant.expires_at <= evaluated_at {
        findings.push(grant_violation(
            grant,
            index,
            "EXPIRED_GRANT",
            "expires_at",
            format!("grant expired at {}", grant.expires_at.to_rfc3339()),
        ));
    }

    for (field, values) in constraint_fields(&grant.constraints) {
        let mut seen = HashSet::new();
        for value in values {
            if value.trim().is_empty() {
                findings.push(grant_violation(
                    grant,
                    index,
                    "EMPTY_CONSTRAINT_VALUE",
                    field,
                    format!("{field} contains an empty value"),
                ));
            } else if !seen.insert(value) {
                findings.push(grant_warning(
                    grant,
                    index,
                    "DUPLICATE_CONSTRAINT_VALUE",
                    field,
                    format!("{field} repeats {value:?}"),
                ));
            }
        }
    }
}

fn audit_hop(parent: &Grant, child: &Grant, child_index: usize, findings: &mut Vec<Finding>) {
    if child.issuer != parent.subject {
        findings.push(grant_violation(
            child,
            child_index,
            "BROKEN_DELEGATION_LINK",
            "issuer",
            format!(
                "issuer {:?} does not match parent subject {:?}",
                child.issuer, parent.subject
            ),
        ));
    }

    if child.issued_at < parent.issued_at || child.issued_at >= parent.expires_at {
        findings.push(grant_violation(
            child,
            child_index,
            "ISSUED_OUTSIDE_PARENT_WINDOW",
            "issued_at",
            "child issued_at must fall within the parent grant window".to_owned(),
        ));
    }

    if child.expires_at > parent.expires_at {
        findings.push(grant_violation(
            child,
            child_index,
            "EXPANDED_EXPIRY",
            "expires_at",
            format!(
                "child expiry {} exceeds parent expiry {}",
                child.expires_at.to_rfc3339(),
                parent.expires_at.to_rfc3339()
            ),
        ));
    }

    let allowed_depth = parent.constraints.max_depth.saturating_sub(1);
    if parent.constraints.max_depth == 0 || child.constraints.max_depth > allowed_depth {
        findings.push(grant_violation(
            child,
            child_index,
            "DEPTH_NOT_ATTENUATED",
            "constraints.max_depth",
            format!(
                "child max_depth {} exceeds remaining parent depth {allowed_depth}",
                child.constraints.max_depth
            ),
        ));
    }

    let parent_fields = constraint_fields(&parent.constraints);
    let child_fields = constraint_fields(&child.constraints);
    for ((field, parent_values), (_, child_values)) in parent_fields.into_iter().zip(child_fields) {
        let additions = expanded_values(parent_values, child_values);
        if !additions.is_empty() {
            findings.push(grant_violation(
                child,
                child_index,
                "CONSTRAINT_EXPANSION",
                field,
                format!(
                    "child adds values not authorized by parent: {}",
                    additions.join(", ")
                ),
            ));
        }
    }
}

fn constraint_fields(constraints: &Constraints) -> [(&'static str, &[String]); 6] {
    [
        ("constraints.actions", &constraints.actions),
        ("constraints.resources", &constraints.resources),
        ("constraints.purposes", &constraints.purposes),
        ("constraints.data_classes", &constraints.data_classes),
        ("constraints.recipients", &constraints.recipients),
        ("constraints.transmissions", &constraints.transmissions),
    ]
}

fn expanded_values(parent: &[String], child: &[String]) -> Vec<String> {
    if parent.iter().any(|value| value == "*") {
        return Vec::new();
    }

    let allowed: HashSet<&str> = parent.iter().map(String::as_str).collect();
    child
        .iter()
        .filter(|value| !allowed.contains(value.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn global_violation(code: &'static str, field: &'static str, message: String) -> Finding {
    Finding {
        severity: Severity::Violation,
        code,
        grant_index: None,
        grant_id: None,
        field,
        message,
    }
}

fn grant_violation(
    grant: &Grant,
    index: usize,
    code: &'static str,
    field: &'static str,
    message: String,
) -> Finding {
    Finding {
        severity: Severity::Violation,
        code,
        grant_index: Some(index),
        grant_id: Some(grant.id.clone()),
        field,
        message,
    }
}

fn grant_warning(
    grant: &Grant,
    index: usize,
    code: &'static str,
    field: &'static str,
    message: String,
) -> Finding {
    Finding {
        severity: Severity::Warning,
        code,
        grant_index: Some(index),
        grant_id: Some(grant.id.clone()),
        field,
        message,
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn instant(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 7, hour, 0, 0)
            .single()
            .expect("valid test instant")
    }

    fn constraints(actions: &[&str], depth: u32) -> Constraints {
        Constraints {
            actions: actions.iter().map(ToString::to_string).collect(),
            resources: vec!["repo:acme/api".to_owned()],
            purposes: vec!["release".to_owned()],
            data_classes: vec!["source".to_owned()],
            recipients: vec!["github.com".to_owned()],
            transmissions: vec!["https".to_owned()],
            max_depth: depth,
        }
    }

    fn valid_chain() -> CapabilityChain {
        CapabilityChain {
            version: 1,
            task_id: "release-42".to_owned(),
            grants: vec![
                Grant {
                    id: "root".to_owned(),
                    issuer: "human:nick".to_owned(),
                    subject: "agent:planner".to_owned(),
                    issued_at: instant(20),
                    expires_at: instant(23),
                    constraints: constraints(&["read", "test", "push"], 2),
                },
                Grant {
                    id: "worker".to_owned(),
                    issuer: "agent:planner".to_owned(),
                    subject: "agent:worker".to_owned(),
                    issued_at: instant(21),
                    expires_at: instant(22),
                    constraints: constraints(&["read", "test"], 1),
                },
            ],
        }
    }

    #[test]
    fn accepts_attenuated_chain() {
        let report = audit(&valid_chain(), b"fixture", instant(21));
        assert!(report.valid);
        assert!(report.findings.is_empty());
        assert_eq!(report.grant_count, 2);
    }

    #[test]
    fn catches_action_expansion() {
        let mut chain = valid_chain();
        chain.grants[1]
            .constraints
            .actions
            .push("delete".to_owned());
        let report = audit(&chain, b"fixture", instant(21));
        assert!(!report.valid);
        assert!(
            report
                .findings
                .iter()
                .any(|f| { f.code == "CONSTRAINT_EXPANSION" && f.field == "constraints.actions" })
        );
    }

    #[test]
    fn wildcard_parent_authorizes_specific_child_values() {
        let mut chain = valid_chain();
        chain.grants[0].constraints.resources = vec!["*".to_owned()];
        chain.grants[1].constraints.resources = vec!["repo:other/worker".to_owned()];
        let report = audit(&chain, b"fixture", instant(21));
        assert!(report.valid);
    }

    #[test]
    fn wildcard_child_requires_wildcard_parent() {
        let mut chain = valid_chain();
        chain.grants[1].constraints.resources = vec!["*".to_owned()];
        let report = audit(&chain, b"fixture", instant(21));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "CONSTRAINT_EXPANSION")
        );
    }

    #[test]
    fn catches_broken_link_expiry_and_depth() {
        let mut chain = valid_chain();
        chain.grants[1].issuer = "agent:other".to_owned();
        chain.grants[1].expires_at = instant(23) + chrono::Duration::hours(1);
        chain.grants[1].constraints.max_depth = 2;
        let report = audit(&chain, b"fixture", instant(21));
        let codes: HashSet<_> = report.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains("BROKEN_DELEGATION_LINK"));
        assert!(codes.contains("EXPANDED_EXPIRY"));
        assert!(codes.contains("DEPTH_NOT_ATTENUATED"));
    }

    #[test]
    fn catches_expired_and_invalid_time_windows() {
        let mut chain = valid_chain();
        chain.grants[0].expires_at = instant(19);
        let report = audit(&chain, b"fixture", instant(21));
        let codes: HashSet<_> = report.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains("INVALID_TIME_WINDOW"));
        assert!(codes.contains("EXPIRED_GRANT"));
    }

    #[test]
    fn reports_duplicate_ids_and_values() {
        let mut chain = valid_chain();
        chain.grants[1].id = "root".to_owned();
        chain.grants[1].constraints.actions = vec!["read".to_owned(), "read".to_owned()];
        let report = audit(&chain, b"fixture", instant(21));
        assert_eq!(report.violation_count, 1);
        assert_eq!(report.warning_count, 1);
    }

    #[test]
    fn hashes_exact_source_bytes() {
        let report = audit(&valid_chain(), b"abc", instant(21));
        assert_eq!(
            report.document_sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
