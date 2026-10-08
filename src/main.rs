use anyhow::{Context, Result};
use capability_ladder::{AuditReport, CapabilityChain, Severity, audit};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Capability-chain JSON document to audit.
    input: PathBuf,

    /// Evaluation time in RFC 3339 form. Defaults to the current UTC time.
    #[arg(long, value_parser = parse_timestamp)]
    at: Option<DateTime<Utc>>,

    /// Report format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Treat warning-only reports as failures.
    #[arg(long)]
    deny_warnings: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    match run() {
        Ok(valid) if valid => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(2),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool> {
    let cli = Cli::parse();
    let source =
        fs::read(&cli.input).with_context(|| format!("failed to read {}", cli.input.display()))?;
    let chain: CapabilityChain = serde_json::from_slice(&source).with_context(|| {
        format!(
            "failed to parse {} as capability-chain JSON",
            cli.input.display()
        )
    })?;
    let report = audit(&chain, &source, cli.at.unwrap_or_else(Utc::now));

    match cli.format {
        OutputFormat::Text => print_text(&report),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    let accepted = report.valid && (!cli.deny_warnings || report.warning_count == 0);
    Ok(accepted)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, String> {
    let timestamp = DateTime::parse_from_rfc3339(value)
        .map_err(|error| format!("invalid RFC 3339 timestamp: {error}"))?;
    Ok(timestamp.with_timezone(&Utc))
}

fn print_text(report: &AuditReport) {
    let decision = if report.valid { "PASS" } else { "FAIL" };
    println!(
        "{decision} task={} grants={} violations={} warnings={}",
        report.task_id, report.grant_count, report.violation_count, report.warning_count
    );
    println!("evaluated_at={}", report.evaluated_at.to_rfc3339());
    println!("document_sha256={}", report.document_sha256);

    for finding in &report.findings {
        let severity = match finding.severity {
            Severity::Violation => "VIOLATION",
            Severity::Warning => "WARNING",
        };
        let location = match (&finding.grant_id, finding.grant_index) {
            (Some(id), Some(index)) => format!("grant[{index}]={id}"),
            _ => "document".to_owned(),
        };
        println!(
            "{severity} {} {location} {}: {}",
            finding.code, finding.field, finding.message
        );
    }
}
