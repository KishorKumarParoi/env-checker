use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use env_checker_core::{purge_leaks, scan_directory, to_sarif, Environment, ScanReport, Severity};
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliEnv {
    Dev,
    Test,
    Stage,
    Prod,
}

impl From<CliEnv> for Environment {
    fn from(v: CliEnv) -> Self {
        match v {
            CliEnv::Dev => Environment::Dev,
            CliEnv::Test => Environment::Test,
            CliEnv::Stage => Environment::Stage,
            CliEnv::Prod => Environment::Prod,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "env-checker",
    version,
    about = "Blazing-fast Rust secret & .env security gate (Nexus/SonarQube style) with API-key auth and auto-purge"
)]
struct Cli {
    /// API Key for env.kishor.tech Quality Gate & Telemetry
    #[arg(long, env = "ENV_CHECKER_API_KEY", global = true)]
    api_key: Option<String>,

    /// Control plane endpoint
    #[arg(long, env = "ENV_CHECKER_ENDPOINT", default_value = "https://env.kishor.tech", global = true)]
    endpoint: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan repository or staged git files for .env files and API keys
    Scan {
        /// Path to scan
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Scan only git staged files (pre-commit mode)
        #[arg(long)]
        staged: bool,
        /// Target deployment environment
        #[arg(long, value_enum, default_value_t = CliEnv::Prod)]
        env: CliEnv,
        /// Output JSON report
        #[arg(long)]
        json: bool,
        /// Output SARIF 2.1.0 report (GitHub / SonarQube compatible)
        #[arg(long)]
        sarif: bool,
        /// Automatically purge leaked .env files and redact source secrets if detected
        #[arg(long)]
        auto_purge: bool,
    },
    /// Purge .env files from git index/disk, redact hardcoded keys, and harden .gitignore
    Purge {
        /// Repository root path
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Target only git staged files
        #[arg(long)]
        staged: bool,
        /// Delete detected .env* / key files from disk after unstaging
        #[arg(long)]
        delete: bool,
        /// Redact hardcoded API keys in source files in-place
        #[arg(long)]
        redact: bool,
        /// Rewrite git history to scrub leaked .env files (use before force-push)
        #[arg(long)]
        history: bool,
    },
    /// CI/CD Quality Gate (Nexus/SonarQube mode): verify API key, scan, report, and block on leaks
    Ci {
        /// Repository root path
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Target CI/CD environment
        #[arg(long, value_enum, default_value_t = CliEnv::Prod)]
        env: CliEnv,
        /// Auto-purge leaked .env files & redact keys before failing gate
        #[arg(long)]
        auto_purge: bool,
    },
    /// Install git pre-commit and pre-push hooks in the current repository
    InitHooks {
        /// Repository root path
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

fn verify_api_key(endpoint: &str, api_key: &str, env: Environment) -> Result<String, String> {
    let url = format!("{}/api/v1/verify", endpoint.trim_end_matches('/'));
    let resp = ureq::post(&url)
        .set("x-api-key", api_key)
        .set("Content-Type", "application/json")
        .send_json(serde_json::json!({ "environment": env.to_string() }));

    match resp {
        Ok(r) => {
            let val: serde_json::Value = r.into_json().map_err(|e| e.to_string())?;
            let valid = val.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
            if valid {
                let org = val
                    .get("project")
                    .and_then(|v| v.as_str())
                    .unwrap_or("verified-org");
                Ok(org.to_string())
            } else {
                Err("API key rejected by control plane".to_string())
            }
        }
        Err(e) => Err(format!("Control plane verification failed: {e}")),
    }
}

fn push_ci_report(endpoint: &str, api_key: &str, report: &ScanReport) {
    let url = format!("{}/api/v1/reports", endpoint.trim_end_matches('/'));
    let _ = ureq::post(&url)
        .set("x-api-key", api_key)
        .set("Content-Type", "application/json")
        .send_json(serde_json::json!(report));
}

fn print_report(report: &ScanReport) {
    println!(
        "\n{} {}  |  env: {}  |  files: {}  |  time: {}ms",
        "ENV-CHECKER".bold().cyan(),
        format!("v{}", report.version).dimmed(),
        report.environment.to_string().yellow().bold(),
        report.files_scanned,
        report.duration_ms
    );
    println!("{}", "─".repeat(72).dimmed());

    if report.findings.is_empty() {
        println!(
            "{}  Zero secrets or leaked .env files detected.",
            " QUALITY GATE: PASSED ".black().on_green().bold()
        );
        return;
    }

    for f in &report.findings {
        let sev = match f.severity {
            Severity::Critical => "CRIT".white().on_red().bold(),
            Severity::High => "HIGH".black().on_yellow().bold(),
            Severity::Medium => "MED ".black().on_cyan(),
        };
        println!(
            "{} [{}] {}:{} — {} ({})",
            sev,
            f.rule_id.cyan(),
            f.file.bold(),
            f.line,
            f.rule_name.red(),
            f.redacted_match.dimmed()
        );
        println!("     {} {}", "↳ Fix:".dimmed(), f.remediation.dimmed());
    }

    println!("{}", "─".repeat(72).dimmed());
    println!(
        "{}  {} finding(s) detected. Commit/deployment blocked.",
        " QUALITY GATE: BLOCKED ".white().on_red().bold(),
        report.findings.len()
    );
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            staged,
            env,
            json,
            sarif,
            auto_purge,
        } => {
            let target_env: Environment = env.into();
            if let Some(ref key) = cli.api_key {
                if !json && !sarif {
                    match verify_api_key(&cli.endpoint, key, target_env) {
                        Ok(org) => println!("{} Authenticated key ({})", "✓".green(), org.cyan()),
                        Err(e) => eprintln!("{} {}", "⚠".yellow(), e.yellow()),
                    }
                }
            }

            let report = scan_directory(&path, staged, target_env);

            if auto_purge && !report.findings.is_empty() {
                let summary = purge_leaks(&path, &report, false, true, false);
                if !json && !sarif {
                    println!(
                        "{} Auto-purge applied: unstaged={}, redacted={}, .gitignore={}",
                        "🧹".cyan(),
                        summary.unstaged_files.len(),
                        summary.redacted_files.len(),
                        summary.gitignore_updated
                    );
                }
            }

            if sarif {
                println!("{}", serde_json::to_string_pretty(&to_sarif(&report)).unwrap());
            } else if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                print_report(&report);
            }

            if report.gate_status == "BLOCKED" {
                process::exit(1);
            }
        }
        Commands::Purge {
            path,
            staged,
            delete,
            redact,
            history,
        } => {
            let report = scan_directory(&path, staged, Environment::Prod);
            let summary = purge_leaks(&path, &report, delete, redact, history);
            println!("{}", serde_json::to_string_pretty(&summary).unwrap());
        }
        Commands::Ci {
            path,
            env,
            auto_purge,
        } => {
            let target_env: Environment = env.into();
            let api_key = cli.api_key.unwrap_or_else(|| {
                eprintln!(
                    "{} Missing --api-key or ENV_CHECKER_API_KEY. Generate one at https://env.kishor.tech",
                    "✗".red().bold()
                );
                process::exit(2);
            });

            match verify_api_key(&cli.endpoint, &api_key, target_env) {
                Ok(org) => println!("{} CI Gate authenticated for project: {}", "✓".green(), org.cyan().bold()),
                Err(err) => {
                    eprintln!("{} {}", "✗".red().bold(), err);
                    process::exit(2);
                }
            }

            let report = scan_directory(&path, false, target_env);
            print_report(&report);
            push_ci_report(&cli.endpoint, &api_key, &report);

            if report.gate_status == "BLOCKED" {
                if auto_purge {
                    let summary = purge_leaks(&path, &report, true, true, false);
                    println!(
                        "{} CI Auto-Purge executed: removed={:?}, redacted={:?}",
                        "🧹".cyan(),
                        summary.removed_files,
                        summary.redacted_files
                    );
                }
                process::exit(1);
            }
        }
        Commands::InitHooks { path } => {
            let hooks_dir = path.join(".git").join("hooks");
            if !hooks_dir.exists() {
                eprintln!("{} Not a git repository (missing .git/hooks)", "✗".red());
                process::exit(1);
            }

            let pre_commit = hooks_dir.join("pre-commit");
            let pre_commit_script = "#!/usr/bin/env sh\n# Installed by env-checker (https://env.kishor.tech)\nset -e\nenv-checker scan --staged --env prod\n";
            fs::write(&pre_commit, pre_commit_script).expect("Failed to write pre-commit hook");

            let pre_push = hooks_dir.join("pre-push");
            let pre_push_script = "#!/usr/bin/env sh\n# Installed by env-checker (https://env.kishor.tech)\nset -e\nenv-checker scan --env prod\n";
            fs::write(&pre_push, pre_push_script).expect("Failed to write pre-push hook");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for p in [&pre_commit, &pre_push] {
                    let mut perms = fs::metadata(p).unwrap().permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(p, perms).unwrap();
                }
            }

            println!(
                "{} Installed pre-commit & pre-push hooks in {}",
                "✓".green().bold(),
                hooks_dir.display()
            );
        }
    }
}
