use ignore::WalkBuilder;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Dev,
    Test,
    Stage,
    Prod,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Environment::Dev => write!(f, "dev"),
            Environment::Test => write!(f, "test"),
            Environment::Stage => write!(f, "stage"),
            Environment::Prod => write!(f, "prod"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub redacted_match: String,
    pub is_env_file: bool,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: String,
    pub version: String,
    pub environment: Environment,
    pub gate_status: String, // "PASSED" | "BLOCKED"
    pub files_scanned: usize,
    pub duration_ms: u128,
    pub findings: Vec<Finding>,
    pub env_files_detected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeSummary {
    pub unstaged_files: Vec<String>,
    pub removed_files: Vec<String>,
    pub redacted_files: Vec<String>,
    pub gitignore_updated: bool,
    pub history_purged: bool,
}

struct SecretRule {
    id: &'static str,
    name: &'static str,
    severity: Severity,
    regex: Regex,
}

static SECRET_RULES: Lazy<Vec<SecretRule>> = Lazy::new(|| {
    vec![
        SecretRule {
            id: "EC-001",
            name: "OpenAI API Key",
            severity: Severity::Critical,
            regex: Regex::new(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b").unwrap(),
        },
        SecretRule {
            id: "EC-002",
            name: "Anthropic API Key",
            severity: Severity::Critical,
            regex: Regex::new(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{24,}\b").unwrap(),
        },
        SecretRule {
            id: "EC-003",
            name: "AWS Access Key ID",
            severity: Severity::Critical,
            regex: Regex::new(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b").unwrap(),
        },
        SecretRule {
            id: "EC-004",
            name: "AWS Secret Access Key",
            severity: Severity::Critical,
            regex: Regex::new(r#"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#).unwrap(),
        },
        SecretRule {
            id: "EC-005",
            name: "GitHub Personal Access Token",
            severity: Severity::Critical,
            regex: Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b").unwrap(),
        },
        SecretRule {
            id: "EC-006",
            name: "Google / Gemini API Key",
            severity: Severity::Critical,
            regex: Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(),
        },
        SecretRule {
            id: "EC-007",
            name: "Stripe Live/Restricted Key",
            severity: Severity::Critical,
            regex: Regex::new(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b").unwrap(),
        },
        SecretRule {
            id: "EC-008",
            name: "Slack Bot/User Token",
            severity: Severity::High,
            regex: Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b").unwrap(),
        },
        SecretRule {
            id: "EC-009",
            name: "HuggingFace Access Token",
            severity: Severity::High,
            regex: Regex::new(r"\bhf_[A-Za-z0-9]{24,}\b").unwrap(),
        },
        SecretRule {
            id: "EC-010",
            name: "Groq API Key",
            severity: Severity::Critical,
            regex: Regex::new(r"\bgsk_[A-Za-z0-9]{40,}\b").unwrap(),
        },
        SecretRule {
            id: "EC-011",
            name: "Private Key Block (PEM)",
            severity: Severity::Critical,
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----").unwrap(),
        },
        SecretRule {
            id: "EC-012",
            name: "Database URL with Embedded Credentials",
            severity: Severity::Critical,
            regex: Regex::new(r#"(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s'"]+:[^@\s'"]{6,}@[^\s'"]+"#).unwrap(),
        },
        SecretRule {
            id: "EC-013",
            name: "Bearer / JWT Token",
            severity: Severity::High,
            regex: Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b").unwrap(),
        },
        SecretRule {
            id: "EC-014",
            name: "Generic API Key / Secret Assignment",
            severity: Severity::High,
            regex: Regex::new(r#"(?i)\b(?:api_key|apikey|secret_key|client_secret|access_token|auth_token|private_key|db_password|database_password|supabase_service_role_key|vercel_token)\s*[:=]\s*(?:['"]([A-Za-z0-9_\-./+=]{16,})['"]|([A-Za-z0-9_\-/+=]{16,})(?:\s|$|#))"#).unwrap(),
        },
    ]
});

/// Compute Shannon entropy (bits per character) to distinguish real secrets from placeholders.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    let len = s.chars().count() as f64;
    for ch in s.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    counts.values().fold(0.0, |acc, &c| {
        let p = (c as f64) / len;
        acc - p * p.log2()
    })
}

fn is_placeholder(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    lower.contains("example")
        || lower.contains("your_")
        || lower.contains("your-")
        || lower.contains("changeme")
        || lower.contains("placeholder")
        || lower.contains("dummy")
        || lower.contains("redacted_by_env_checker")
        || lower.contains("xxxx")
        || lower.starts_with("${")
        || lower.starts_with("<")
        || val.chars().all(|c| c == '*' || c == 'x' || c == 'X')
}

pub fn redact_secret(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 8 {
        return "****".to_string();
    }
    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{prefix}...{suffix}")
}

pub fn is_sensitive_env_filename(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };

    if name == ".env.example" || name == ".env.sample" || name == ".env.template" {
        return false;
    }

    name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || name == "id_rsa"
        || name == "id_ed25519"
}

fn is_binary_or_ignored(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    if path_str.contains("/.git/")
        || path_str.contains("\\.git\\")
        || path_str.contains("/target/")
        || path_str.contains("/node_modules/")
        || path_str.contains("/.env-checker-quarantine/")
    {
        return true;
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let lower = ext.to_ascii_lowercase();
        return matches!(
            lower.as_str(),
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "ico"
                | "pdf"
                | "zip"
                | "tar"
                | "gz"
                | "pt"
                | "pth"
                | "safetensors"
                | "onnx"
                | "bin"
                | "exe"
                | "dll"
                | "so"
                | "dylib"
                | "woff"
                | "woff2"
                | "mp4"
                | "mov"
                | "lock"
        );
    }
    false
}

pub fn scan_content(file_label: &str, content: &str, is_env_file: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        for rule in SECRET_RULES.iter() {
            if let Some(caps) = rule.regex.captures(line) {
                let matched = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .or_else(|| caps.get(0))
                    .map(|m| m.as_str())
                    .unwrap_or("");

                if matched.is_empty() || is_placeholder(matched) {
                    continue;
                }

                // For generic assignment rule, enforce Shannon entropy threshold to cut false positives
                if rule.id == "EC-014" && shannon_entropy(matched) < 3.4 {
                    continue;
                }

                findings.push(Finding {
                    rule_id: rule.id.to_string(),
                    rule_name: rule.name.to_string(),
                    severity: rule.severity,
                    file: file_label.to_string(),
                    line: idx + 1,
                    redacted_match: redact_secret(matched),
                    is_env_file,
                    remediation: if is_env_file {
                        "Unstage and purge .env file; move secrets to CI/CD vault or .env.example".to_string()
                    } else {
                        "Remove hardcoded secret, inject via env var, and run `env-checker purge --redact`".to_string()
                    },
                });
                break; // One primary finding per line
            }
        }
    }
    findings
}

pub fn get_staged_files(root: &Path) -> Vec<PathBuf> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .output();

    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| root.join(l.trim()))
            .collect(),
        _ => Vec::new(),
    }
}

pub fn scan_directory(root: &Path, staged_only: bool, env: Environment) -> ScanReport {
    let start = Instant::now();

    let files: Vec<PathBuf> = if staged_only {
        get_staged_files(root)
    } else {
        WalkBuilder::new(root)
            .hidden(false) // Must inspect .env* dotfiles!
            .git_ignore(true)
            .filter_entry(|entry| {
                let p = entry.path();
                let name = entry.file_name().to_string_lossy();
                name != ".git"
                    && name != "node_modules"
                    && name != "target"
                    && name != ".env-checker-quarantine"
                    && !p.ends_with(".git")
            })
            .build()
            .filter_map(|res| res.ok())
            .filter(|e| e.file_type().map(|ft| ft.is_file()).unwrap_or(false))
            .map(|e| e.into_path())
            .collect()
    };

    let candidate_files: Vec<PathBuf> = files
        .into_iter()
        .filter(|p| !is_binary_or_ignored(p))
        .collect();

    let files_scanned = candidate_files.len();

    let results: Vec<(Option<String>, Vec<Finding>)> = candidate_files
        .par_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            let is_env = is_sensitive_env_filename(path);

            let mut file_findings = Vec::new();
            if let Ok(content) = fs::read_to_string(path) {
                file_findings = scan_content(&rel, &content, is_env);
            }

            // Flag committed/staged .env files even if empty or low-entropy
            if is_env && file_findings.is_empty() && staged_only {
                file_findings.push(Finding {
                    rule_id: "EC-ENV".to_string(),
                    rule_name: "Sensitive .env / Key File Staged for Commit".to_string(),
                    severity: Severity::Critical,
                    file: rel.clone(),
                    line: 1,
                    redacted_match: "<sensitive-file>".to_string(),
                    is_env_file: true,
                    remediation: "Run `env-checker purge --staged` to unstage and protect .gitignore".to_string(),
                });
            }

            let env_hit = if is_env { Some(rel) } else { None };
            (env_hit, file_findings)
        })
        .collect();

    let mut findings = Vec::new();
    let mut env_files_detected = Vec::new();
    for (env_hit, mut f) in results {
        if let Some(e) = env_hit {
            env_files_detected.push(e);
        }
        findings.append(&mut f);
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.file.cmp(&b.file)));

    let gate_status = if findings.is_empty() {
        "PASSED".to_string()
    } else {
        "BLOCKED".to_string()
    };

    ScanReport {
        tool: "env-checker".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        environment: env,
        gate_status,
        files_scanned,
        duration_ms: start.elapsed().as_millis(),
        findings,
        env_files_detected,
    }
}

/// Purge leaked .env files from git index / disk and redact API keys in source files.
pub fn purge_leaks(
    root: &Path,
    report: &ScanReport,
    delete_env_files: bool,
    redact_source: bool,
    purge_history: bool,
) -> PurgeSummary {
    let mut summary = PurgeSummary {
        unstaged_files: Vec::new(),
        removed_files: Vec::new(),
        redacted_files: Vec::new(),
        gitignore_updated: false,
        history_purged: false,
    };

    // 1. Unstage & optionally remove any sensitive .env / key files
    let mut handled_env_files: Vec<String> = report.env_files_detected.clone();
    for f in &report.findings {
        if f.is_env_file && !handled_env_files.contains(&f.file) {
            handled_env_files.push(f.file.clone());
        }
    }

    for rel in &handled_env_files {
        let full = root.join(rel);
        let rm_out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rm", "--cached", "--ignore-unmatch", "-f", rel])
            .output();
        if let Ok(out) = rm_out {
            if out.status.success() {
                summary.unstaged_files.push(rel.clone());
            }
        }

        if delete_env_files && full.exists() {
            if fs::remove_file(&full).is_ok() {
                summary.removed_files.push(rel.clone());
            }
        }
    }

    // 2. Redact hardcoded secrets in non-.env source files if requested
    if redact_source {
        let mut source_files: Vec<String> = report
            .findings
            .iter()
            .filter(|f| !f.is_env_file)
            .map(|f| f.file.clone())
            .collect();
        source_files.sort();
        source_files.dedup();

        for rel in source_files {
            let full = root.join(&rel);
            if let Ok(content) = fs::read_to_string(&full) {
                let mut updated = content.clone();
                for rule in SECRET_RULES.iter() {
                    updated = rule
                        .regex
                        .replace_all(&updated, |caps: &regex::Captures| {
                            if let Some(m1) = caps.get(1) {
                                let whole = caps.get(0).unwrap().as_str();
                                if is_placeholder(m1.as_str()) {
                                    whole.to_string()
                                } else {
                                    whole.replace(m1.as_str(), "[REDACTED_BY_ENV_CHECKER]")
                                }
                            } else {
                                let whole = caps.get(0).unwrap().as_str();
                                if is_placeholder(whole) {
                                    whole.to_string()
                                } else {
                                    "[REDACTED_BY_ENV_CHECKER]".to_string()
                                }
                            }
                        })
                        .to_string();
                }

                if updated != content && fs::write(&full, updated).is_ok() {
                    summary.redacted_files.push(rel);
                }
            }
        }
    }

    // 3. Harden .gitignore
    let gitignore_path = root.join(".gitignore");
    let existing = fs::read_to_string(&gitignore_path).unwrap_or_default();
    let required_patterns = [".env", ".env.*", "!.env.example", "*.pem", "*.key"];
    let mut additions = Vec::new();
    for pat in required_patterns {
        if !existing.lines().any(|l| l.trim() == pat) {
            additions.push(pat);
        }
    }
    if !additions.is_empty() {
        let mut next = existing;
        if !next.is_empty() && !next.ends_with('\n') {
            next.push('\n');
        }
        next.push_str("\n# Added by env-checker security gate\n");
        for pat in additions {
            next.push_str(pat);
            next.push('\n');
        }
        if fs::write(&gitignore_path, next).is_ok() {
            summary.gitignore_updated = true;
        }
    }

    // 4. Optional git history scrub for leaked .env files
    if purge_history && !handled_env_files.is_empty() {
        let paths_arg = handled_env_files.join(" ");
        let filter_cmd = format!("git rm --cached --ignore-unmatch -f {paths_arg}");
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .env("FILTER_BRANCH_SQUELCH_WARNING", "1")
            .args([
                "filter-branch",
                "--force",
                "--index-filter",
                &filter_cmd,
                "--prune-empty",
                "--tag-name-filter",
                "cat",
                "--",
                "--all",
            ])
            .status();
        if matches!(status, Ok(s) if s.success()) {
            summary.history_purged = true;
        }
    }

    summary
}

pub fn to_sarif(report: &ScanReport) -> serde_json::Value {
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": match f.severity {
                    Severity::Critical | Severity::High => "error",
                    Severity::Medium => "warning",
                },
                "message": {
                    "text": format!("{} ({}) — {}", f.rule_name, f.redacted_match, f.remediation)
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": { "startLine": f.line }
                    }
                }]
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "env-checker",
                    "version": report.version,
                    "informationUri": "https://env.kishor.tech"
                }
            },
            "results": results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_openai_and_aws_keys() {
        let sample = "OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890abcdef\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7PROD999\n";
        let findings = scan_content(".env", sample, true);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "EC-001");
        assert_eq!(findings[1].rule_id, "EC-003");
    }

    #[test]
    fn ignores_placeholders_and_example_files() {
        let sample = "OPENAI_API_KEY=your_api_key_here_example\nDB_PASS=${DATABASE_PASSWORD}\n";
        let findings = scan_content(".env.example", sample, false);
        assert!(findings.is_empty());
        assert!(!is_sensitive_env_filename(Path::new(".env.example")));
        assert!(is_sensitive_env_filename(Path::new(".env.production")));
    }

    #[test]
    fn computes_shannon_entropy_correctly() {
        assert!(shannon_entropy("aaaaaaaaaa") < 0.1);
        assert!(shannon_entropy("xK9#mP2$vL8qR4zT1wN6") > 4.0);
    }

    #[test]
    fn purges_and_redacts_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("env_checker_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let env_file = dir.join(".env.production");
        fs::write(&env_file, "GROQ_API_KEY=gsk_1234567890abcdefghijklmnopqrstuvwxyz123456\n").unwrap();

        let src_file = dir.join("config.ts");
        fs::write(&src_file, "export const key = 'AIzaSyD-9999999999999999999999999999999';\n").unwrap();

        let report = scan_directory(&dir, false, Environment::Prod);
        assert_eq!(report.gate_status, "BLOCKED");
        assert!(report.findings.len() >= 2);

        let summary = purge_leaks(&dir, &report, true, true, false);
        assert!(summary.removed_files.contains(&".env.production".to_string()));
        assert!(summary.redacted_files.contains(&"config.ts".to_string()));
        assert!(summary.gitignore_updated);
        assert!(!env_file.exists());

        let redacted_src = fs::read_to_string(&src_file).unwrap();
        assert!(redacted_src.contains("[REDACTED_BY_ENV_CHECKER]"));

        let _ = fs::remove_dir_all(&dir);
    }
}
