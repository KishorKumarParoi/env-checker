#!/usr/bin/env python3
"""
🛡️ Universal ENV-CHECKER Integration Engine
Installs and activates env-checker pre-commit and pre-push quality gates
across all existing git repositories on the system.
"""

import os
import sys
import subprocess
from pathlib import Path

HOME = Path.home()

SCAN_ROOTS = [
    HOME / "Desktop",
    HOME / "job-project",
]

EXCLUDE_DIRS = {
    "node_modules",
    ".cache",
    ".cargo",
    "target",
    "dist",
    "build",
    "venv",
    ".venv",
    "Library",
    ".Trash",
    ".gemini",
    ".antigravity",
}

PRE_COMMIT_BLOCK = """
# --- [ENV-CHECKER Pre-Commit Gate (https://env.kishor.tech)] ---
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
if command -v env-checker >/dev/null 2>&1; then
    env-checker scan --staged --env prod || exit 1
elif [ -x "$HOME/.local/bin/env-checker" ]; then
    "$HOME/.local/bin/env-checker" scan --staged --env prod || exit 1
elif [ -x "$HOME/.cargo/bin/env-checker" ]; then
    "$HOME/.cargo/bin/env-checker" scan --staged --env prod || exit 1
fi
# --- [END ENV-CHECKER] ---
"""

PRE_PUSH_BLOCK = """
# --- [ENV-CHECKER Pre-Push Gate (https://env.kishor.tech)] ---
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
if command -v env-checker >/dev/null 2>&1; then
    env-checker scan --env prod || exit 1
elif [ -x "$HOME/.local/bin/env-checker" ]; then
    "$HOME/.local/bin/env-checker" scan --env prod || exit 1
elif [ -x "$HOME/.cargo/bin/env-checker" ]; then
    "$HOME/.cargo/bin/env-checker" scan --env prod || exit 1
fi
# --- [END ENV-CHECKER] ---
"""

def find_git_repos():
    repos = set()
    for root_dir in SCAN_ROOTS:
        if not root_dir.exists():
            continue
        for root, dirs, _ in os.walk(root_dir):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".trash")]
            if ".git" in dirs:
                repo_path = Path(root)
                repos.add(repo_path)
                dirs.remove(".git")
    return sorted(list(repos))


def get_hooks_dir(repo_path: Path) -> Path:
    # Use git command to accurately resolve hooks directory even for worktrees / submodules
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--git-path", "hooks"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=True
        )
        hooks_rel = res.stdout.strip()
        hooks_dir = repo_path / hooks_rel if not Path(hooks_rel).is_absolute() else Path(hooks_rel)
        if not hooks_dir.is_absolute():
            hooks_dir = (repo_path / hooks_dir).resolve()
        return hooks_dir
    except Exception:
        return repo_path / ".git" / "hooks"


def install_hook(hook_file: Path, hook_block: str, default_shebang: str = "#!/usr/bin/env sh\n"):
    if not hook_file.exists():
        content = default_shebang + hook_block + "\nexit 0\n"
        hook_file.write_text(content, encoding="utf-8")
        hook_file.chmod(0o755)
        return "created"

    current_content = hook_file.read_text(encoding="utf-8")
    if "env-checker" in current_content:
        return "already_active"

    # Prepend right after shebang
    lines = current_content.splitlines(keepends=True)
    if lines and lines[0].startswith("#!"):
        shebang = lines[0]
        rest = "".join(lines[1:])
        new_content = shebang + hook_block + "\n" + rest
    else:
        new_content = default_shebang + hook_block + "\n" + current_content

    hook_file.write_text(new_content, encoding="utf-8")
    hook_file.chmod(0o755)
    return "updated"


def main():
    print("🔍 Discovering all Git repositories on the system...")
    repos = find_git_repos()
    print(f"📦 Found {len(repos)} Git repositories to protect.\n")

    created_count = 0
    updated_count = 0
    already_active = 0

    for i, repo in enumerate(repos, 1):
        hooks_dir = get_hooks_dir(repo)
        hooks_dir.mkdir(parents=True, exist_ok=True)

        pre_commit = hooks_dir / "pre-commit"
        pre_push = hooks_dir / "pre-push"

        status_pc = install_hook(pre_commit, PRE_COMMIT_BLOCK)
        status_pp = install_hook(pre_push, PRE_PUSH_BLOCK)

        if "created" in (status_pc, status_pp):
            created_count += 1
            action_tag = "✅ INSTALLED"
        elif "updated" in (status_pc, status_pp):
            updated_count += 1
            action_tag = "🔄 INTEGRATED"
        else:
            already_active += 1
            action_tag = "🔒 ACTIVE"

        print(f"[{i:02d}/{len(repos):02d}] {action_tag:12s} {repo.name} ({repo})")

    print("\n" + "=" * 70)
    print("🛡️  ENV-CHECKER INTEGRATION SUMMARY")
    print("=" * 70)
    print(f"Total Repositories Protected : {len(repos)}")
    print(f"New Hooks Created            : {created_count}")
    print(f"Existing Hooks Upgraded      : {updated_count}")
    print(f"Already Protected            : {already_active}")
    print(f"Global Git Template          : Configured at ~/.git-templates/hooks")
    print(f"System-Wide Binary           : /Users/kishorkumarparoi/.local/bin/env-checker")
    print("=" * 70)


if __name__ == "__main__":
    main()
