#!/usr/bin/env python3
"""Pre-push safety scan: blocks pushes to public remotes that contain PII or sensitive data.

Called by .git/hooks/pre-push automatically on every `git push`.
Also callable standalone:
    python scripts/pre_push_check.py           # scan HEAD vs remote
    python scripts/pre_push_check.py --all     # scan entire working tree

Exit 0 = clean (push proceeds). Exit 1 = blocked (push aborted).
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# (label, compiled_regex, severity)
CONTENT_RULES = [
    # AWS credentials
    ("AWS_ACCESS_KEY_ID",  re.compile(r"AKIA[0-9A-Z]{16}"),                             "CRITICAL"),
    ("AWS_PRIVATE_KEY",    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),            "CRITICAL"),
    ("AWS_SESSION_TOKEN",  re.compile(r"FwoGZXIvYXdzE[A-Za-z0-9+/=]{80,}"),             "CRITICAL"),
    # Amazon internal systems / URLs not appropriate for public repos
    ("INTERNAL_URL",       re.compile(r"\.corp\.amazon\.com|\.internal\.amazon\.com"),   "HIGH"),
    ("ISENGARD_URL",       re.compile(r"isengard\.amazon\.com"),                         "HIGH"),
    ("MIDWAY_URL",         re.compile(r"midway-auth\.amazon\.com"),                      "HIGH"),
    # Only flag ada commands that include --provider isengard (internal system reference in non-doc files)
    ("ADA_ISENGARD_CMD",  re.compile(r"ada credentials update.*--provider isengard.*--role\s+Admin"), "HIGH"),
    # Internal account IDs outside the known public demo account
    ("AWS_ACCOUNT_INTERNAL", re.compile(r"\b83192662779[0-9]\b"),                        "HIGH"),
    # PII
    ("SSN",                re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                         "CRITICAL"),
    ("US_PHONE",           re.compile(r"\b(\+1[\s-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"), "MEDIUM"),
]

# File path prefixes that must never be pushed externally (checked against the
# actual file path, not content, so the scanner itself doesn't self-trigger).
BLOCKED_PATH_PATTERNS = [
    re.compile(r"(^|/)CLAUDE\.md$"),
    re.compile(r"(^|/)\.env$"),
    re.compile(r"(^|/)\.claude/"),
    re.compile(r"(^|/)paper_intercept/"),
    re.compile(r"(^|/)paper_iilm/"),
]

# Known-safe test/demo values that must not trigger false positives.
# These are canonical fake values from AWS docs and standard test SSNs.
ALLOWLISTED_STRINGS = {
    "AKIAIOSFODNN7EXAMPLE",   # AWS docs fake key
    "AKIAIOSFODNN7EXAMPL",    # truncated variant
    "987-65-4321",            # canonical fake SSN used in HIPAA demos
    "123-45-6789",            # canonical fake SSN
    "000-00-0000",            # canonical fake SSN
}

# Extensions to skip (binary / generated / unlikely to carry secrets)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".pdf",
    ".pyc", ".pyo", ".so", ".dll", ".exe",
    ".lock",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _git(*args):
    return subprocess.check_output(["git"] + list(args), text=True).strip()


def _changed_files_in_push(local_sha: str, remote_sha: str) -> list[str]:
    """Files changed between what's on remote and what's about to be pushed."""
    if remote_sha == "0" * 40:
        # New branch: compare against the merge-base with main, or just list all files
        try:
            base = _git("merge-base", "HEAD", "origin/main")
            result = _git("diff", "--name-only", base, local_sha)
        except subprocess.CalledProcessError:
            result = _git("diff", "--name-only", "--cached")
    else:
        result = _git("diff", "--name-only", remote_sha, local_sha)
    return [f for f in result.splitlines() if f.strip()]


def _all_tracked_files() -> list[str]:
    return _git("ls-files").splitlines()


def _scan_file(path: str) -> list[tuple[str, str, str, int]]:
    """Return list of (path, label, severity, line_num) findings."""
    findings = []
    p = Path(path)
    if not p.exists():
        return findings
    if p.suffix.lower() in SKIP_EXTENSIONS:
        return findings
    # The scanner file itself contains its own patterns as string literals; skip it
    if p.name == "pre_push_check.py":
        return findings
    is_doc = p.suffix.lower() in {".md", ".rst", ".txt"}
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return findings
    for i, line in enumerate(lines, 1):
        # Skip lines that only contain known-safe demo/test values
        if any(safe in line for safe in ALLOWLISTED_STRINGS):
            continue
        for label, pattern, severity in CONTENT_RULES:
            # Ada/isengard command in docs or script docstrings = usage instructions, expected
            if label == "ADA_ISENGARD_CMD" and (is_doc or line.strip().startswith("ada ")):
                continue
            if pattern.search(line):
                findings.append((path, label, severity, i))
    return findings


def _check_paths(files: list[str]) -> list[tuple[str, str]]:
    """Return list of (path, label) for blocked file paths."""
    blocked = []
    for f in files:
        for pat in BLOCKED_PATH_PATTERNS:
            if pat.search(f):
                blocked.append((f, pat.pattern))
                break
    return blocked


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Pre-push PII / sensitive data scan")
    parser.add_argument("--all", action="store_true", help="Scan entire working tree instead of changed files")
    parser.add_argument("--remote", default="", help="Remote name (set by hook)")
    parser.add_argument("--url",    default="", help="Remote URL (set by hook)")
    args, _ = parser.parse_known_args()

    # Only run for pushes to external GitHub remotes
    url = args.url or ""
    if url and "github.com" not in url and "gitlab.com" not in url and "bitbucket.org" not in url:
        print(f"[pre-push] Skipping scan for internal/local remote: {url}")
        sys.exit(0)

    if args.all:
        files = _all_tracked_files()
        print(f"[pre-push] Scanning all {len(files)} tracked files...")
    else:
        # Read push refs from stdin (format: <local_ref> <local_sha> <remote_ref> <remote_sha>)
        files = []
        stdin_lines = sys.stdin.read().strip().splitlines() if not sys.stdin.isatty() else []
        if stdin_lines:
            for line in stdin_lines:
                parts = line.split()
                if len(parts) == 4:
                    local_sha, remote_sha = parts[1], parts[3]
                    files.extend(_changed_files_in_push(local_sha, remote_sha))
        if not files:
            # Fallback: everything staged or diff vs HEAD~1
            try:
                files = _changed_files_in_push("HEAD", _git("rev-parse", "HEAD~1"))
            except Exception:
                files = _all_tracked_files()
        files = list(set(files))
        print(f"[pre-push] Scanning {len(files)} changed file(s) before push to {url or 'remote'}...")

    # Run checks
    path_violations = _check_paths(files)
    content_violations = []
    for f in files:
        content_violations.extend(_scan_file(f))

    # Report
    clean = True

    if path_violations:
        clean = False
        print("\n[BLOCKED] Files that must never be pushed externally:")
        for path, label in path_violations:
            print(f"  {path}  ({label})")

    criticals = [(p, l, s, n) for p, l, s, n in content_violations if s == "CRITICAL"]
    highs     = [(p, l, s, n) for p, l, s, n in content_violations if s == "HIGH"]
    mediums   = [(p, l, s, n) for p, l, s, n in content_violations if s == "MEDIUM"]

    if criticals:
        clean = False
        print("\n[BLOCKED] CRITICAL findings (credentials / PII):")
        for path, label, _, lineno in criticals:
            print(f"  {path}:{lineno}  [{label}]")

    if highs:
        clean = False
        print("\n[BLOCKED] HIGH findings (internal systems / sensitive data):")
        for path, label, _, lineno in highs:
            print(f"  {path}:{lineno}  [{label}]")

    if mediums:
        # Warn but do not block
        print("\n[WARN] MEDIUM findings (review before continuing):")
        for path, label, _, lineno in mediums:
            print(f"  {path}:{lineno}  [{label}]")

    if not clean:
        print("\n[pre-push] Push BLOCKED. Resolve findings above before pushing externally.")
        print("To push anyway (not recommended): git push --no-verify")
        sys.exit(1)

    print(f"[pre-push] Clean. {len(files)} file(s) checked, no PII or sensitive data found.")
    sys.exit(0)


if __name__ == "__main__":
    main()
