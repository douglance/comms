"""Reject credential-shaped examples before publication."""
import argparse
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW_ARCHIVE = "docs/slack/raw/llms-full.txt"
CREDENTIAL_PATTERNS = (
    ("slack-token", re.compile(r"\b(?:xox[baprs]-|xapp-)[0-9][A-Za-z0-9-]{10,}")),
    ("slack-webhook", re.compile(
        r"https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]{12,}"
    )),
)


def findings(path, text):
    """Report paths and line numbers only, never matching credential values."""
    result = []
    if path == RAW_ARCHIVE:
        result.append({"path": path, "line": 0, "kind": "raw-archive"})
    for number, line in enumerate(text.splitlines(), 1):
        for kind, pattern in CREDENTIAL_PATTERNS:
            if pattern.search(line):
                result.append({"path": path, "line": number, "kind": kind})
    return result


def self_test():
    # Generated synthetic examples exercise shapes without embedding token literals.
    for token_type in ("b", "p", "a", "r", "s"):
        sample = "xo" + "x" + token_type + "-" + "1234567890-" * 2 + "a" * 32
        assert findings("sample.txt", sample), token_type
    app = "xa" + "pp-" + "1-T1234567890-1234567890-" + "a" * 64
    assert findings("sample.txt", app)
    for endpoint in ("services", "workflows"):
        webhook = "https://hooks." + "slack.com/" + endpoint + "/T1234567890/B1234567890/" + "a" * 24
        assert findings("sample.txt", webhook), endpoint
    assert findings(RAW_ARCHIVE, "") == [
        {"path": RAW_ARCHIVE, "line": 0, "kind": "raw-archive"}
    ]
    assert not findings("sample.txt", "SLACK_TOKEN_PLACEHOLDER https://hooks.slack.example/WEBHOOK_PLACEHOLDER")
    assert not findings("sample.txt", "fixture-slack-user-token")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print(json.dumps({"self_test": "passed"}))
        return 0
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
    ).decode().split("\0")
    result = []
    for name in sorted(set(filter(None, names))):
        path = ROOT / name
        if name == RAW_ARCHIVE:
            result.extend(findings(name, ""))
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        result.extend(findings(name, text))
    print(json.dumps({"ok": not result, "findings": result}))
    return 1 if result else 0


if __name__ == "__main__":
    raise SystemExit(main())
