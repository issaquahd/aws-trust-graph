"""Turn the placeholder fixtures into realistic input at test time.

Committed fixtures never contain 12-digit numbers. ACCOUNT_* placeholders are
replaced with synthetic, runtime-built account IDs so the redaction logic is
exercised for real. Run `python3 -m tests.fixture_util examples` to refresh
the committed (redacted) example outputs.
"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")

# Synthetic IDs assembled at runtime (never stored as literals).
ACCOUNTS = {
    "ACCOUNT_SELF": "1" * 12,
    "ACCOUNT_PARTNER": "2" * 6 + "3" * 6,
    "ACCOUNT_VENDOR": "4" * 4 + "5" * 8,
    "ACCOUNT_THIRD": "6" * 12,
}


def substitute(text):
    for placeholder, value in ACCOUNTS.items():
        text = text.replace(placeholder, value)
    return text


def materialize():
    """Copy fixtures into a temp dir with real-looking IDs. Returns (tmpdir, list_roles_path, get_role_dir)."""
    tmp = tempfile.mkdtemp(prefix="trust-graph-test-")
    for root, _dirs, files in os.walk(FIXTURES):
        rel = os.path.relpath(root, FIXTURES)
        os.makedirs(os.path.join(tmp, rel), exist_ok=True)
        for name in files:
            with open(os.path.join(root, name)) as src:
                text = substitute(src.read())
            with open(os.path.join(tmp, rel, name), "w") as dst:
                dst.write(text)
    return tmp, os.path.join(tmp, "list-roles.json"), os.path.join(tmp, "get-role")


def main(out_dir):
    sys.path.insert(0, os.path.dirname(HERE))
    import trust_graph

    tmp, list_roles, get_role_dir = materialize()
    try:
        os.makedirs(out_dir, exist_ok=True)
        return trust_graph.main([list_roles, "--get-role-dir", get_role_dir,
                                 "--out", os.path.join(out_dir, "trust-graph.mmd"),
                                 "--findings", os.path.join(out_dir, "findings.md")])
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "examples"))
