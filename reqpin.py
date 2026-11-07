#!/usr/bin/env python3
"""reqpin - supply-chain audit for pip requirements files.

Offline and read-only. Flags unpinned versions, missing hashes, insecure or extra
package indexes, unpinned git/URL dependencies, and package names that look like
typosquats of popular packages. Standard library only.
Exit code 0 = clean, 1 = findings, 2 = error.
"""
import argparse
import re
import sys

__version__ = "1.0.0"

POPULAR = """requests numpy pandas scipy matplotlib flask django fastapi uvicorn pydantic sqlalchemy boto3
botocore urllib3 certifi idna charset-normalizer setuptools wheel pip pytest black flake8 mypy pillow pyyaml
cryptography jinja2 markupsafe click six python-dateutil pytz tqdm beautifulsoup4 lxml selenium scikit-learn
tensorflow torch keras opencv-python aiohttp httpx redis celery psycopg2 pymysql gunicorn paramiko rich typer
attrs packaging pyparsing colorama jsonschema protobuf grpcio openpyxl xlrd sympy networkx seaborn plotly dash
streamlit transformers huggingface-hub tokenizers openai anthropic langchain pytest-cov tox poetry virtualenv
twine sphinx docutils regex tabulate termcolor joblib numba pyarrow werkzeug itsdangerous starlette websockets
requests-oauthlib oauthlib pyjwt bcrypt pynacl pyopenssl google-auth azure-core kubernetes docker ansible
fabric pexpect psutil pyserial pycparser cffi zipp importlib-metadata typing-extensions tomli filelock
platformdirs pluggy iniconfig exceptiongroup decorator wrapt ujson orjson simplejson python-dotenv pymongo motor
elasticsearch pika kafka-python sentry-sdk loguru coloredlogs humanize arrow pendulum babel cachetools backoff
tenacity retry deprecated mock faker hypothesis freezegun responses""".split()
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
FULL_SHA = re.compile(r"@[0-9a-f]{40}(?:$|[#\s])")


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def edit_distance(a, b):
    """Optimal string alignment distance (insert, delete, substitute, transpose)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def lookalike(name, popular=POPULAR, allow=()):
    """Return the popular package that `name` resembles, or None."""
    n = normalize(name)
    pops = {normalize(p) for p in popular}
    if n in pops or n in {normalize(a) for a in allow} or len(n) < 5:
        return None
    for p in sorted(pops):
        if abs(len(p) - len(n)) <= 1 and edit_distance(n, p) == 1:
            return p
    return None


def logical_lines(text):
    out, buf, start = [], "", 0
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = no
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        out.append((start, re.sub(r"(^|\s)#.*$", "", buf).strip()))
        buf = ""
    if buf:
        out.append((start, re.sub(r"(^|\s)#.*$", "", buf).strip()))
    return [(n, t) for n, t in out if t]


def audit_text(text, allow=()):
    """Return list of (severity, rule, lineno, message, fix)."""
    out = []
    add = lambda sev, rule, no, msg, fix: out.append((sev, rule, no, msg, fix))
    pinned_no_hash = []
    for no, line in logical_lines(text):
        low = line.lower()
        if line.startswith("-"):
            opt = line.split(None, 1)
            key = opt[0].lower()
            val = opt[1] if len(opt) > 1 else ""
            if key in ("--index-url", "-i") and val.lower().startswith("http://"):
                add("HIGH", "insecure-index", no, "package index uses plain http", "use an https index")
            elif key == "--extra-index-url":
                add("MEDIUM", "extra-index", no, "extra index enables dependency-confusion attacks",
                    "prefer a single trusted index (--index-url) or pin with hashes")
            elif key == "--trusted-host":
                add("MEDIUM", "trusted-host", no, "TLS verification is disabled for %s" % val, "remove --trusted-host")
            elif key == "--find-links" and val.lower().startswith("http://"):
                add("HIGH", "insecure-index", no, "find-links uses plain http", "use https")
            elif key in ("-e", "--editable"):
                add("LOW", "editable-install", no, "editable installs are not reproducible", "install a pinned build")
                if val.startswith(("git+", "http")):
                    line = val
                else:
                    continue
            else:
                continue
        if low.startswith("git://") or low.startswith("git+http://"):
            add("HIGH", "insecure-vcs", no, "git dependency over an unencrypted protocol", "use git+https with a commit SHA")
            continue
        if "git+" in low or low.startswith("hg+") or low.startswith("svn+"):
            if not FULL_SHA.search(line + " "):
                add("MEDIUM", "unpinned-vcs", no, "VCS dependency is not pinned to a full commit SHA",
                    "append @<40-char commit SHA>")
            continue
        if re.match(r"(?i)^https?://", line) or " @ http" in low:
            if low.startswith("http://") or " @ http://" in low:
                add("HIGH", "insecure-url", no, "dependency downloaded over plain http", "use https and a hash")
            elif "#sha256=" not in low and "--hash" not in low:
                add("LOW", "url-without-hash", no, "URL dependency has no integrity hash", "add #sha256=<hash>")
            continue
        m = NAME.match(line.split(";")[0].strip())
        if not m:
            continue
        name, spec = m.group(1), m.group(2)
        specifier = spec.split("--hash")[0]
        exact = re.search(r"(?<![<>=!~])==\s*[\w.+!-]+(?!\*)", specifier) and "*" not in specifier
        if not exact:
            add("MEDIUM", "unpinned-version", no, "%s is not pinned with ==" % name, "pin an exact version, e.g. %s==x.y.z" % name)
        elif "--hash=" not in line:
            pinned_no_hash.append(name)
        similar = lookalike(name, allow=allow)
        if similar:
            add("MEDIUM", "typosquat-lookalike", no, "%r is one edit away from popular package %r" % (name, similar),
                "verify the name on PyPI; use --allow %s if it is intentional" % name)
    if pinned_no_hash:
        add("LOW", "missing-hashes", None, "%d pinned requirement(s) have no --hash (e.g. %s)" % (
            len(pinned_no_hash), pinned_no_hash[0]), "generate hashes (pip-compile --generate-hashes) and install with --require-hashes")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Supply-chain audit for requirements files (offline).")
    ap.add_argument("files", nargs="*", default=["requirements.txt"])
    ap.add_argument("--allow", action="append", default=[], help="package name to exempt from lookalike check")
    ap.add_argument("--min-severity", choices=("LOW", "MEDIUM", "HIGH"), default="LOW")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    limit, count = SEV[args.min_severity], 0
    for path in args.files:
        try:
            with open(path, errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print("reqpin: %s" % exc, file=sys.stderr)
            return 2
        for sev, rule, no, msg, fix in sorted(audit_text(text, args.allow), key=lambda f: (SEV[f[0]], f[2] or 0)):
            if SEV[sev] > limit:
                continue
            count += 1
            print("%-6s %-20s %s%s: %s\n         fix: %s" % (sev, rule, path, ":%d" % no if no else "", msg, fix))
    print("reqpin: %d finding(s)" % count, file=sys.stderr)
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
