# reqpin

Supply-chain audit for pip requirements files. It works **offline** and is read-only:
it flags unpinned versions, missing hashes, risky indexes, unpinned git/URL
dependencies and package names that look like **typosquats** of popular packages.
One file, standard library only.

## Usage

```bash
python3 reqpin.py                          # ./requirements.txt
python3 reqpin.py requirements.txt dev-requirements.txt --min-severity MEDIUM
python3 reqpin.py requirements.txt --allow my-custom-lib
python3 reqpin.py --format json                 # or --format sarif
# or: pip install git+https://github.com/TPOALOS/reqpin && reqpin
```

Example output:

```
MEDIUM unpinned-version     requirements.txt:3: flask is not pinned with ==
         fix: pin an exact version, e.g. flask==x.y.z
MEDIUM typosquat-lookalike  requirements.txt:5: 'reqeusts' is one edit away from popular package 'requests'
         fix: verify the name on PyPI; use --allow reqeusts if it is intentional
LOW    missing-hashes       requirements.txt: 12 pinned requirement(s) have no --hash (e.g. rich)
         fix: generate hashes (pip-compile --generate-hashes) and install with --require-hashes
```

## Checks

| Rule | Severity | What it flags |
|------|----------|---------------|
| `insecure-index`, `insecure-url`, `insecure-vcs` | HIGH | plain `http://` indexes or downloads, `git://` and `git+http://` |
| `unpinned-version` | MEDIUM | anything not pinned with an exact `==` (including `>=`, `~=`, `==1.*`) |
| `unpinned-vcs` | MEDIUM | `git+https://...` not pinned to a full 40-character commit SHA |
| `extra-index` | MEDIUM | `--extra-index-url` (dependency-confusion risk) |
| `trusted-host` | MEDIUM | `--trusted-host` (TLS verification disabled) |
| `typosquat-lookalike` | MEDIUM | name is one edit (typo, swap, missing letter) from a built-in list of ~150 popular packages |
| `missing-hashes` | LOW | pinned requirements without `--hash` (reported once per file) |
| `url-without-hash`, `editable-install` | LOW | URL dependency without `#sha256=`, `-e` installs |

Exit codes: `0` clean, `1` findings, `2` unreadable file.

### Included files

`-r base.txt` lines are followed, so `requirements.txt` that pulls in `base.txt` and `dev.txt` audits all three,
and each finding names the file it came from. Includes must stay inside the directory of the file you passed
(symlinks pointing outside are refused), remote includes are never fetched, and include cycles are safe.
Use `--no-follow` to audit only the files you name.

### Silencing a finding you accept

```
internal-lib  # reqpin: ignore[unpinned-version]
# reqpin: ignore-file[missing-hashes]      (silences a rule for the whole file; no list = everything)
```

The comment goes on the first line of the requirement.

## Limits

- The typosquat check only compares against a small built-in list and is a hint, not a verdict.
  Real packages can sit one edit from a popular name; use `--allow NAME` for those.
- It does not query PyPI or vulnerability databases. `-c` constraint files are not followed.
- Environment markers are ignored; `pyproject.toml` and `Pipfile` are not parsed.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
