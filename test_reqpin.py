import contextlib
import io
import json
import os
import tempfile
import unittest

import reqpin as rp

H = "--hash=sha256:" + "a" * 64
SHA = "a" * 40


def rules(text, **kw):
    return {(f[0], f[1]) for f in rp.audit_text(text, **kw)}


class HelperTests(unittest.TestCase):
    def test_edit_distance(self):
        self.assertEqual(rp.edit_distance("requests", "requests"), 0)
        self.assertEqual(rp.edit_distance("requets", "requests"), 1)
        self.assertEqual(rp.edit_distance("reqeusts", "requests"), 1)  # transposition
        self.assertEqual(rp.edit_distance("abc", "xyz"), 3)

    def test_lookalike(self):
        self.assertEqual(rp.lookalike("reqeusts"), "requests")
        self.assertEqual(rp.lookalike("python-dateutils"), "python-dateutil")
        self.assertIsNone(rp.lookalike("requests"))
        self.assertIsNone(rp.lookalike("Flask"))
        self.assertIsNone(rp.lookalike("my-internal-lib"))
        self.assertIsNone(rp.lookalike("numpyx", allow=["numpyx"]))
        self.assertIsNone(rp.lookalike("pip3"))  # too short to compare

    def test_normalize(self):
        self.assertEqual(rp.normalize("Typing_Extensions"), "typing-extensions")


class AuditTests(unittest.TestCase):
    def test_pinned_with_hash_clean(self):
        self.assertEqual(rp.audit_text("requests==2.31.0 \\\n    %s\n" % H), [])

    def test_unpinned_variants(self):
        for line in ("flask", "flask>=2.0", "flask~=2.0", "flask==2.*", "flask!=1.0"):
            self.assertIn(("MEDIUM", "unpinned-version"), rules(line + "\n"), line)
        self.assertNotIn(("MEDIUM", "unpinned-version"), rules("flask==2.0.1\n"))

    def test_extras_and_markers(self):
        self.assertNotIn(("MEDIUM", "unpinned-version"), rules("uvicorn[standard]==0.30.0 ; python_version>'3.8'\n"))

    def test_missing_hashes_aggregated(self):
        f = [x for x in rp.audit_text("flask==2.0.1\nrich==13.0.0\n") if x[1] == "missing-hashes"]
        self.assertEqual(len(f), 1)
        self.assertIn("2 pinned", f[0][3])

    def test_indexes(self):
        r = rules("--index-url http://pypi.example/simple\n--extra-index-url https://x.example/simple\n"
                  "--trusted-host pypi.example\n")
        for e in (("HIGH", "insecure-index"), ("MEDIUM", "extra-index"), ("MEDIUM", "trusted-host")):
            self.assertIn(e, r)
        self.assertEqual(rules("--index-url https://pypi.org/simple\n"), set())

    def test_vcs(self):
        self.assertIn(("MEDIUM", "unpinned-vcs"), rules("git+https://example.com/a/b.git@main#egg=b\n"))
        self.assertNotIn(("MEDIUM", "unpinned-vcs"), rules("git+https://example.com/a/b.git@%s#egg=b\n" % SHA))
        self.assertIn(("HIGH", "insecure-vcs"), rules("git://example.com/a/b.git\n"))
        self.assertIn(("MEDIUM", "unpinned-vcs"), rules("-e git+https://example.com/a/b.git#egg=b\n"))

    def test_urls(self):
        self.assertIn(("HIGH", "insecure-url"), rules("http://example.com/pkg.whl\n"))
        self.assertIn(("LOW", "url-without-hash"), rules("https://example.com/pkg.whl\n"))
        self.assertNotIn(("LOW", "url-without-hash"), rules("https://example.com/pkg.whl#sha256=" + "a" * 64 + "\n"))

    def test_typosquat_finding(self):
        self.assertIn(("MEDIUM", "typosquat-lookalike"), rules("reqeusts==1.0.0 %s\n" % H))
        self.assertNotIn(("MEDIUM", "typosquat-lookalike"), rules("reqeusts==1.0.0 %s\n" % H, allow=["reqeusts"]))

    def test_comments_and_blank(self):
        self.assertEqual(rp.audit_text("# flask\n\n"), [])
        self.assertEqual(rp.audit_text("requests==2.31.0 %s  # pinned\n" % H), [])


class CliTests(unittest.TestCase):
    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "requirements.txt")
            with open(p, "w") as fh:
                fh.write("requests==2.31.0 %s\n" % H)
            self.assertEqual(rp.main([p]), 0)
            with open(p, "w") as fh:
                fh.write("requests\n")
            self.assertEqual(rp.main([p]), 1)
            self.assertEqual(rp.main([os.path.join(d, "nope.txt")]), 2)


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = rp.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    return path


class IncludeTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = self._t.name

    def tearDown(self):
        self._t.cleanup()

    def test_includes_parsing(self):
        self.assertEqual(rp.includes("-r base.txt\n--requirement=dev.txt\n-rtests.txt\nflask==1\n"),
                         ["base.txt", "dev.txt", "tests.txt"])

    def test_follows_include_and_labels_findings_by_file(self):
        write(os.path.join(self.d, "base.txt"), "flask\n")
        top = write(os.path.join(self.d, "requirements.txt"), "-r base.txt\nrequests==2.31.0 %s\n" % H)
        code, out, err = run_main(top, "--format", "json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual([os.path.basename(d["file"]) for d in data if d["rule"] == "unpinned-version"], ["base.txt"])
        self.assertIn("2 file(s)", err)

    def test_no_follow(self):
        write(os.path.join(self.d, "base.txt"), "flask\n")
        top = write(os.path.join(self.d, "requirements.txt"), "-r base.txt\nrequests==2.31.0 %s\n" % H)
        self.assertEqual(run_main(top, "--no-follow")[0], 0)

    def test_cycle_terminates(self):
        write(os.path.join(self.d, "a.txt"), "-r b.txt\nflask==1.0\n")
        write(os.path.join(self.d, "b.txt"), "-r a.txt\nflask==1.0\n")
        order = rp.expand(os.path.join(self.d, "a.txt"))
        self.assertEqual(len(order), 2)

    def test_include_outside_project_not_followed(self):
        with tempfile.TemporaryDirectory() as other:
            write(os.path.join(other, "evil.txt"), "flask\n")
            os.makedirs(os.path.join(self.d, "proj"))
            top = write(os.path.join(self.d, "proj", "requirements.txt"), "-r %s\n-r ../x.txt\n" % os.path.join(other, "evil.txt"))
            warnings = []
            order = rp.expand(top, True, warnings.append)
            self.assertEqual(order, [top])
            self.assertEqual(len(warnings), 2)
            self.assertTrue(all("outside" in w for w in warnings))

    def test_symlink_escape_not_followed(self):
        with tempfile.TemporaryDirectory() as other:
            target = write(os.path.join(other, "evil.txt"), "flask\n")
            os.makedirs(os.path.join(self.d, "proj"))
            os.symlink(target, os.path.join(self.d, "proj", "link.txt"))
            top = write(os.path.join(self.d, "proj", "requirements.txt"), "-r link.txt\n")
            self.assertEqual(rp.expand(top), [top])

    def test_remote_and_missing_includes_warn(self):
        top = write(os.path.join(self.d, "requirements.txt"), "-r https://example.com/r.txt\n-r missing.txt\n")
        warnings = []
        rp.expand(top, True, warnings.append)
        self.assertEqual(len(warnings), 2)

    def test_file_included_twice_scanned_once(self):
        write(os.path.join(self.d, "base.txt"), "flask\n")
        write(os.path.join(self.d, "a.txt"), "-r base.txt\n")
        write(os.path.join(self.d, "b.txt"), "-r base.txt\n")
        _, out, _ = run_main(os.path.join(self.d, "a.txt"), os.path.join(self.d, "b.txt"), "--format", "json")
        self.assertEqual(sum(1 for d in json.loads(out) if d["rule"] == "unpinned-version"), 1)

    def test_missing_top_file(self):
        self.assertEqual(run_main(os.path.join(self.d, "nope.txt"))[0], 2)


class IgnoreTests(unittest.TestCase):
    def names(self, text):
        return {f[1] for f in rp.apply_ignores(text, rp.audit_text(text))}

    def test_line_ignore(self):
        self.assertNotIn("unpinned-version", self.names("flask  # reqpin: ignore[unpinned-version]\n"))

    def test_line_ignore_all_rules(self):
        self.assertNotIn("unpinned-version", self.names("flask  # reqpin: ignore\n"))

    def test_other_rule_does_not_silence(self):
        self.assertIn("unpinned-version", self.names("flask  # reqpin: ignore[extra-index]\n"))

    def test_only_that_line(self):
        t = "flask  # reqpin: ignore\ndjango\n"
        found = rp.apply_ignores(t, rp.audit_text(t))
        self.assertEqual([f[2] for f in found if f[1] == "unpinned-version"], [2])

    def test_ignore_file(self):
        t = "# reqpin: ignore-file[unpinned-version]\nflask\ndjango\n"
        self.assertNotIn("unpinned-version", self.names(t))


class FormatTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.path = write(os.path.join(self._t.name, "requirements.txt"), "flask\nreqeusts==1.0 %s\n" % H)

    def tearDown(self):
        self._t.cleanup()

    def test_json(self):
        code, out, _ = run_main(self.path, "--format", "json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual({d["rule"] for d in data}, {"unpinned-version", "typosquat-lookalike"})

    def test_sarif(self):
        _, out, _ = run_main(self.path, "--format", "sarif")
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual({r["level"] for r in sarif["runs"][0]["results"]}, {"warning"})

    def test_min_severity_json(self):
        _, out, _ = run_main(self.path, "--format", "json", "--min-severity", "HIGH")
        self.assertEqual(json.loads(out), [])

    def test_allow_still_works(self):
        _, out, _ = run_main(self.path, "--format", "json", "--allow", "reqeusts")
        self.assertNotIn("typosquat-lookalike", {d["rule"] for d in json.loads(out)})


if __name__ == "__main__":
    unittest.main()
