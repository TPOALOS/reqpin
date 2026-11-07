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


if __name__ == "__main__":
    unittest.main()
