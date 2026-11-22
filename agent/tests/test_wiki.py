"""Every wiki page names the portnook version it was checked against (docs/wiki)."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WIKI = ROOT / "docs" / "wiki"
LINE = re.compile(r"^> \*\*Applies to:\*\* portnook (\d+)\.(\d+) \((\w+)\) · \[Versions\]\(Versions\)$", re.M)
META = {"Versions.md"}


def version():
    major, minor = (ROOT / "VERSION").read_text().strip().split(".")[:2]
    return int(major), int(minor)


class WikiVersionTest(unittest.TestCase):
    def pages(self):
        return [p for p in sorted(WIKI.glob("*.md")) if not p.name.startswith("_") and p.name not in META]

    def test_every_page_has_applies_to(self):
        self.assertTrue(self.pages())
        for page in self.pages():
            with self.subTest(page=page.name):
                self.assertIsNotNone(LINE.search(page.read_text()), "missing 'Applies to' line")

    def test_applies_to_not_newer_than_version(self):
        for page in self.pages():
            m = LINE.search(page.read_text())
            if m:
                with self.subTest(page=page.name):
                    self.assertLessEqual((int(m.group(1)), int(m.group(2))), version())

    def test_every_page_in_versions_table(self):
        table = (WIKI / "Versions.md").read_text()
        for page in self.pages():
            with self.subTest(page=page.name):
                self.assertIn("](%s)" % page.stem, table)


if __name__ == "__main__":
    unittest.main()
