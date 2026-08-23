from __future__ import annotations

import re
import struct
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agent_shellcheck import __version__  # noqa: E402


class RepositoryQualityTests(unittest.TestCase):
    def test_package_and_source_versions_match(self) -> None:
        metadata = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', metadata, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), __version__)
        self.assertRegex(metadata, r"(?m)^dependencies\s*=\s*\[\]\s*$")

    def test_readme_relative_links_resolve(self) -> None:
        for readme_name in ("README.md", "README.zh-CN.md"):
            readme = (PROJECT_ROOT / readme_name).read_text(encoding="utf-8")
            links = re.findall(r"(?:href=\"|\]\()([^\"\s)#]+)", readme)
            missing = []
            for target in links:
                if "://" in target or target.startswith("#"):
                    continue
                path = (PROJECT_ROOT / target.split("#", 1)[0]).resolve()
                if not path.exists():
                    missing.append(target)
            self.assertEqual(missing, [], f"broken links in {readme_name}: {missing}")

    def test_svg_assets_are_well_formed(self) -> None:
        for name in ("logo.svg", "demo.svg", "social-preview.svg"):
            with self.subTest(name=name):
                root = ET.parse(PROJECT_ROOT / "assets" / name).getroot()
                self.assertTrue(root.tag.endswith("svg"))

    def test_social_preview_png_has_github_dimensions(self) -> None:
        data = (PROJECT_ROOT / "assets" / "social-preview.png").read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        width, height = struct.unpack(">II", data[16:24])
        self.assertEqual((width, height), (1280, 640))


if __name__ == "__main__":
    unittest.main()
