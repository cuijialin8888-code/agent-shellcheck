import os
from pathlib import Path
import tempfile
import unittest

from _support import run_cli, write_text


class OutputSafetyTests(unittest.TestCase):
    def test_hard_link_outputs_cannot_overwrite_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instruction = write_text(root / "AGENTS.md", "# Instructions\n")
            policy = write_text(root / "policy.json", "{}")
            baseline = write_text(root / "baseline.json", '{"findings": []}')
            for source in (instruction, policy, baseline):
                for option in ("--output", "--write-baseline"):
                    with self.subTest(source=source.name, option=option):
                        alias = root / "alias.json"
                        original = source.read_bytes()
                        try:
                            os.link(source, alias)
                        except OSError as exc:
                            self.skipTest(f"hard links unavailable: {exc}")
                        process = run_cli([
                            str(instruction), "--config", str(policy), option, str(alias)
                        ])
                        self.assertEqual(process.returncode, 2, process.stderr)
                        self.assertIn("hard links", process.stderr)
                        self.assertEqual(source.read_bytes(), original)
                        self.assertEqual(alias.read_bytes(), original)
                        self.assertEqual(process.stdout, "")
                        alias.unlink()

    def test_symbolic_link_outputs_preserve_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instruction = write_text(root / "AGENTS.md", "# Instructions\n")
            target = write_text(root / "outside.txt", "preserve this file")
            alias = root / "alias.json"
            try:
                alias.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {exc}")
            for option in ("--output", "--write-baseline"):
                with self.subTest(option=option):
                    process = run_cli([str(instruction), "--no-config", option, str(alias)])
                    self.assertEqual(process.returncode, 2, process.stderr)
                    self.assertIn("symbolic links", process.stderr)
                    self.assertEqual(target.read_text(encoding="utf-8"), "preserve this file")
                    self.assertTrue(alias.is_symlink())

    def test_ordinary_existing_outputs_can_still_be_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instruction = write_text(root / "AGENTS.md", "# Instructions\n")
            for option in ("--output", "--write-baseline"):
                with self.subTest(option=option):
                    output = write_text(root / "report.json", "old report")
                    process = run_cli([
                        str(instruction), "--no-config", "--format", "json", option, str(output)
                    ])
                    self.assertEqual(process.returncode, 0, process.stderr)
                    self.assertIn('"findings"', output.read_text(encoding="utf-8"))

    def test_deep_baselines_fail_cleanly_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instruction = write_text(root / "AGENTS.md", "# Instructions\n")
            baseline = root / "baseline.json"
            output = write_text(root / "report.json", "previous report")
            for value in ("[" * 20000 + "]" * 20000,
                          '{"x":' * 20000 + "0" + "}" * 20000):
                with self.subTest(prefix=value[:8]):
                    write_text(baseline, value)
                    process = run_cli([
                        str(instruction), "--no-config", "--baseline", str(baseline),
                        "--output", str(output)
                    ])
                    self.assertEqual(process.returncode, 2, process.stderr)
                    self.assertIn("nesting exceeds the parser limit", process.stderr)
                    self.assertNotIn("Traceback", process.stderr)
                    self.assertEqual(process.stdout, "")
                    self.assertEqual(baseline.read_text(encoding="utf-8"), value)
                    self.assertEqual(output.read_text(encoding="utf-8"), "previous report")
