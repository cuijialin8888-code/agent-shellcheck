from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from _support import run_cli, write_text
from agent_shellcheck.baseline import BaselineError, load_baseline
from agent_shellcheck.config import ConfigError, load_project_config
from agent_shellcheck.discover import DiscoveryError, discover_files, read_text
from agent_shellcheck.scanner import scan_paths


class InputBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_hidden_directory_excludes_preserve_leading_dots(self) -> None:
        keep = write_text(self.root / "AGENTS.md", "# keep\n")
        write_text(self.root / ".github" / "nested" / "review.instructions.md", "# skip\n")
        for pattern in (".github/**", "./.github/**", ".\\.github\\**"):
            with self.subTest(pattern=pattern):
                result = discover_files([self.root], excludes=[pattern])
                self.assertEqual(result.files, (keep.resolve(),))
                self.assertEqual(result.skipped_files, 1)

    def test_explicit_files_respect_exclusion_patterns(self) -> None:
        keep = write_text(self.root / "keep.md", "# keep\n")
        drop = write_text(self.root / "drop.md", "# skip\n")
        result = discover_files([keep, drop], excludes=["DROP.MD"])
        self.assertEqual(result.files, (keep.resolve(),))
        self.assertEqual(result.skipped_files, 1)

    def test_explicit_files_cannot_bypass_the_file_cap(self) -> None:
        first = write_text(self.root / "first.md", "# first\n")
        second = write_text(self.root / "second.md", "# second\n")
        with self.assertRaisesRegex(DiscoveryError, "more than 1"):
            discover_files([first, second], max_files=1)

    def test_mixed_inputs_obey_file_cap_in_either_order(self) -> None:
        first = write_text(self.root / "first.md", "# first\n")
        nested = self.root / "nested"
        write_text(nested / "AGENTS.md", "# second\n")
        for inputs in ([first, nested], [nested, first]):
            with self.subTest(inputs=inputs):
                with self.assertRaisesRegex(DiscoveryError, "more than 1"):
                    discover_files(inputs, max_files=1)

    def test_duplicate_explicit_inputs_count_once(self) -> None:
        path = write_text(self.root / "AGENTS.md", "# same\n")
        self.assertEqual(discover_files([path, path], max_files=1).files, (path.resolve(),))

    def test_file_cap_requires_a_positive_integer(self) -> None:
        for limit in (True, False, 0, -1, 1.5, "1", None):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(DiscoveryError, "positive integer"):
                    discover_files([self.root], max_files=limit)
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    scan_paths([self.root], max_files=limit)

    def test_explicit_oversized_input_fails_instead_of_reporting_clean(self) -> None:
        path = write_text(self.root / "AGENTS.md", "x" * 17)
        with patch("agent_shellcheck.discover.MAX_FILE_BYTES", 16):
            with self.assertRaisesRegex(DiscoveryError, "larger than 16"):
                discover_files([path])

    def test_directory_discovery_still_skips_oversized_files(self) -> None:
        write_text(self.root / "AGENTS.md", "x" * 17)
        with patch("agent_shellcheck.discover.MAX_FILE_BYTES", 16):
            result = discover_files([self.root])
        self.assertEqual(result.files, ())
        self.assertEqual(result.skipped_files, 1)

    def test_instruction_read_accepts_exact_cap_and_rejects_one_byte_more(self) -> None:
        path = write_text(self.root / "AGENTS.md", "x" * 16)
        with patch("agent_shellcheck.discover.MAX_FILE_BYTES", 16):
            self.assertEqual(read_text(path), "x" * 16)
            path.write_bytes(b"x" * 17)
            with self.assertRaisesRegex(DiscoveryError, "larger than 16"):
                read_text(path)

    def test_case_fold_ties_have_an_exact_path_tiebreaker(self) -> None:
        upper = write_text(self.root / "AGENTS.md", "# upper\n")
        lower = write_text(self.root / "agents.md", "# lower\n")
        if upper.samefile(lower):
            self.skipTest("filesystem does not support distinct case-only filenames")
        self.assertEqual(discover_files([lower, upper]).files,
                         (upper.resolve(), lower.resolve()))

    def test_nonregular_inputs_are_rejected_before_reading(self) -> None:
        with patch.object(Path, "open") as opening:
            with self.assertRaisesRegex(DiscoveryError, "regular file"):
                read_text(self.root)
            with self.assertRaisesRegex(BaselineError, "regular file"):
                load_baseline(self.root)
            opening.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes unavailable")
    def test_named_pipes_are_skipped_and_never_opened(self) -> None:
        pipe = self.root / "AGENTS.md"
        os.mkfifo(pipe)
        with self.assertRaisesRegex(DiscoveryError, "regular file or directory"):
            discover_files([pipe])
        result = discover_files([self.root])
        self.assertEqual(result.files, ())
        self.assertEqual(result.skipped_files, 1)
        with patch.object(Path, "open") as opening:
            with self.assertRaisesRegex(DiscoveryError, "regular file"):
                read_text(pipe)
            with self.assertRaisesRegex(BaselineError, "regular file"):
                load_baseline(pipe)
            opening.assert_not_called()

    def test_baseline_read_is_bounded_even_after_a_stale_size_check(self) -> None:
        path = write_text(self.root / "baseline.json", '{"findings": []}' + " " * 64)
        stale = SimpleNamespace(st_mode=stat.S_IFREG, st_size=1)
        with patch("agent_shellcheck.baseline.MAX_BASELINE_BYTES", 32):
            with patch.object(Path, "stat", return_value=stale):
                with self.assertRaisesRegex(BaselineError, "grew beyond 32"):
                    load_baseline(path)

    def test_baseline_utf8_bom_and_normal_findings_are_preserved(self) -> None:
        path = self.root / "baseline.json"
        path.write_bytes(json.dumps({"findings": [{
            "ruleId": "ASC001", "path": "nested\\AGENTS.md",
            "message": "message", "evidence": "evidence"
        }]}).encode("utf-8-sig"))
        self.assertEqual(load_baseline(path),
                         {("ASC001", "nested/AGENTS.md", "message", "evidence")})

    def test_deep_configuration_fails_cleanly_without_output_writes(self) -> None:
        instruction = write_text(self.root / "AGENTS.md", "# instructions\n")
        policy = write_text(self.root / "policy.json", "[" * 20000 + "]" * 20000)
        output = write_text(self.root / "report.json", "preserve this report")
        with self.assertRaisesRegex(ConfigError, "nesting exceeds the parser limit"):
            load_project_config(explicit=policy)
        process = run_cli([str(instruction), "--config", str(policy), "--output", str(output)])
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertIn("nesting exceeds the parser limit", process.stderr)
        self.assertNotIn("Traceback", process.stderr)
        self.assertEqual(process.stdout, "")
        self.assertEqual(output.read_text(encoding="utf-8"), "preserve this report")

    def test_json_integer_limits_are_normalized_for_policy_and_baseline(self) -> None:
        limit = getattr(sys, "get_int_max_str_digits", lambda: 0)()
        if not limit or limit > 100000:
            self.skipTest("interpreter has no practical decimal integer parser cap")
        number = "9" * (limit + 1)
        policy = write_text(self.root / "policy.json", '{"maxFiles":' + number + "}")
        baseline = write_text(self.root / "baseline.json",
                              '{"findings": [], "extra":' + number + "}")
        with self.assertRaisesRegex(ConfigError, "JSON exceeds the parser limits"):
            load_project_config(explicit=policy)
        with self.assertRaisesRegex(BaselineError, "JSON exceeds the parser limits"):
            load_baseline(baseline)


if __name__ == "__main__":
    unittest.main()
