from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from _support import parsed_stdout, run_cli, write_text
from agent_shellcheck.config import ConfigError, find_project_config, load_project_config


class ProjectConfigTests(unittest.TestCase):
    def test_auto_config_applies_paths_target_and_ignore_policy(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_text(root / "instructions" / "AGENTS.md", "```console\nexport MODE=dev\n```\n")
            write_text(
                root / ".agent-shellcheck.json",
                json.dumps(
                    {
                        "version": 1,
                        "paths": ["instructions"],
                        "target": "portable",
                        "ignore": ["ASC001"],
                        "failOn": "warning",
                    }
                ),
            )

            process = run_cli(["--format", "json"], cwd=root)

            self.assertEqual(process.returncode, 0, process.stderr)
            payload = parsed_stdout(process)
            self.assertEqual(payload["target"], "portable")
            self.assertEqual(payload["summary"]["filesScanned"], 1)
            self.assertEqual(payload["summary"]["findingCount"], 0)

    def test_cli_values_override_config_policy(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_text(root / "AGENTS.md", "```console\nexport MODE=dev\n```\n")
            write_text(
                root / ".agent-shellcheck.json",
                json.dumps({"version": 1, "target": "portable", "failOn": "error"}),
            )

            process = run_cli(["--target", "bash-linux", "--format", "json"], cwd=root)

            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(parsed_stdout(process)["target"], "bash-linux")

    def test_show_config_prints_effective_policy_without_scanning(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = write_text(
                root / "policy.json",
                json.dumps({"version": 1, "target": "portable", "maxFiles": 25}),
            )

            process = run_cli(["--config", str(config_path), "--show-config"], cwd=root)

            self.assertEqual(process.returncode, 0, process.stderr)
            payload = parsed_stdout(process)
            self.assertEqual(payload["target"], "portable")
            self.assertEqual(payload["maxFiles"], 25)
            self.assertEqual(Path(payload["configFile"]), config_path.resolve())

    def test_no_config_bypasses_a_malformed_discovered_file(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_text(root / ".agent-shellcheck.json", "{not-json")
            clean = write_text(root / "AGENTS.md", "# Verify\n`python -m unittest`\n")

            process = run_cli([str(clean), "--no-config", "--format", "json"], cwd=root)

            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(parsed_stdout(process)["summary"]["findingCount"], 0)

    def test_invalid_or_unknown_config_values_fail_with_exit_two(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_text(root / ".agent-shellcheck.json", json.dumps({"typoTarget": "portable"}))

            process = run_cli(["--show-config"], cwd=root)

            self.assertEqual(process.returncode, 2)
            self.assertIn("unknown configuration key", process.stderr)

    def test_config_discovery_stops_at_repository_root(self) -> None:
        with TemporaryDirectory() as directory:
            outer = Path(directory)
            write_text(outer / ".agent-shellcheck.json", "{}")
            repo = outer / "repo"
            (repo / ".git").mkdir(parents=True)
            child = repo / "nested"
            child.mkdir()

            self.assertIsNone(find_project_config(child))

    def test_loader_rejects_invalid_list_and_bound_values(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_text(
                root / ".agent-shellcheck.json",
                json.dumps({"version": 1, "ignore": "ASC001", "maxFiles": 0}),
            )

            with self.assertRaises(ConfigError):
                load_project_config(explicit=path, cwd=root)

    def test_unknown_config_rule_is_rejected_even_when_cli_ignore_is_present(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_text(root / "AGENTS.md", "# clean\n")
            write_text(
                root / ".agent-shellcheck.json",
                json.dumps({"version": 1, "ignore": ["ASC999"]}),
            )

            process = run_cli(["--ignore", "ASC001", "--show-config"], cwd=root)

            self.assertEqual(process.returncode, 2)
            self.assertIn("unknown rule ID in configuration: ASC999", process.stderr)

    def test_loader_rejects_non_integer_version_and_non_string_schema(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            version_path = write_text(root / "version.json", json.dumps({"version": 1.0}))
            schema_path = write_text(root / "schema.json", json.dumps({"$schema": 7}))

            with self.assertRaises(ConfigError):
                load_project_config(explicit=version_path, cwd=root)
            with self.assertRaises(ConfigError):
                load_project_config(explicit=schema_path, cwd=root)

    def test_configured_paths_cannot_escape_the_policy_directory(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for value in ("../outside", str(root.resolve())):
                with self.subTest(value=value):
                    write_text(
                        root / ".agent-shellcheck.json",
                        json.dumps({"version": 1, "paths": [value]}),
                    )

                    process = run_cli(["--show-config"], cwd=root)

                    self.assertEqual(process.returncode, 2)
                    self.assertIn("configured path", process.stderr)

    def test_github_annotations_keep_configured_subdirectory_prefix(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            write_text(root / "docs" / "AGENTS.md", "```powershell\nexport MODE=dev\n```\n")
            nested = root / "nested"
            nested.mkdir()
            write_text(
                root / ".agent-shellcheck.json",
                json.dumps({"version": 1, "paths": ["docs"], "target": "portable"}),
            )

            unrelated_workspace = Path(__file__).resolve().parents[1]
            with patch.dict(os.environ, {"GITHUB_WORKSPACE": str(unrelated_workspace)}):
                process = run_cli(["--format", "github"], cwd=nested)

            self.assertEqual(process.returncode, 1, process.stderr)
            self.assertIn("file=docs/AGENTS.md,line=2,col=1", process.stdout)


if __name__ == "__main__":
    unittest.main()
