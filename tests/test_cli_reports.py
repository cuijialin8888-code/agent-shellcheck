from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from _support import parsed_stdout, run_cli, write_text
from agent_shellcheck.report import _github_data, _github_property


class CliAndReportTests(unittest.TestCase):
    def test_json_is_valid_deterministic_and_sorted_across_input_order(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            a_path = write_text(root / "a" / "AGENTS.md", "```console\n$env:MODE='a'\n```\n")
            b_path = write_text(root / "b" / "SKILL.md", "```console\nexport MODE=b\n```\n")

            first = run_cli([str(b_path), str(a_path), "--format", "json", "--target", "portable"])
            second = run_cli([str(a_path), str(b_path), "--format", "json", "--target", "portable"])

            self.assertEqual(first.returncode, 1, first.stderr)
            self.assertEqual(second.returncode, 1, second.stderr)
            self.assertEqual(first.stdout, second.stdout)
            payload = parsed_stdout(first)
            self.assertEqual(payload["schemaVersion"], 1)
            self.assertEqual(payload["tool"]["name"], "agent-shellcheck")
            self.assertEqual(payload["summary"]["filesScanned"], 2)
            findings = payload["findings"]
            self.assertGreaterEqual(len(findings), 2)
            locations = [(item["path"].casefold(), item["line"], item["ruleId"]) for item in findings]
            self.assertEqual(locations, sorted(locations))

    def test_sarif_is_valid_deterministic_and_uses_relative_uris(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            a_path = write_text(root / "a" / "AGENTS.md", "```console\n$env:MODE='a'\n```\n")
            b_path = write_text(root / "b" / "SKILL.md", "```console\nexport MODE=b\n```\n")

            first = run_cli([str(b_path), str(a_path), "--format", "sarif", "--target", "portable"])
            second = run_cli([str(a_path), str(b_path), "--format", "sarif", "--target", "portable"])

            self.assertEqual(first.returncode, 1, first.stderr)
            self.assertEqual(second.returncode, 1, second.stderr)
            self.assertEqual(first.stdout, second.stdout)
            payload = parsed_stdout(first)
            self.assertEqual(payload["version"], "2.1.0")
            self.assertIn("sarif", payload["$schema"].casefold())
            self.assertEqual(len(payload["runs"]), 1)
            run = payload["runs"][0]
            self.assertEqual(run["tool"]["driver"]["name"], "agent-shellcheck")
            self.assertTrue(run["tool"]["driver"]["rules"])
            self.assertTrue(run["results"])
            uris = [
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for result in run["results"]
            ]
            self.assertTrue(all(not Path(uri).is_absolute() for uri in uris), uris)
            self.assertTrue(all("\\" not in uri for uri in uris), uris)

    def test_cli_exit_codes_distinguish_clean_findings_and_usage_errors(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            clean = write_text(root / "clean.md", "# Verify\n`python -m unittest`\n")
            broken = write_text(root / "broken.md", "```console\nexport MODE=dev\n```\n")

            clean_process = run_cli([str(clean), "--format", "json", "--target", "portable"])
            finding_process = run_cli([str(broken), "--format", "json", "--target", "portable"])
            usage_process = run_cli([str(root / "missing.md"), "--format", "json"])

            self.assertEqual(clean_process.returncode, 0, clean_process.stderr)
            self.assertEqual(finding_process.returncode, 1, finding_process.stderr)
            self.assertEqual(usage_process.returncode, 2, usage_process.stderr)
            self.assertEqual(parsed_stdout(clean_process)["summary"]["findingCount"], 0)
            self.assertGreater(parsed_stdout(finding_process)["summary"]["findingCount"], 0)
            self.assertTrue(usage_process.stderr.strip())

    def test_cli_ignore_rule_can_make_a_known_finding_non_blocking(self) -> None:
        with TemporaryDirectory() as directory:
            path = write_text(Path(directory) / "AGENTS.md", "```console\nexport MODE=dev\n```\n")
            baseline = run_cli([str(path), "--format", "json", "--target", "portable"])
            self.assertEqual(baseline.returncode, 1, baseline.stderr)
            rule_id = parsed_stdout(baseline)["findings"][0]["ruleId"]

            ignored = run_cli(
                [
                    str(path),
                    "--format",
                    "json",
                    "--target",
                    "portable",
                    "--ignore",
                    rule_id,
                ]
            )

            self.assertEqual(ignored.returncode, 0, ignored.stderr)
            self.assertEqual(parsed_stdout(ignored)["summary"]["findingCount"], 0)

    def test_fail_on_uses_findings_hidden_by_minimum_severity(self) -> None:
        with TemporaryDirectory() as directory:
            path = write_text(
                Path(directory) / "AGENTS.md",
                "```bash\ncat C:\\workspace\\instructions.md\n```\n",
            )

            process = run_cli(
                [
                    str(path),
                    "--format",
                    "json",
                    "--min-severity",
                    "error",
                    "--fail-on",
                    "warning",
                ]
            )

            self.assertEqual(process.returncode, 1, process.stderr)
            self.assertEqual(parsed_stdout(process)["summary"]["findingCount"], 0)

    def test_github_format_emits_native_annotations_with_escaped_properties(self) -> None:
        with TemporaryDirectory() as directory:
            path = write_text(
                Path(directory) / "bad,name.md",
                "```powershell\nexport MODE=dev\n```\n",
            )

            process = run_cli([str(path), "--format", "github"])

            self.assertEqual(process.returncode, 1, process.stderr)
            self.assertIn("::error file=bad%2Cname.md,line=2,col=1,title=ASC001::", process.stdout)
            self.assertIn("agent-shellcheck: 1 error", process.stdout)

    def test_github_workflow_commands_escape_control_sequences(self) -> None:
        self.assertEqual(
            _github_data("100%\r\n::warning"),
            "100%25%0D%0A::warning",
        )
        self.assertEqual(
            _github_property("C:\\repo,docs"),
            "C%3A\\repo%2Cdocs",
        )


if __name__ == "__main__":
    unittest.main()
