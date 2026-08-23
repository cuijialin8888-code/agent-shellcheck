from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from _support import SRC_ROOT, finding_lines, findings_on_line, write_text  # noqa: F401
from agent_shellcheck.models import Severity
from agent_shellcheck.scanner import scan_paths


class ScannerRuleTests(unittest.TestCase):
    def scan(self, text: str, *, target: str = "auto"):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = write_text(Path(temporary.name) / "AGENTS.md", text)
        return scan_paths([path], target=target)

    def assert_line_has_finding(self, result, line: int) -> None:
        self.assertTrue(
            findings_on_line(result, line),
            f"expected a finding on line {line}; got "
            f"{[(item.rule_id, item.line, item.message) for item in result.findings]}",
        )

    def test_generic_block_detects_high_confidence_posix_powershell_and_cmd_syntax(self) -> None:
        result = self.scan(
            """# Setup
```console
export MODE=dev
$env:MODE = 'dev'
set MODE=dev
```
""",
            target="portable",
        )

        self.assert_line_has_finding(result, 3)
        self.assert_line_has_finding(result, 4)
        self.assert_line_has_finding(result, 5)
        affected = {
            shell
            for finding in result.findings
            for shell in finding.rule.affected_shells
        }
        self.assertIn("posix", affected)
        self.assertIn("powershell", affected)
        self.assertIn("cmd", affected)

    def test_portable_commands_are_clean_in_an_unlabelled_fence(self) -> None:
        result = self.scan(
            """# Verify
```
python -m unittest
git status
uv run python -m unittest
```
""",
            target="portable",
        )
        self.assertEqual(result.findings, [])

    def test_explicit_shell_fences_allow_native_syntax_without_line_level_noise(self) -> None:
        result = self.scan(
            """# Platform-specific alternatives

## Linux and macOS
```bash
export MODE=dev
chmod +x scripts/check.sh
```

## Windows PowerShell
```powershell
$env:MODE = 'dev'
Get-ChildItem
```

## Windows cmd
```cmd
set MODE=dev
where python
```
""",
            target="portable",
        )

        native_command_lines = {5, 6, 11, 12, 17, 18}
        noisy = [finding for finding in result.findings if finding.line in native_command_lines]
        self.assertEqual(
            noisy,
            [],
            f"native syntax in a correctly labelled fence was reported: {noisy}",
        )

    def test_dialect_mismatch_inside_an_explicit_fence_is_reported(self) -> None:
        cases = (
            ("powershell", "export MODE=dev"),
            ("bash", "$env:MODE = 'dev'"),
            ("cmd", "export MODE=dev"),
        )
        for dialect, command in cases:
            with self.subTest(dialect=dialect, command=command):
                result = self.scan(f"# Setup\n```{dialect}\n{command}\n```\n")
                self.assert_line_has_finding(result, 3)
                self.assertTrue(
                    any(finding.severity is Severity.ERROR for finding in findings_on_line(result, 3)),
                    f"dialect mismatch should be an error: {result.findings}",
                )

    def test_negative_example_headings_suppress_intentional_bad_commands(self) -> None:
        result = self.scan(
            """# Guidance

## What not to do
```bash
rm -rf $WORKSPACE
```

## 错误示例
```powershell
Remove-Item -Recurse $target
```
""",
            target="portable",
        )

        self.assertEqual(result.findings, [])

    def test_target_override_changes_which_platform_specific_command_is_actionable(self) -> None:
        posix_text = """# Setup
```
export MODE=dev
```
"""
        powershell_text = """# Setup
```
$env:MODE = 'dev'
```
"""

        self.assertEqual(self.scan(posix_text, target="posix").findings, [])
        self.assert_line_has_finding(self.scan(posix_text, target="windows"), 3)
        self.assertEqual(self.scan(powershell_text, target="windows").findings, [])
        self.assert_line_has_finding(self.scan(powershell_text, target="posix"), 3)

    def test_unclosed_shell_fence_has_an_exact_structural_finding(self) -> None:
        result = self.scan("# Setup\n\n```bash\nexport MODE=dev\n")
        at_fence = findings_on_line(result, 3)
        self.assertTrue(at_fence, result.findings)
        self.assertTrue(
            any("fence" in finding.message.casefold() for finding in at_fence),
            at_fence,
        )

    def test_minimum_severity_and_ignored_rules_filter_results(self) -> None:
        text = """# Setup
```
export MODE=dev
```
"""
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = write_text(Path(temporary.name) / "AGENTS.md", text)
        all_findings = scan_paths([path], target="portable", min_severity=Severity.INFO)
        self.assertTrue(all_findings.findings)

        error_only = scan_paths([path], target="portable", min_severity=Severity.ERROR)
        self.assertTrue(
            all(finding.severity >= Severity.ERROR for finding in error_only.findings)
        )

        ignored = scan_paths(
            [path],
            target="portable",
            ignore_rules=tuple({finding.rule_id for finding in all_findings.findings}),
        )
        self.assertEqual(ignored.findings, [])

    def test_scanning_is_read_only_and_preserves_crlf_unicode_input(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "AGENTS.md"
            original = "# 安装\r\n\r\n```console\r\nexport MODE=测试\r\n```\r\n".encode("utf-8")
            path.write_bytes(original)
            before_names = sorted(item.relative_to(root).as_posix() for item in root.rglob("*"))
            before_stat = path.stat()

            result = scan_paths([root], target="portable")

            after_names = sorted(item.relative_to(root).as_posix() for item in root.rglob("*"))
            after_stat = path.stat()
            self.assertTrue(result.findings)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(after_names, before_names)
            self.assertEqual(after_stat.st_size, before_stat.st_size)
            self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)

    def test_dependency_directories_do_not_affect_scan_counts_or_findings(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            write_text(root / "AGENTS.md", "# Clean\n`python -m unittest`\n")
            write_text(
                root / "node_modules" / "package" / "AGENTS.md",
                "```console\nexport SECRET=value\n```\n",
            )

            result = scan_paths([root], target="portable")

            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()
