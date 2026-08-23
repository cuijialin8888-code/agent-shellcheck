from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from _support import SRC_ROOT, write_text  # noqa: F401
from agent_shellcheck.scanner import scan_paths


class RuleCatalogTests(unittest.TestCase):
    def scan(
        self,
        body: str,
        *,
        dialect: str = "console",
        target: str = "auto",
        heading: str = "Setup",
    ):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        text = f"# {heading}\n\n```{dialect}\n{body}\n```\n"
        path = write_text(Path(temporary.name) / "AGENTS.md", text)
        return scan_paths([path], target=target)

    @staticmethod
    def ids(result) -> set[str]:
        return {finding.rule_id for finding in result.findings}

    def assert_rule(
        self,
        rule_id: str,
        body: str,
        *,
        dialect: str,
        target: str = "auto",
        heading: str = "Setup",
    ) -> None:
        result = self.scan(body, dialect=dialect, target=target, heading=heading)
        self.assertIn(rule_id, self.ids(result), result.findings)

    def test_each_shell_syntax_rule_fires_in_a_conflicting_declared_fence(self) -> None:
        cases = (
            ("ASC001", "export MODE=dev", "powershell"),
            ("ASC002", "echo $env:TEMP", "bash"),
            ("ASC003", "echo %USERPROFILE%", "bash"),
            ("ASC004", "python -m tool \\", "powershell"),
            ("ASC005", "python -m tool `", "bash"),
            ("ASC006", "python -m tool ^", "bash"),
            ("ASC007", "python - <<'PY'", "powershell"),
            ("ASC008", '$value = @"', "bash"),
            ("ASC009", "tool 2>/dev/null", "powershell"),
            ("ASC010", "tool 2>$null", "bash"),
            ("ASC011", "rm -rf build", "powershell"),
            ("ASC012", "Get-ChildItem -Force", "bash"),
            ("ASC013", "rmdir /s /q build", "bash"),
            ("ASC014", "cd C:\\work\\repo", "bash"),
            ("ASC015", ".\\scripts\\build.ps1", "bash"),
            ("ASC016", "source .venv/bin/activate", "powershell"),
            ("ASC017", "echo $(git rev-parse HEAD)", "cmd"),
            ("ASC018", "source scripts/env.sh", "powershell"),
        )
        for rule_id, body, dialect in cases:
            with self.subTest(rule_id=rule_id):
                self.assert_rule(rule_id, body, dialect=dialect)

    def test_wsl_batch_rule_uses_host_as_well_as_shell(self) -> None:
        self.assert_rule(
            "ASC019",
            "./scripts/setup.cmd --quiet",
            dialect="bash",
            target="bash-wsl",
        )
        linux = self.scan(
            "./scripts/setup.cmd --quiet",
            dialect="bash",
            target="bash-linux",
        )
        self.assertNotIn("ASC019", self.ids(linux))

    def test_correct_native_examples_are_clean(self) -> None:
        cases = (
            ("export MODE=dev", "bash", "auto"),
            ("$env:MODE = 'dev'", "powershell", "auto"),
            ('set "MODE=dev"', "cmd", "auto"),
            (". .venv/bin/activate", "bash", "auto"),
            (". .\\.venv\\Scripts\\Activate.ps1", "powershell", "auto"),
            ("call .venv\\Scripts\\activate.bat", "cmd", "auto"),
            ("tool 2>/dev/null", "bash", "auto"),
            ("tool 2>$null", "powershell", "auto"),
        )
        for body, dialect, target in cases:
            with self.subTest(body=body, dialect=dialect):
                self.assertEqual(
                    self.scan(body, dialect=dialect, target=target).findings,
                    [],
                )

    def test_shell_wrappers_suppress_unparsed_nested_commands(self) -> None:
        cases = (
            ("bash -lc 'export MODE=dev'", "powershell"),
            ('pwsh -NoProfile -Command "$env:MODE=\'dev\'"', "bash"),
            ('cmd.exe /d /c "set MODE=dev"', "bash"),
        )
        for body, dialect in cases:
            with self.subTest(body=body):
                self.assertEqual(self.scan(body, dialect=dialect).findings, [])

    def test_heredoc_and_here_string_bodies_are_data_not_commands(self) -> None:
        bash = self.scan(
            "cat <<'EOF'\n$env:MODE = 'literal'\nEOF",
            dialect="bash",
        )
        powershell = self.scan(
            '$value = @"\nexport MODE=literal\n"@',
            dialect="powershell",
        )
        self.assertEqual(bash.findings, [])
        self.assertEqual(powershell.findings, [])

    def test_quoted_explanatory_values_do_not_trigger_environment_rules(self) -> None:
        bash = self.scan("echo '$env:TEMP'", dialect="bash")
        powershell = self.scan("Write-Output '%USERPROFILE%'", dialect="powershell")
        self.assertEqual(bash.findings, [])
        self.assertEqual(powershell.findings, [])

    def test_windows_interop_guards_avoid_known_false_positives(self) -> None:
        windows_tool = self.scan(
            "notepad.exe 'C:\\work\\note.txt'",
            dialect="bash",
            target="bash-wsl",
        )
        explicit_host = self.scan(
            "cmd.exe /d /c scripts\\setup.cmd",
            dialect="bash",
            target="bash-wsl",
        )
        drive_root = self.scan("Set-Location C:\\", dialect="powershell")
        self.assertEqual(windows_tool.findings, [])
        self.assertEqual(explicit_host.findings, [])
        self.assertEqual(drive_root.findings, [])

    def test_auto_unlabelled_finding_is_informational_but_portable_is_actionable(self) -> None:
        auto = self.scan("export MODE=dev", target="auto")
        portable = self.scan("export MODE=dev", target="portable")
        self.assertEqual({item.severity.label for item in auto.findings}, {"info"})
        self.assertEqual({item.severity.label for item in portable.findings}, {"error"})


if __name__ == "__main__":
    unittest.main()
