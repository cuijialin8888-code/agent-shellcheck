from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from _support import SRC_ROOT, write_text  # noqa: F401
from agent_shellcheck.discover import DiscoveryError, discover_files, read_text, relative_path


class DiscoveryTests(unittest.TestCase):
    def test_discovers_only_instruction_file_names_in_deterministic_order(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            selected = (
                write_text(root / "AGENTS.md", "# root\n"),
                write_text(root / "nested" / "CLAUDE.md", "# claude\n"),
                write_text(root / "nested" / "review.instructions.md", "# review\n"),
                write_text(root / "rules" / "python.mdc", "# cursor\n"),
                write_text(root / "skills" / "demo" / "SKILL.md", "# skill\n"),
            )
            write_text(root / "README.md", "# not an instruction file\n")
            write_text(root / "notes" / "random.md", "# not selected\n")

            result = discover_files([root])

            expected = sorted(
                (path.resolve() for path in selected),
                key=lambda path: relative_path(path, root).casefold(),
            )
            self.assertEqual(list(result.files), expected)
            self.assertEqual(result.root, root.resolve())

    def test_explicit_markdown_file_is_allowed_even_with_a_nonstandard_name(self) -> None:
        with TemporaryDirectory() as directory:
            path = write_text(Path(directory) / "custom-guide.markdown", "# Guide\n")
            result = discover_files([path])
            self.assertEqual(result.files, (path.resolve(),))
            self.assertEqual(result.root, path.parent.resolve())

    def test_dependency_and_build_directories_are_skipped(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            wanted = write_text(root / "AGENTS.md", "# wanted\n")
            for dirname in ("node_modules", ".venv", "vendor", "dist", "target", ".git"):
                write_text(root / dirname / "AGENTS.md", f"# skip {dirname}\n")

            result = discover_files([root])

            self.assertEqual(result.files, (wanted.resolve(),))

    def test_utf8_bom_unicode_and_crlf_are_read_without_changing_text(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "AGENTS.md"
            path.write_bytes("# 中文说明\r\n\r\n`python --version`\r\n".encode("utf-8-sig"))

            self.assertEqual(read_text(path), "# 中文说明\r\n\r\n`python --version`\r\n")

    def test_exclude_patterns_are_case_insensitive_and_counted(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            keep = write_text(root / "AGENTS.md", "# keep\n")
            write_text(root / "generated" / "CLAUDE.md", "# skip\n")

            result = discover_files([root], excludes=("GENERATED/*",))

            self.assertEqual(result.files, (keep.resolve(),))
            self.assertEqual(result.skipped_files, 1)

    def test_missing_input_is_a_bounded_discovery_error(self) -> None:
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "does-not-exist"
            with self.assertRaisesRegex(DiscoveryError, "does not exist|cannot be read"):
                discover_files([missing])


if __name__ == "__main__":
    unittest.main()
