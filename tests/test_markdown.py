from __future__ import annotations

from pathlib import Path
import unittest

from _support import SRC_ROOT  # noqa: F401 - adds src/ to sys.path
from agent_shellcheck.markdown import language_to_dialect, parse_markdown


class MarkdownParsingTests(unittest.TestCase):
    def test_language_aliases_map_to_the_expected_dialects(self) -> None:
        cases = {
            "bash": "posix",
            "SH": "posix",
            "powershell": "powershell",
            "pwsh": "powershell",
            "ps1": "powershell",
            "cmd": "cmd",
            "BAT": "cmd",
            "console": "generic",
            "": "generic",
            "python": "other",
        }
        for language, expected in cases.items():
            with self.subTest(language=language):
                self.assertEqual(language_to_dialect(language), expected)

    def test_fences_inline_commands_headings_and_coordinates(self) -> None:
        text = """# Setup

Run `python -m pip install .` before continuing.

## Windows
```powershell
PS C:\\repo> Get-ChildItem
  $env:MODE = 'dev'
```

## Linux
~~~bash
$ export MODE=dev
~~~
"""
        path = Path("AGENTS.md")
        blocks, snippets = parse_markdown(path, "AGENTS.md", text)

        self.assertEqual(len(blocks), 2)
        self.assertEqual(
            [(block.dialect, block.start_line, block.end_line, block.heading) for block in blocks],
            [
                ("powershell", 6, 9, "Setup / Windows"),
                ("posix", 12, 14, "Setup / Linux"),
            ],
        )
        self.assertTrue(all(block.closed for block in blocks))

        observed = [
            (item.line, item.column, item.text, item.dialect, item.source_kind, item.heading)
            for item in snippets
        ]
        self.assertEqual(
            observed,
            [
                (3, 6, "python -m pip install .", "generic", "inline", "Setup"),
                (7, 13, "Get-ChildItem", "powershell", "fence", "Setup / Windows"),
                (8, 3, "$env:MODE = 'dev'", "powershell", "fence", "Setup / Windows"),
                (13, 3, "export MODE=dev", "posix", "fence", "Setup / Linux"),
            ],
        )

    def test_unclosed_fence_is_retained_with_exact_start_and_content_lines(self) -> None:
        text = """# Install

```cmd
set MODE=dev
where python
"""
        blocks, snippets = parse_markdown(Path("SKILL.md"), "SKILL.md", text)

        self.assertEqual(len(blocks), 1)
        block = blocks[0]
        self.assertFalse(block.closed)
        self.assertEqual(block.start_line, 3)
        self.assertEqual(block.content_start_line, 4)
        self.assertEqual(block.end_line, 5)
        self.assertEqual(block.lines, ("set MODE=dev", "where python"))
        self.assertEqual([snippet.line for snippet in snippets], [4, 5])

    def test_non_command_inline_code_and_non_shell_fences_are_ignored(self) -> None:
        text = """Use `AGENTS.md`, `PATH`, and `https://example.test`.

```python
import os
os.remove("thing")
```
"""
        blocks, snippets = parse_markdown(Path("AGENTS.md"), "AGENTS.md", text)

        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].dialect, "other")
        self.assertEqual(snippets, [])

    def test_longer_fence_is_not_closed_by_a_shorter_marker(self) -> None:
        text = """````bash
echo first
```
rm -rf build
````
"""
        blocks, snippets = parse_markdown(Path("AGENTS.md"), "AGENTS.md", text)

        self.assertEqual(len(blocks), 1)
        self.assertTrue(blocks[0].closed)
        self.assertEqual(blocks[0].end_line, 5)
        self.assertIn("rm -rf build", blocks[0].lines)
        self.assertEqual([item.line for item in snippets if item.text == "rm -rf build"], [4])


if __name__ == "__main__":
    unittest.main()
