"""Tab completion offers files and directories exactly where one is expected.

`ti juicy CH<TAB>` answered "no more arguments". zsh's `_arguments` treats
$words[1] as the command and everything after it as that command's arguments,
so with words=(ti juicy CH) it read "juicy" as positional 1 and "CH" as an
illegal positional 2. Every branch now shifts past the subcommand(s) it has
already dispatched on before handing the rest to `_arguments`.

These drive the real shells with completion internals stubbed, so they assert
on what the completer *asks for* — a file here, a directory there, plain words
elsewhere — without needing a terminal.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu.completion import completion_script, shell_initialization

ZSH_HARNESS = r'''
source "$1"
_arguments()  { print -r -- "WORDS=${(j: :)words} CURRENT=$CURRENT SPECS=${(j:|:)@}" }
_files()      { print -r -- "FILES $*" }
_directories(){ print -r -- "DIRS $*" }
_describe()   { print -r -- "DESCRIBE $2" }
_message()    { print -r -- "MESSAGE $*" }
compadd()     { print -r -- "COMPADD" }
words=("${@:2}"); CURRENT=$#words
_tacu
'''


def _zsh(words: list[str]) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".zsh", delete=False) as init:
        init.write(shell_initialization("zsh"))
    with tempfile.NamedTemporaryFile("w", suffix=".zsh", delete=False) as harness:
        harness.write(ZSH_HARNESS)
    done = subprocess.run(["zsh", "-f", harness.name, init.name, *words],
                          capture_output=True, text=True, timeout=30)
    return done.stdout + done.stderr


def _bash(words: list[str]) -> list[str]:
    script = completion_script("bash")
    probe = (script + '\nCOMP_WORDS=("$@"); COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 )); COMPREPLY=()\n'
             '_tacu_complete 2>/dev/null || _ticu 2>/dev/null\nprintf "%s\\n" "${COMPREPLY[@]}"\n')
    done = subprocess.run(["bash", "-c", probe, "bash", *words], capture_output=True, text=True,
                          timeout=30, cwd=str(Path(__file__).resolve().parents[1]))
    return [line for line in done.stdout.splitlines() if line]


@unittest.skipUnless(shutil.which("zsh"), "zsh is not installed")
class ZshPositionTests(unittest.TestCase):
    def test_the_subcommand_is_shifted_out_before_arguments_sees_the_line(self) -> None:
        out = _zsh(["ti", "juicy", "CH"])
        self.assertIn("WORDS=juicy CH CURRENT=2", out)
        self.assertIn("1:file or directory:_files", out)

    def test_two_subcommands_are_shifted_for_tools(self) -> None:
        out = _zsh(["ti", "tools", "search", "VT=", "./not_req"])
        self.assertIn("WORDS=search VT= ./not_req CURRENT=3", out)
        self.assertIn("2:directory:_directories", out)

    def test_noglob_from_the_alias_is_shifted_too(self) -> None:
        out = _zsh(["noglob", "ti", "tools", "map", "sr"])
        self.assertIn("WORDS=map sr CURRENT=2", out)
        self.assertIn("1:directory:_directories", out)

    def test_positions_that_expect_words_do_not_offer_paths(self) -> None:
        for words in (["ti", "ask", ""], ["ti", "auto", "list", ""], ["ti", "tools", "search", ""]):
            with self.subTest(words=words):
                out = _zsh(words)
                self.assertNotIn("_files", out.split("SPECS=")[-1].split("|")[0])

    def test_the_command_and_subcommand_menus_are_untouched(self) -> None:
        self.assertIn("COMPADD", _zsh(["ti", ""]))
        self.assertIn("COMPADD", _zsh(["ti", "tools", ""]))


@unittest.skipUnless(shutil.which("bash"), "bash is not installed")
class BashPositionTests(unittest.TestCase):
    def test_a_file_position_completes_files(self) -> None:
        self.assertIn("CHANGELOG.md", _bash(["ti", "juicy", "CH"]))

    def test_a_directory_position_completes_directories(self) -> None:
        self.assertIn("src", _bash(["ti", "tools", "map", "sr"]))
        self.assertIn("tests", _bash(["ti", "tools", "search", "TODO", "te"]))

    def test_a_flag_prefix_still_completes_flags(self) -> None:
        self.assertIn("--depth", _bash(["ti", "tools", "map", "--d"]))

    def test_the_text_position_of_search_offers_nothing(self) -> None:
        self.assertEqual(_bash(["ti", "tools", "search", ""]), [])


if __name__ == "__main__":
    unittest.main()
