"""Counting and naming what is already on the page needs no model.

Asking gemma4:12b to retype 55 filenames took 342 seconds across three budgets
and produced nothing at all. Reading them takes no measurable time and cannot be
wrong, which is the whole argument for deterministic tools before inference.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu.companion import enumeration_answer

LISTING = """total 48
drwxr-xr-x  6 me staff   192 Sep  7 10:00 .
drwxr-xr-x 20 me staff   640 Sep  7 10:00 ..
-rw-r--r--  1 me staff  1024 Sep  7 10:00 alpha.txt
-rw-r--r--  1 me staff  2048 Sep  7 10:00 beta report.pdf
drwxr-xr-x  2 me staff    64 Sep  7 10:00 nested
-rw-r--r--  1 me staff   512 Sep  7 10:00 gamma.md
lrwxr-xr-x  1 me staff    11 Sep  7 10:00 shortcut -> alpha.txt
"""


class CountingTests(unittest.TestCase):
    def test_files_are_counted_without_directories_or_dot_entries(self) -> None:
        answer = enumeration_answer("how many files are there in the command output", LISTING)
        self.assertIsNotNone(answer)
        # alpha, beta report, gamma, shortcut — "nested", "." and ".." excluded.
        self.assertIn("There are 4 files", answer)
        self.assertIn("1 directories", answer)

    def test_names_are_all_listed_when_asked(self) -> None:
        answer = enumeration_answer(
            "how many files are there in the command output show their names", LISTING)
        self.assertIn("4. shortcut", answer)
        for name in ("alpha.txt", "beta report.pdf", "gamma.md", "shortcut"):
            with self.subTest(name=name):
                self.assertIn(name, answer)
        self.assertNotIn("nested", answer)

    def test_a_name_with_spaces_survives(self) -> None:
        answer = enumeration_answer("list the files", LISTING)
        self.assertIn("beta report.pdf", answer)

    def test_a_symlink_target_is_not_part_of_the_name(self) -> None:
        answer = enumeration_answer("list the files", LISTING)
        self.assertNotIn("-> alpha.txt", answer)

    def test_entries_means_directories_too(self) -> None:
        answer = enumeration_answer("how many entries are in the output", LISTING)
        self.assertIn("There are 5 entries", answer)

    def test_the_headline_names_what_was_counted(self) -> None:
        files = enumeration_answer("how many files are there", LISTING)
        dirs = enumeration_answer("how many directories are there", LISTING)
        self.assertTrue(files.startswith("There are 4 files"), files)
        self.assertTrue(dirs.startswith("There are 1 directories"), dirs)


class TargetTests(unittest.TestCase):
    """What is being counted must be read from the question, not assumed.

    "How many folders not files are there and name them all" was answered with
    the file list and the file count — instant, confident, and wrong.
    """

    def test_folders_not_files_counts_folders(self) -> None:
        answer = enumeration_answer(
            "how many folders not files are there and name them all", LISTING)
        self.assertIsNotNone(answer)
        self.assertIn("1 directories", answer)
        self.assertIn("nested", answer)
        self.assertNotIn("alpha.txt", answer)

    def test_files_not_folders_counts_files(self) -> None:
        answer = enumeration_answer("how many files not folders are there", LISTING)
        self.assertIn("4 files", answer)

    def test_directories_asked_plainly(self) -> None:
        for question in ("how many directories are there",
                         "list the folders",
                         "name all the directories",
                         "count the subdirectories"):
            with self.subTest(question=question):
                answer = enumeration_answer(question, LISTING)
                self.assertIsNotNone(answer, question)
                self.assertIn("directories", answer)
                self.assertNotIn("4 files in", answer)

    def test_an_ambiguous_subject_goes_to_the_model(self) -> None:
        # "files and folders" names both without excluding either; guessing which
        # one is meant is exactly the mistake this refuses to repeat.
        self.assertIsNone(enumeration_answer("how many files and folders are there", LISTING))

    def test_a_question_naming_no_subject_goes_to_the_model(self) -> None:
        self.assertIsNone(enumeration_answer("how many are there", LISTING))
        self.assertIsNone(enumeration_answer("count them", LISTING))


class RestraintTests(unittest.TestCase):
    """A selective question needs judgement and must reach the model."""

    def test_a_filtered_question_is_left_to_the_model(self) -> None:
        for question in ("which database ports are open in this output",
                         "how many files are larger than 1MB",
                         "list the files containing report",
                         "show only the pdf files",
                         "which of these failed"):
            with self.subTest(question=question):
                self.assertIsNone(enumeration_answer(question, LISTING), question)

    def test_text_that_is_not_a_listing_is_left_alone(self) -> None:
        prose = "The quick brown fox\njumped over the lazy dog\nand kept running.\n"
        self.assertIsNone(enumeration_answer("how many lines are there", prose))

    def test_a_question_that_asks_nothing_countable_is_left_alone(self) -> None:
        self.assertIsNone(enumeration_answer("summarise this", LISTING))
        self.assertIsNone(enumeration_answer("", LISTING))


class LadderTests(unittest.TestCase):
    def test_the_ladder_has_no_wasted_middle_rung(self) -> None:
        from tacu.providers import _MAX_NUM_PREDICT, OllamaProvider

        client = OllamaProvider("http://localhost:11434", "test-model", 30)
        budgets = client.reply_budgets()
        # A model looping on its own reasoning loops at every budget; a middle
        # attempt only spent another minute before failing the same way.
        self.assertEqual(budgets, [client.num_predict, _MAX_NUM_PREDICT])


if __name__ == "__main__":
    unittest.main()
