"""A definitive ask gets the whole answer, or is told it did not.

"How many files are there, show their names" returned "there are 31 files" and
then listed twenty of them. The count was right and the list was short, which is
the worst combination: nothing on screen said the answer was partial.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu.model_context import _compact_block


def listing(count: int) -> str:
    rows = ["total 0", "drwxr-xr-x  2 me staff   64 Sep  7 10:00 .",
            "drwxr-xr-x 20 me staff  640 Sep  7 10:00 .."]
    rows += [f"-rw-r--r--  1 me staff 0 Sep  7 10:00 report_{index}_summary.txt"
             for index in range(1, count + 1)]
    return "\n".join(rows)


class EvidenceCompletenessTests(unittest.TestCase):
    def test_everything_that_fits_the_budget_is_sent(self) -> None:
        # 34 lines is more than 24 and fewer than 48 — the range that was cut to
        # its first 24 lines with no marker and no tail.
        text = listing(31)
        compact, meta = _compact_block({"type": "text", "text": text},
                                       "how many files show their names", 20_000)
        self.assertTrue(meta.get("complete"))
        self.assertEqual(meta["kept_lines"], meta["original_lines"])
        blob = json.dumps(compact)
        missing = [n for n in range(1, 32) if f"report_{n}_summary" not in blob]
        self.assertEqual(missing, [], "the model must see every line it is asked about")

    def test_a_small_input_is_never_sampled(self) -> None:
        for count in (1, 10, 21, 22, 23, 24, 25, 40, 47, 48, 49):
            with self.subTest(files=count):
                text = listing(count)
                compact, meta = _compact_block({"type": "text", "text": text},
                                               "list the files", 20_000)
                blob = json.dumps(compact)
                self.assertTrue(meta.get("complete"), f"{count} files was sampled")
                self.assertIn(f"report_{count}_summary", blob)

    def test_input_over_the_budget_shows_both_ends_and_names_the_gap(self) -> None:
        text = listing(4_000)
        compact, meta = _compact_block({"type": "text", "text": text},
                                       "list the files", 4_000)
        blob = json.dumps(compact)
        self.assertFalse(meta.get("complete"))
        # The first and last lines both survive, and the omission is stated.
        self.assertIn("report_1_summary", blob)
        self.assertIn("report_4000_summary", blob)
        self.assertIn("omitted", blob)

    def test_the_gap_is_never_silent(self) -> None:
        compact, meta = _compact_block({"type": "text", "text": listing(4_000)},
                                       "list the files", 4_000)
        if not meta.get("complete"):
            self.assertIn("omitted", json.dumps(compact),
                          "a partial view must say that it is partial")


class ReplyBudgetTests(unittest.TestCase):
    def test_the_ceiling_leaves_room_for_a_long_listing(self) -> None:
        from tacu.providers import _MAX_NUM_PREDICT

        # 4096 was not enough to name 77 files once the model had spent tokens
        # thinking; it returned nothing at all.
        self.assertGreaterEqual(_MAX_NUM_PREDICT, 8192)

    def test_the_ladder_climbs_to_the_ceiling(self) -> None:
        from tacu.providers import _MAX_NUM_PREDICT, OllamaProvider

        client = OllamaProvider("http://localhost:11434", "test-model", 30)
        budgets = client.reply_budgets()
        self.assertEqual(budgets[-1], _MAX_NUM_PREDICT)
        self.assertEqual(budgets, sorted(budgets))

    def test_a_truncated_reply_is_retried_rather_than_shipped(self) -> None:
        from tacu.providers import OllamaProvider

        client = OllamaProvider("http://localhost:11434", "test-model", 30)
        attempts: list[int] = []

        def fake_once(model, messages, *, stream, outcome=None, num_predict=None,
                      can_retry=False):
            attempts.append(num_predict)
            record = outcome if outcome is not None else {}
            if can_retry:
                # Cut off at the limit: hold it back and let the ladder widen.
                record["truncated"] = True
                return iter(())
            return iter(["the whole answer"])

        client._chat_once = fake_once            # type: ignore[method-assign]
        text = "".join(client.chat([{"role": "user", "content": "list them"}], stream=True))
        self.assertIn("the whole answer", text)
        self.assertGreater(len(attempts), 1, "a truncated reply must be retried")
        self.assertEqual(attempts, sorted(attempts))

    def test_an_answer_truncated_at_the_ceiling_says_so(self) -> None:
        from tacu.providers import OllamaProvider

        client = OllamaProvider("http://localhost:11434", "test-model", 30)

        def always_truncated(model, messages, *, stream, outcome=None, num_predict=None,
                            can_retry=False):
            record = outcome if outcome is not None else {}
            record["truncated"] = True
            return iter(()) if can_retry else iter(["1. one\n2. two"])

        client._chat_once = always_truncated     # type: ignore[method-assign]
        text = "".join(client.chat([{"role": "user", "content": "list them"}], stream=True))
        self.assertIn("1. one", text)
        self.assertIn("incomplete", text.casefold())


class SystemPromptTests(unittest.TestCase):
    def test_the_word_cap_does_not_apply_to_lists(self) -> None:
        from tacu.cli import SYSTEM_PROMPT

        lowered = SYSTEM_PROMPT.casefold()
        self.assertIn("60 words", lowered)
        self.assertIn("that limit does not apply", lowered)
        self.assertIn("never stop a list partway", lowered)


if __name__ == "__main__":
    unittest.main()
