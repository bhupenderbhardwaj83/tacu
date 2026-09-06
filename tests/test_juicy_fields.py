"""Field-named credentials: aliases, origin, context, scoring and report naming.

The detector's job is not to find the word "password". It is to tell a secret
from the name of a secret, and to say so with a score rather than a guess.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tacu import juicyfields
from tacu.juicy import detect_juicy
from tacu.juicyscan import (
    apply_path_context, project_of, report_basename, report_stamp,
    root_is_single_project, stamp_of,
)


def kinds(text: str) -> list[tuple[str, str, str]]:
    return [(item.kind, item.value, item.confidence) for item in detect_juicy(text)]


def found(text: str, kind: str) -> list[tuple[str, str, str]]:
    return [item for item in kinds(text) if item[0] == kind]


class ValueOriginTests(unittest.TestCase):
    """Only a literal can be a hard-coded secret."""

    def test_a_secret_read_from_the_environment_is_not_a_hard_coded_secret(self) -> None:
        for line in ('password = os.getenv("DB_PASSWORD")',
                     'password = "${DB_PASSWORD}"',
                     'password = config.password',
                     'password = get_secret()',
                     'DB_PASS=$DATABASE_PASSWORD',
                     'password = System.Environment.GetEnvironmentVariable("P")'):
            with self.subTest(line=line):
                self.assertEqual(found(line, "password"), [], line)

    def test_a_literal_is_reported(self) -> None:
        self.assertEqual(found('password = "Xv9!qA38zkP"', "password"),
                         [("password", "Xv9!qA38zkP", "high")])

    def test_an_interpolated_string_is_built_at_run_time_not_stored(self) -> None:
        self.assertEqual(found('user = f"Environment: {snapshot}"', "username"), [])

    def test_placeholders_are_not_credentials(self) -> None:
        for value in ("REPLACE_ME", "changeme", "your_password", "<password>",
                      "xxxxxxxx", "example", "TODO", "********"):
            with self.subTest(value=value):
                self.assertEqual(found(f'password = "{value}"', "password"), [], value)

    def test_origin_is_named_not_merely_scored(self) -> None:
        self.assertEqual(juicyfields.classify_origin('os.getenv("X")')[0],
                         juicyfields.ENVIRONMENT)
        self.assertEqual(juicyfields.classify_origin('"Xv9!qA38zkP"')[0],
                         juicyfields.LITERAL)
        self.assertEqual(juicyfields.classify_origin("get_secret()")[0],
                         juicyfields.CALL)
        self.assertEqual(juicyfields.classify_origin("config.password")[0],
                         juicyfields.REFERENCE)
        self.assertEqual(juicyfields.classify_origin('"changeme"')[0],
                         juicyfields.PLACEHOLDER)


class AliasTests(unittest.TestCase):
    """Find the field however it is spelled, without matching inside a word."""

    def test_short_and_prefixed_aliases_are_found(self) -> None:
        for line in ('const pw = "A9df#3!Kd";',
                     'pwd => "Tq82!zLm9"',
                     'pass = "Zk91#mQx4"',
                     'passphrase: "Rr7$vNq2wE"',
                     'db_password="Pr0d!Secret9x"',
                     'smtp_password = "Mx8#qWe7z"',
                     'SmtpPassword = "Mx8#qWe7zLp"',
                     '"DbPassword": "Zx91#kQm4"',
                     '$Password = "Wq7!nMx3z"'):
            with self.subTest(line=line):
                self.assertTrue(found(line, "password"), line)

    def test_an_alias_inside_another_word_is_not_a_field(self) -> None:
        for line in ("bypass = true", 'compass = "north-west-x"',
                     "passenger_count = 4", "password_policy = strong"):
            with self.subTest(line=line):
                self.assertEqual(found(line, "password"), [], line)

    def test_xml_configuration_carries_credentials_too(self) -> None:
        # The shapes an ASP.NET Web.config actually uses.
        self.assertTrue(found("<password>Sup3r!Secret9</password>", "password"))
        self.assertTrue(found('<add key="Password" value="Pr0d!x9Qz" />', "password"))
        self.assertTrue(found('<add key="SmtpPassword" value="Mx8#qWe7zLp" />', "password"))
        self.assertTrue(found('<add key="ApiKey" value="T7k9Qx82mPL0Zv3Nc6" />', "secret"))

    def test_a_connection_string_yields_the_login_and_the_password(self) -> None:
        line = ('connectionString="Server=sql01;Database=portal;'
                'User Id=svc_portal;Password=Pr0d!x9QzR4;"')
        self.assertTrue(found(line, "password"))
        self.assertTrue(found(line, "username"))


class NegativeContextTests(unittest.TestCase):
    def test_settings_and_counts_are_not_secrets(self) -> None:
        for line in ("max_tokens = 4096", "token_count: 512", 'tokenizer = "bpe"',
                     "minimum password length = 8", "token_limit = 100",
                     '<add key="MaxTokens" value="4096" />'):
            with self.subTest(line=line):
                self.assertEqual([item for item in kinds(line)
                                  if item[0] in {"password", "secret", "username"}], [], line)

    def test_a_negative_word_on_the_next_line_does_not_silence_this_one(self) -> None:
        # The window around a candidate is not the candidate's own line.
        self.assertTrue(found('var pw = "A9df#3!Kd";\nvar maxTokens = 4096;\n', "password"))

    def test_an_assignment_does_not_run_past_the_end_of_the_line(self) -> None:
        self.assertEqual(found('if executable == "uname":\n    return prefer()',
                               "username"), [])

    def test_a_comparison_is_not_an_assignment(self) -> None:
        self.assertEqual(found('password == "x"', "password"), [])


class CorrelationTests(unittest.TestCase):
    def test_a_username_beside_a_password_is_a_login(self) -> None:
        alone = found('username = "prod_admin"', "username")
        self.assertEqual(alone[0][2], "medium")
        together = detect_juicy('username = "prod_admin"\npassword = "A7!pQ91k"')
        levels = {item.kind: item.confidence for item in together}
        self.assertEqual(levels["username"], "high")
        self.assertEqual(levels["password"], "critical")


class NoiseTests(unittest.TestCase):
    """Things that merely look like findings."""

    def test_a_dotted_call_is_not_a_hostname(self) -> None:
        self.assertEqual(found("os.path.join(a, b)", "domain"), [])
        self.assertEqual(found("System.Environment.GetEnvironmentVariable(\"D\")", "domain"), [])
        self.assertEqual(found("item.value = 3", "domain"), [])

    def test_a_real_hostname_still_is_one(self) -> None:
        self.assertTrue(found("visit api.example.com now", "domain"))
        self.assertTrue(found("ns1.google.co.uk", "domain"))

    def test_a_connection_state_is_not_a_bank_code(self) -> None:
        self.assertEqual(found("ESTABLISHED", "swift"), [])
        self.assertTrue(found("DEUTDEFF500", "swift"))
        self.assertTrue(found("swift: DEUTDEFF", "swift"))

    def test_source_code_is_not_a_csv_of_credentials(self) -> None:
        # A docstring with a comma once became a CSV header, and every line
        # below it became a credential.
        source = Path(__file__).resolve().parents[1] / "src" / "tacu" / "acceptance.py"
        text = source.read_text(encoding="utf-8")
        self.assertEqual([item for item in kinds(text)
                          if item[0] in {"password", "username", "secret"}], [])

    def test_a_real_csv_still_reports_its_credential_columns(self) -> None:
        table = "name,email,password\nada,ada@corp.io,Zx91#kQm4\nbob,bob@corp.io,Qw82!pLm3\n"
        self.assertTrue(found(table, "password"))
        self.assertTrue(found(table, "email"))


class PathContextTests(unittest.TestCase):
    def test_where_a_file_lives_argues_about_the_finding(self) -> None:
        self.assertGreater(juicyfields.path_adjustment("service/.env"), 0)
        self.assertLess(juicyfields.path_adjustment("tests/test_login.py"), 0)
        self.assertLess(juicyfields.path_adjustment("docs/setup.md"), 0)
        self.assertEqual(juicyfields.path_adjustment("src/app/main.py"), 0)

    def test_a_test_directory_lowers_confidence_but_never_silences(self) -> None:
        finding = detect_juicy('password = "Xv9!qA38zkP"')[0]
        lowered = apply_path_context(finding, "tests/test_login.py")
        self.assertEqual(lowered.confidence, "medium")
        raised = apply_path_context(finding, "service/.env")
        self.assertEqual(raised.confidence, "critical")


class ReportNamingTests(unittest.TestCase):
    def test_the_stamp_is_indian_time_in_the_agreed_shape(self) -> None:
        from datetime import datetime, timezone

        # 2026-09-06 08:15 UTC is 13:45 IST the same day.
        moment = datetime(2026, 9, 6, 8, 15, tzinfo=timezone.utc)
        self.assertEqual(report_stamp(moment), "06_Sep_2026_1345_IST")

    def test_a_report_is_named_for_its_project_and_its_run(self) -> None:
        name = report_basename("My Portal", "06_Sep_2026_1345_IST")
        self.assertEqual(name, "_Juicy_My_Portal_06_Sep_2026_1345_IST")
        self.assertEqual(stamp_of(Path(f"{name}.csv")), "06_Sep_2026_1345_IST")


class ProjectDetectionTests(unittest.TestCase):
    def test_an_application_is_one_project_not_one_per_folder(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "MyPortal"
            (root / "Areas" / "Admin").mkdir(parents=True)
            (root / "Views").mkdir()
            (root / "Web.config").write_text("<configuration/>", encoding="utf-8")
            self.assertTrue(root_is_single_project(root))
            for relative in ("Web.config", "Areas/Admin/A.cs", "Views/Index.cshtml"):
                with self.subTest(relative=relative):
                    self.assertEqual(project_of(root / relative, root), "MyPortal")

    def test_a_folder_of_repositories_still_reports_one_project_each(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repos"
            (root / "api").mkdir(parents=True)
            (root / "web").mkdir()
            self.assertFalse(root_is_single_project(root))
            self.assertEqual(project_of(root / "api" / "main.py", root), "api")
            self.assertEqual(project_of(root / "web" / "app.js", root), "web")


if __name__ == "__main__":
    unittest.main()
