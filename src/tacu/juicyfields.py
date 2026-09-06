"""Field-named credentials: aliases, value origin, and a score instead of a guess.

A detector built on exact field names finds `password` and misses `pw`, `pass`,
`db_password` and `<password>`. A detector built on loose names finds `bypass`
and `max_tokens`. Neither is useful, so nothing here matches a name on its own:
a candidate is an alias *at a word boundary*, an assignment, and a value — and
the value then has to survive being classified.

The classification is the part that matters. `password = os.getenv("DB_PASS")`
and `password = "Xv9!qA38zkP"` look identical to a regex and are opposites to a
reader: one names a secret, the other *is* one. Origin is decided first, and
only a literal can be a hard-coded secret.

Scores are additive and explainable rather than a single yes/no, so a finding
can say why it is a finding.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# ---------------------------------------------------------------------------
# Aliases — the words people actually use for these fields
# ---------------------------------------------------------------------------

PASSWORD_ALIASES = (
    "password", "passwd", "pass", "pwd", "pw", "passcode", "passphrase",
    "login_password", "user_password", "db_password", "db_pass",
    "database_password", "admin_password", "smtp_password", "ftp_password",
    "ssh_password", "auth_password", "root_password", "master_password",
)
USERNAME_ALIASES = (
    "username", "user_name", "uname", "usr", "login", "login_name",
    "login_user", "account_name", "account_user", "userid", "user_id",
    "admin_user", "db_user", "db_username", "database_user", "sql_user",
    "smtp_user", "ftp_user", "ssh_user", "user", "account",
)
SECRET_ALIASES = (
    "api_key", "apikey", "api-key", "api_secret", "client_secret", "app_secret",
    "application_secret", "consumer_secret", "signing_secret", "shared_secret",
    "access_key", "access_key_id", "secret_key", "private_key", "secret",
    "credential", "credentials", "creds", "authkey", "auth_key",
    "aws_access_key", "aws_access_key_id", "aws_secret_access_key",
    "azure_client_secret", "tenant_secret", "subscription_key", "gcp_key",
    "google_api_key", "service_account_key", "encryption_key", "signing_key",
)
TOKEN_ALIASES = (
    "token", "auth_token", "access_token", "refresh_token", "bearer_token",
    "id_token", "session_token", "csrf_token", "xsrf_token", "jwt", "jwt_token",
    "oauth_token", "api_token", "personal_access_token", "pat",
)
EMAIL_ALIASES = (
    "email", "e_mail", "email_address", "mail", "mailid", "mail_id",
    "mail_address", "user_email", "contact_email", "admin_email", "support_email",
)


def _separator_tolerant(name: str) -> str:
    """`api_key` should also match `api-key`, `api.key` and `apikey`."""

    return r"[_\-. ]?".join(re.escape(part) for part in re.split(r"[_\-. ]+", name) if part)


def _title_case(name: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[_\-. ]+", name) if part)


def _alias_group(aliases: tuple[str, ...]) -> str:
    """The alias as people write it, without letting it match inside a word.

    Two branches. The first is the alias on its own, case-insensitively, and it
    must not be preceded by a name character — that is what stops `pass` from
    matching `bypass` and `compass`. The second allows a prefix, but only for
    the TitleCase spelling and only case-sensitively: `SmtpPassword` and
    `DbPassword` are everywhere in .NET and JSON config, while `bypass` cannot
    reach `Password` because its `p` is lowercase.
    """

    plain = "|".join(sorted((_separator_tolerant(name) for name in aliases),
                            key=len, reverse=True))
    camel = "|".join(sorted({re.escape(_title_case(name)) for name in aliases},
                            key=len, reverse=True))
    return rf"(?-i:[A-Za-z0-9]{{0,24}}(?:{camel}))|(?:{plain})"


PASSWORD_GROUP = _alias_group(PASSWORD_ALIASES)
USERNAME_GROUP = _alias_group(USERNAME_ALIASES)
SECRET_GROUP = _alias_group(SECRET_ALIASES + TOKEN_ALIASES)

# The value side of an assignment, in the syntaxes people actually write.
# A quoted run wins over a bare run so `"a b"` stays one value, and the language's
# string prefix (f, r, b, $, @) is part of the quote, not of the secret.
_PREFIX = r"(?:[fFrRbBuU]{1,2}|\$|@)?"
VALUE = (r"(?P<value>" + _PREFIX + r"""(?:"[^"\r\n]{0,4096}"|'[^'\r\n]{0,4096}'"""
         r"|`[^`\r\n]{0,4096}`)" + r"|[^\s,;)\]}\r\n]{1,4096})")
# Python/JS/Java/C#/YAML/JSON/TOML/properties/shell/PowerShell all reduce to
# "name, optional quote, an assignment operator, value". Horizontal space only:
# `\s*` walked over the newline after `if executable == "uname":` and took the
# next line's `return` as the value. `==` is left out for the same reason — a
# comparison reads a value, it does not set one.
ASSIGN = r"""["'\]]?[ \t]*(?:=>|::=|:=|[:=])(?!=)[ \t]*"""


def assignment_pattern(alias_group: str) -> re.Pattern[str]:
    return re.compile(
        rf"""(?ix)
        (?<![\w.-])                      # not the tail of a longer identifier
        (?P<alias>{alias_group})
        {ASSIGN}
        {VALUE}
        """
    )


def xml_element_pattern(alias_group: str) -> re.Pattern[str]:
    """<password>value</password> — how .NET and Java configs carry credentials."""

    return re.compile(
        rf"""(?ix)<\s*(?P<alias>{alias_group})\s*>(?P<value>[^<\r\n]{{1,4096}})<\s*/"""
    )


def xml_attribute_pattern(alias_group: str) -> re.Pattern[str]:
    """<add key="Password" value="..."/> — the ASP.NET appSettings shape."""

    return re.compile(
        rf"""(?ix)
        \b(?:key|name)\s*=\s*["'](?P<alias>{alias_group})["']
        \s+value\s*=\s*["'](?P<value>[^"'\r\n]{{0,4096}})["']
        """
    )


# ---------------------------------------------------------------------------
# Value origin — only a literal can be a hard-coded secret
# ---------------------------------------------------------------------------

LITERAL = "literal"
ENVIRONMENT = "environment"
REFERENCE = "reference"
CALL = "call"
PLACEHOLDER = "placeholder"
EMPTY = "empty"

# Reading a secret from the environment is the correct thing to do; reporting it
# as a hard-coded secret trains people to ignore the scanner.
_ENV_READ = re.compile(
    r"""(?ix)\b(?:
        os\.environ | os\.getenv | getenv | environ\[ | process\.env |
        import\.meta\.env | Deno\.env | System\.getenv | System\.Environment |
        Environment\.GetEnvironmentVariable | ConfigurationManager\.AppSettings |
        ENV\[ | env\.  | dotenv | config\.get | configuration\[
    )"""
)
# ${VAR} $VAR %VAR% {{ var }} <%= var %> #{var} @Value("${...}")
_INTERPOLATION = re.compile(
    r"""(?x)^(?:
        \$\{[^}]*\} | \$[A-Za-z_]\w* | %[A-Za-z_]\w*% |
        \{\{[^}]*\}\} | <%[^%]*%> | \#\{[^}]*\} | \$\([^)]*\)
    )$"""
)
_CALL = re.compile(r"^[A-Za-z_][\w.$]*\s*\(")
_REFERENCE = re.compile(r"^[A-Za-z_$][\w.$\[\]'\"-]*$")

# Values that are a way of saying "put a real one here".
PLACEHOLDER_VALUES = frozenset({
    "password", "passwd", "pass", "pwd", "secret", "token", "apikey", "api_key",
    "changeme", "change_me", "changeit", "change-me", "replace_me", "replace-me",
    "replaceme", "your_password", "your-password", "your_password_here",
    "yourpassword", "example", "sample", "dummy", "placeholder", "redacted",
    "test", "testing", "foobar", "foo", "bar", "none", "null", "nil", "undefined",
    "todo", "tbd", "n/a", "na", "xxx", "xxxx", "xxxxx", "xxxxxxxx", "unset",
    "insert_here", "fill_me_in", "notset", "not_set", "value", "string",
})
# Real, but weak and almost always a default rather than a live credential.
WEAK_DEFAULTS = frozenset({
    "admin", "root", "toor", "guest", "123456", "1234", "12345678", "123456789",
    "password1", "passw0rd", "qwerty", "letmein", "welcome", "default", "public",
    "private", "manager", "system",
})
_MASKED = re.compile(r"^[x*.#\-_\s]{3,}$", re.I)
_ANGLE_OR_BRACE = re.compile(r"^(?:<[^>]*>|\[[^\]]*\]|\{[^}]*\})$")


# f"...", r'...', b"...", $"..." — the prefix belongs to the language, not the
# value, and leaving it attached made `f"Environment:` look like a literal.
_STRING_PREFIX = re.compile(r"^(?:[fFrRbBuU]{1,2}|\$|@)(?=[\"'`])")


def unquote(raw: str) -> str:
    text = _STRING_PREFIX.sub("", (raw or "").strip().rstrip(";,"))
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'`":
        return text[1:-1]
    return text


def classify_origin(raw: str) -> tuple[str, str]:
    """Say where a value came from, and hand back the value without its quotes.

    The distinction the scanner lives or dies on: a literal is a secret, a name
    of a secret is not.
    """

    text = _STRING_PREFIX.sub("", (raw or "").strip().rstrip(";,"))
    quoted = len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'`"
    inner = unquote(text)
    if quoted and re.search(r"\{[^}]*\}|\$\{|%\(", inner):
        # An interpolated string is assembled at run time, so whatever it holds
        # is not the literal sitting in the file.
        return ENVIRONMENT, inner
    if not inner:
        return EMPTY, ""
    if _INTERPOLATION.match(inner):
        return ENVIRONMENT, inner
    if _ANGLE_OR_BRACE.match(inner) or _MASKED.match(inner):
        return PLACEHOLDER, inner
    if inner.casefold() in PLACEHOLDER_VALUES:
        return PLACEHOLDER, inner
    if quoted:
        # Inside quotes the only non-literals are interpolations, handled above.
        return LITERAL, inner
    if _ENV_READ.search(inner):
        return ENVIRONMENT, inner
    if _CALL.match(inner):
        return CALL, inner
    if _REFERENCE.match(inner) and ("." in inner or "[" in inner):
        return REFERENCE, inner
    return LITERAL, inner


def is_placeholder(value: str) -> bool:
    origin, _cleaned = classify_origin(value)
    return origin in {PLACEHOLDER, EMPTY}


# ---------------------------------------------------------------------------
# Context that argues against a finding
# ---------------------------------------------------------------------------

# Names that contain an alias but describe a setting, a count or a rule.
NEGATIVE_CONTEXT = re.compile(
    r"""(?ix)\b(?:
        password[_\s-]?(?:length|policy|policies|regex|rules?|hint|strength|
                          validation|validator|confirm|confirmation|field|label|
                          prompt|expiry|expiration|history|reset|change|toggle) |
        (?:min|max|minimum|maximum)[_\s-]?(?:password|token|length) |
        token[_\s-]?(?:count|counts|limit|limits|type|types|length|size|index|
                       izer|ization|budget|usage) |
        (?:max|min)[_\s-]?tokens? |
        user[_\s-]?(?:count|list|agent|agents|interface|experience|guide|manual) |
        key[_\s-]?(?:name|names|type|types|code|codes|board|word|words|stroke) |
        mail[_\s-]?(?:server|servers|port|host|subject|template|queue|driver) |
        secret[_\s-]?(?:name|names|manager|store|scope|version|arn|ref|reference) |
        auth[_\s-]?(?:type|types|mode|scheme|method|header|url|endpoint|provider)
    )\b"""
)
# Wording around the candidate that says "this is an illustration".
# "example" as a word means an illustration; "example.com" is just a hostname
# that happens to sit on the same line, and must not silence a real credential.
DOC_CONTEXT = re.compile(
    r"""(?ix)(?<![\w.@-])(?:
        examples?(?!\.[a-z]{2,}) | e\.g\. | samples?(?!\.[a-z]{2,}) | dummy |
        placeholder | for\s+instance | documentation | docs? | tutorial |
        demos? | mocked? | fixtures? | boilerplate | scaffold
    )\b"""
)
COMMENT_LINE = re.compile(r"""^\s*(?:#|//|--|;|\*|/\*|<!--|rem\s)""", re.I)


def in_comment(line: str) -> bool:
    """A commented-out credential is still a credential — worth knowing, not worth ignoring."""

    return bool(COMMENT_LINE.match(line or ""))


def entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum((count / length) * math.log2(count / length)
                for count in Counter(value).values())


def looks_random(value: str) -> bool:
    """Structure of a generated secret rather than a word someone chose."""

    if len(value) < 12:
        return False
    classes = sum(bool(re.search(pattern, value)) for pattern in
                  (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return entropy(value) >= 3.2 and classes >= 2


# ---------------------------------------------------------------------------
# Scoring — additive, so a finding can explain itself
# ---------------------------------------------------------------------------

SCORE_ALIAS = 20
SCORE_LITERAL_ASSIGNMENT = 25
SCORE_PROVIDER_FORMAT = 35
SCORE_HIGH_ENTROPY = 10
SCORE_CREDENTIAL_PAIR = 20
SCORE_COMMENT = -10
SCORE_ACTIVE_CODE = 20
PENALTY_PLACEHOLDER = -80
PENALTY_ENVIRONMENT = -50
PENALTY_REFERENCE = -45
PENALTY_NEGATIVE_KEYWORD = -40
PENALTY_DOCUMENTATION = -25

# Report thresholds. Below the floor a candidate is not shown at all.
SUPPRESS_BELOW = 55


def level_for(score: int) -> str | None:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= SUPPRESS_BELOW:
        return "medium"
    return None


def score_field_secret(*, value: str, context: str, line: str,
                       kind: str = "password") -> tuple[int, str, str]:
    """Score one alias-and-assignment candidate.

    Returns the score, the value origin, and the value with quotes removed. A
    score below the floor means the caller should say nothing.
    """

    origin, cleaned = classify_origin(value)
    if origin == EMPTY:
        return 0, origin, cleaned

    score = SCORE_ALIAS
    if origin == LITERAL:
        score += SCORE_LITERAL_ASSIGNMENT
    elif origin == PLACEHOLDER:
        score += PENALTY_PLACEHOLDER
    elif origin == ENVIRONMENT:
        score += PENALTY_ENVIRONMENT
    elif origin in {REFERENCE, CALL}:
        score += PENALTY_REFERENCE

    folded = cleaned.casefold()
    if kind != "username" and folded in WEAK_DEFAULTS:
        # A real default credential — worth reporting, not worth calling critical.
        score += 15
    elif looks_random(cleaned):
        score += SCORE_HIGH_ENTROPY
    if kind == "password" and origin == LITERAL and len(cleaned) >= 8:
        score += 10
    if kind == "secret" and origin == LITERAL:
        # An API key is long and unguessable. A short word next to `token =` is
        # a variable name, a mode, or a state — not a credential.
        if len(cleaned) < 8:
            score -= 40
        elif len(cleaned) >= 16 and entropy(cleaned) >= 3.5:
            score += 15
    if kind == "username":
        # A username on its own is context. Paired with a password it is a
        # credential, and the correlation pass upgrades it there.
        score -= 10

    # Only the candidate's own line can disqualify it. A `maxTokens` on the next
    # line is not a reason to drop the password on this one.
    if NEGATIVE_CONTEXT.search(line or context or ""):
        score += PENALTY_NEGATIVE_KEYWORD
    if DOC_CONTEXT.search(context or ""):
        score += PENALTY_DOCUMENTATION
    score += SCORE_COMMENT if in_comment(line) else SCORE_ACTIVE_CODE
    return score, origin, cleaned


# ---------------------------------------------------------------------------
# Path context — where a file lives changes how much a finding matters
# ---------------------------------------------------------------------------

PATH_SCORES: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"(?i)(^|/)\.env(\.|$)"), 20),
    (re.compile(r"(?i)(^|/)(secrets?|credentials?)\.(ya?ml|json|toml|ini|txt)$"), 20),
    (re.compile(r"(?i)(^|/)(terraform\.tfvars|\.tfvars)$"), 20),
    (re.compile(r"(?i)(^|/)(appsettings|web|app)\.(production|prod|release)\.(json|config)$"), 18),
    (re.compile(r"(?i)(^|/)(config|settings|appsettings)\.(production|prod|live)\."), 15),
    (re.compile(r"(?i)(^|/)(web|app)\.config$"), 12),
    (re.compile(r"(?i)(^|/)(dockerfile|docker-compose[^/]*\.ya?ml|jenkinsfile)$"), 10),
    (re.compile(r"(?i)(^|/)(deployment|values)\.ya?ml$"), 10),
    (re.compile(r"(?i)(^|/)(tests?|spec|specs|__tests__|fixtures?|mocks?)/"), -25),
    (re.compile(r"(?i)(^|/)(examples?|samples?|demo|demos)/"), -30),
    (re.compile(r"(?i)(^|/)(docs?|documentation)/"), -30),
    (re.compile(r"(?i)(^|/)(node_modules|vendor|third_party|site-packages|dist|build)/"), -40),
    (re.compile(r"(?i)(^|/)readme[^/]*$"), -25),
    (re.compile(r"(?i)\.(md|rst|txt)$"), -15),
)


def path_adjustment(relative_path: str) -> int:
    """How much this location argues for or against the finding.

    A test directory lowers confidence but never silences it: secrets leak into
    tests constantly, and a scanner that skips them misses real ones.
    """

    text = (relative_path or "").replace("\\", "/")
    return sum(points for pattern, points in PATH_SCORES if pattern.search(text))
