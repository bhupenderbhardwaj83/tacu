"""Progressive, color-segmented help and the interactive TACU tutorial."""

from __future__ import annotations

import io
import shutil
import sys
import textwrap
from contextlib import redirect_stdout
from collections.abc import Callable
from typing import Iterable

from .dataset import DEFAULT_TTL_HOURS
from .theme import PALETTE, banner, logo, paint, strip_ansi


def _heading(text: str) -> str:
    return paint(text, PALETTE.accent + PALETTE.bold)


def _command(parts: Iterable[tuple[str, str]]) -> str:
    return "".join(paint(text, color) for text, color in parts)


def _zone(title: str) -> None:
    print(paint(title, PALETTE.violet + PALETTE.bold))


_AI_SPARKLE = "✨"


_ENTRY_INDENT = "  "
_ENTRY_WIDTH = 10


def _row(name: str, primary: str, extra: str | None = None, *, ai: bool = False, width: int = 10) -> None:
    """Dense row: action · example · short why — same layout for every help topic."""

    lead = f"{_AI_SPARKLE} " if ai else ""
    left = f"  {name.ljust(width)} "
    main = f"{lead}{primary}"
    if not extra:
        print(_command(((left, PALETTE.green + PALETTE.bold), (main, PALETTE.accent))))
        return
    sep = " · "
    budget = 112
    if len(left) + len(main) + len(sep) + len(extra) <= budget:
        print(_command((
            (left, PALETTE.green + PALETTE.bold),
            (main, PALETTE.accent),
            (f"{sep}{extra}", PALETTE.muted),
        )))
        return
    print(_command(((left, PALETTE.green + PALETTE.bold), (main, PALETTE.accent))))
    print(paint(f"{' ' * len(left)}{extra}", PALETTE.muted))


_SYNTAX_COLUMN = 44
_DESCRIPTION_INDENT = 5
_MIN_TEXT_WIDTH = 40
_MAX_TEXT_WIDTH = 120


def _terminal_width() -> int:
    return shutil.get_terminal_size(fallback=(120, 24)).columns


def _entry(name: str, syntax: str, example: str, does: str, *, ai: bool = False,
           width: int | None = None) -> None:
    """Uniform help entry used by every topic.

    Line 1 pairs the shape with a runnable example:
        name   SHAPE ARG [OPT]        |  e.g. real command you can paste
    Line 2 explains what it does and when to reach for it, wrapped to the terminal.
    """

    left = f"{_ENTRY_INDENT}{name.ljust(width or _ENTRY_WIDTH)} "
    lead = f"{_AI_SPARKLE} " if ai else ""
    shape = f"{lead}{syntax}"
    # The sparkle renders two columns wide but counts as one character.
    shape_columns = len(shape) + (1 if ai else 0)

    parts: list[tuple[str, str]] = [(left, PALETTE.green + PALETTE.bold)]
    if example:
        filler = " " * max(1, _SYNTAX_COLUMN - shape_columns)
        parts.append((f"{shape}{filler}", PALETTE.accent))
        parts.append(("  |  e.g. ", PALETTE.muted))
        parts.append((example, PALETTE.yellow))
    else:
        parts.append((shape, PALETTE.accent))
    print(_command(parts))

    if does:
        indent = " " * (len(left) + _DESCRIPTION_INDENT)
        width = min(_MAX_TEXT_WIDTH, max(_MIN_TEXT_WIDTH, _terminal_width() - len(indent) - 1))
        for line in textwrap.wrap(does, width=width) or [does]:
            print(paint(f"{indent}{line}", PALETTE.muted))


def _legend(*, fields: bool = False) -> None:
    """The shape key. `fields` adds the marker only where contract inputs are shown."""

    parts = ["UPPERCASE = you supply it", "[brackets] = optional", "a|b = pick one"]
    if fields:
        parts.append("field* = required")
    print(paint("Shape: " + " · ".join(parts), PALETTE.muted))


def _more(*topics: str) -> None:
    linked = " · ".join(f"ti help {topic}" for topic in topics)
    print(paint(f"more: {linked} · ti all", PALETTE.muted))


def print_clip_help() -> None:
    """Compact clip help — avoids argparse's wide empty right column."""

    print(_heading("ti clip — clipboard tray"))
    print(paint("WHAT: A numbered tray of snippets (max 50), separate from Terminal scrollback.", PALETTE.text))
    print(paint("WHEN: Stash a command/line and paste later with Cmd/Ctrl-V.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("list", "ti clip [list]", "ti clip",
           "Shows every slot as number, label, and a short preview so you can spot the one you want.")
    _entry("add", "ti clip add TEXT [--label NAME]", "ti clip add \"nmap -sC host\"",
           "Stores TEXT in the next free slot. Give it a --label when the preview alone would not "
           "tell you what the snippet is for.")
    _entry("from turn", "ti clip add --from-turn TURN:LINE", "ti clip add --from-turn 42:3",
           "Pulls one line straight out of a retained answer into the tray, using the L### numbers "
           "printed beside that answer.")
    _entry("paste", "ti clip N", "ti clip 3",
           "Copies slot N to the OS clipboard so the next Cmd-V pastes it anywhere.")
    _entry("show", "ti clip show N", "ti clip show 3",
           "Prints the full body of slot N to stdout, which is handy when the preview is truncated "
           "or you want to pipe it somewhere.")
    _entry("edit", "ti clip edit N TEXT", "ti clip edit 3 \"new text\"",
           "Replaces the body of slot N and refreshes its auto-generated label.")
    _entry("label", "ti clip edit N --label NAME", "ti clip edit 3 --label scan",
           "Renames slot N without touching the stored text.")
    _entry("rm", "ti clip rm N", "ti clip rm 3",
           "Deletes one slot. The remaining numbers stay put, so your muscle memory keeps working.")
    _entry("search", "ti clip search TEXT", "ti clip search nmap",
           "Filters the tray by label or body text when you have more snippets than you can scan.")
    _entry("clear", "ti clip clear --yes", "ti clip clear --yes",
           "Empties the whole tray and restarts numbering at 1. The --yes is required so this "
           "cannot happen by accident.")
    _entry("via copy", "ti copy TURN:LINE --to-clip", "ti copy 42:3 --to-clip",
           "Routes an answer line into the tray instead of the OS clipboard, so you can collect "
           "several pieces before pasting any of them.")
    print()
    print(paint("Interactive: :clip · :clip 3 · :clip add text · :clip rm 3", PALETTE.muted))
    _more("copy", "review", "memory")


def print_health_help() -> None:
    """Doctor / config / model — what each command is for, with examples."""

    print(_heading("ti doctor — health & config"))
    print(paint("WHAT: Check this Mac is ready, then set model, context, and workspace.", PALETTE.text))
    print(paint("WHEN: First install, after upgrades, or when Ollama/Docker/SearXNG misbehave.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("CHECK", PALETTE.violet + PALETTE.bold))
    _entry("doctor", "ti doctor [--json]", "ti doctor",
           "Checks OS version, RAM, free disk, Ollama, installed models, the workspace, and your "
           "PATH, then reports what is missing. Add --json when a script needs the result.")
    print()
    print(paint("CONFIGURE", PALETTE.violet + PALETTE.bold))
    _entry("config", "ti config show", "ti config show",
           "Prints the settings currently in effect: which model answers, and how many past turns "
           "are replayed as context.")
    _entry("update", "ti config update [--model NAME] [--context-turns N]",
           "ti config update --model gemma4:12b-mlx --context-turns 5",
           "Saves your preferences so they survive restarts. Both flags are optional — pass only "
           "the one you want to change.")
    _entry("model", "ti model list|current|use NAME", "ti model use gemma4:12b-mlx",
           "Lists the models Ollama has installed, shows the active one, or switches to another. "
           "On Apple Silicon the MLX builds run noticeably faster.")
    _entry("setup", "ti setup [--workspace DIR]", "ti setup --workspace ~/TACU-Workspace",
           "Runs first-time setup or repairs a broken install, optionally pointing TACU at a "
           "different workspace directory.")
    print()
    print(paint("WORKSPACE", PALETTE.violet + PALETTE.bold))
    _entry("workspace", "ti workspace show|use DIR|create DIR", "ti workspace use ~/proj",
           "Sets the boundary that file tools may write inside. Everything outside it is read-only, "
           "which is what keeps ti do and ti tools safe to run.")
    _entry("enter", "ti workspace enter", "ti workspace enter",
           "Opens a subshell already inside the workspace; type exit to come back.")
    _entry("plugins", "ti plugins", "ti plugins",
           "Lists the providers and middleware currently loaded, useful when diagnosing an "
           "unexpected model or filter.")
    _entry("version", "ti version", "ti version",
           "Prints the installed TACU version.")
    print()
    print(paint("SHELL", PALETTE.violet + PALETTE.bold))
    _entry("completion", "ti completion [zsh|bash|fish]", "eval \"$(ti completion zsh)\"",
           "Prints tab-completion for the named shell. auto picks from the environment.")
    _entry("shell-init", "ti shell-init [zsh|bash|fish]", "eval \"$(ti shell-init zsh)\"",
           "Prints completion, punctuation, and ghost-prompt integration. Reload after install.")
    print()
    print(paint("Tip: ti doctor first · missing models → ti setup or ti model use …", PALETTE.muted))
    _more("workspace", "safety")


def print_syntax_help() -> None:
    """Compact recipe/cookbook help."""

    print(_heading("ti syntax — command cookbook"))
    print(paint("WHAT: Pasteable OS argv + capability ops from past ti auto / ti do runs.", PALETTE.text))
    print(paint("WHEN: You want the exact command again without re-planning.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("list", "ti syntax [list]", "ti syntax",
           "Shows the cookbook as number, capability, and the purpose or argv, so you can find a "
           "command you already proved works on this machine.")
    _entry("search", "ti syntax search TEXT", "ti syntax search cpu",
           "Filters recipes by purpose, label, or the argv itself — usually faster than scrolling "
           "the full list.")
    _entry("copy", "ti syntax N", "ti syntax 3",
           "Copies recipe N's ready-to-paste command straight to the OS clipboard.")
    _entry("show", "ti syntax show N", "ti syntax show 3",
           "Prints recipe N in full, including the capability it belongs to, without copying it.")
    _entry("via copy", "ti copy --command [N|TEXT]", "ti copy --command",
           "Copies the most recent recipe, or one selected by number or search text, from wherever "
           "you happen to be.")
    _entry("add", "ti syntax add [--label NAME] -- ARGV…", "ti syntax add -- /bin/ps -Ao pid,command",
           "Indexes a command you wrote yourself so it joins the cookbook. Everything after -- is "
           "stored verbatim as the argv.")
    _entry("seed", "ti syntax seed", "ti syntax seed",
           "Reloads the built-in host recipes, which is the fix if the cookbook looks empty or stale.")
    _entry("rm", "ti syntax rm N", "ti syntax rm 3",
           "Deletes recipe N from the cookbook.")
    print()
    print(paint("Interactive: :syntax · :syntax 3 · :syntax search dns", PALETTE.muted))
    _more("memory", "clip", "auto")


def print_review_help() -> None:
    print(_heading("ti review — retained turns"))
    print(paint("WHAT: Browse answers TACU kept (max 100).", PALETTE.text))
    print(paint("WHEN: You need a past answer, then copy a line or export it.", PALETTE.text))
    print(paint("SAME AS: ti history · ti menu · ti report", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("browse", "ti review", "ti review",
           "Opens an interactive menu of retained turns where typing filters the list as you go.")
    _entry("list", "ti review --list", "ti review --list",
           "Prints a plain table of id, model, and query — better than the menu when you want to "
           "scan or pipe the output.")
    _entry("search", "ti review search TEXT", "ti review search dns",
           "Matches your text against the question, the answer body, and the model name, so you can "
           "find a turn even when you only remember the reply.")
    _entry("alias", "ti history|menu|report …", "ti history find CPU",
           "The same browser under three other names, so whichever word comes to mind will work.")
    print()
    print(paint("THEN REUSE IT", PALETTE.violet + PALETTE.bold))
    _entry("copy", "ti copy TURN[:LINE]", "ti copy last:1",
           "Copies the turn, or one L### line from it, to the clipboard once you have found it. "
           "ti copy last is the most recent answer.")
    _entry("save", "ti save TURN --format md|txt|json", "ti save 42 --format md",
           "Exports a whole turn to a file when you want to keep it outside TACU.")
    _entry("evidence", "ti evidence [TURN]", "ti evidence 42",
           "Shows the secured raw-output artifact for a retained turn.")
    _entry("clear", "ti clear --yes", "ti clear --yes",
           "Deletes the private 100-turn memory after confirmation.")
    print()
    print(paint("Menu: type text · /dns · [a]ll · or a turn id", PALETTE.muted))
    _more("copy", "clip", "memory")


def print_copy_help() -> None:
    print(_heading("ti copy — answer lines & blocks"))
    print(paint("WHAT: Copy a retained answer (or part of it) to the OS clipboard or clip tray.", PALETTE.text))
    print(paint("WHEN: The left gutter L001… marks lines — copy uses those numbers.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("WHAT TO COPY", PALETTE.violet + PALETTE.bold))
    _entry("latest", "ti copy [last]", "ti copy last",
           "Copies the entire most recent answer. Bare ti copy and ti copy last are the same.")
    _entry("turn", "ti copy TURN", "ti copy 42",
           "Copies all of an older turn by its id, which ti review lists for you.")
    _entry("line", "ti copy TURN:LINE", "ti copy last:1",
           "Copies a single line of that turn. ti copy last:1 is L001 of the latest answer; "
           "ti copy 42:3 is L003 of an older turn. The number after the colon is the L### gutter.")
    _entry("range", "ti copy TURN:FIRST-LAST", "ti copy last:2-3",
           "Copies a span of lines in one go. Works with last or a numeric turn id.")
    _entry("block", "ti copy TURN --block N", "ti copy last --block 1",
           "Copies the Nth ``` fenced code or command block, so you get the command without the "
           "prose around it.")
    print()
    print(paint("WHERE IT GOES", PALETTE.violet + PALETTE.bold))
    _entry("to tray", "ti copy TURN:LINE --to-clip [--label NAME]", "ti copy 42:3 --to-clip",
           "Sends the selection to the clip tray rather than the OS clipboard, so it is still there "
           "later and does not disturb what you already had copied.")
    _entry("recipe", "ti copy --command [N|TEXT]", "ti copy --command",
           "Copies a command from the syntax cookbook instead of an answer — the latest one, or one "
           "picked by number or search text.")
    print()
    print(paint("Blank L### lines still count — if empty, try the next L number.", PALETTE.muted))
    _more("clip", "review", "syntax")


# Grouping and examples are presentational. Syntax and description come from each
# tool's own contract, and anything ungrouped still prints, so adding a tool cannot
# make it invisible or make this text wrong.
_TOOL_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("HOST TOOLS — facts about this machine",
     ("process", "network", "system", "application", "service", "package", "ollama")),
    ("SECURITY TOOLS — is this machine clean",
     ("forensics", "security")),
    ("CODE & CONTAINER TOOLS",
     ("git", "docker", "run_tests", "diagnostics", "inspect_symbol")),
    ("WORKSPACE TOOLS",
     ("filesystem", "shell", "task_state")),
    ("FILE CONTRACTS — behind the file commands above",
     ("repo_map", "search_code", "read_file", "write_file", "edit_file")),
)

# How you would actually reach each tool in words. A tool with no example still
# prints; it just shows the contract call instead.
_TOOL_EXAMPLES = {
    "process": "ti auto which process is consuming most CPU",
    "network": "ti auto am i connected to github.com",
    "system": "ti auto what is current date and time",
    "application": "ti auto is Docker Desktop installed",
    "service": "ti auto which services are running",
    "package": "ti auto which brew packages are outdated",
    "ollama": "ti auto list active local AI models",
    "forensics": "ti auto am i compromised",
    "security": "ti auto is this binary signed",
    "git": "ti auto summarize uncommitted git changes",
    "docker": "ti auto list docker containers",
    "run_tests": "ti auto run the tests",
    "diagnostics": "ti auto check this file for syntax errors",
    "inspect_symbol": "ti auto where is the function main defined",
    "filesystem": "ti auto find all images on Desktop",
    "shell": "ti do run the build script",
    "task_state": "ti tools run task_state --input '{\"operation\":\"show\"}'",
    "repo_map": "ti tools map . --depth 3",
    "search_code": "ti tools search TODO . --glob \"*.py\"",
    "read_file": "ti tools read README.md --start 1 --end 40",
    "write_file": "ti tools write hello.py --content \"print(1)\"",
    "edit_file": "ti tools edit app.py --old \"foo\" --new \"bar\"",
}


# The widest tool name is longer than the shared column, so this section sets its own.
_TOOL_NAME_WIDTH = 15


def _tool_shape(spec: Any) -> str:
    """The operations a tool accepts, read from its own input contract."""

    properties = (spec.input_schema or {}).get("properties") or {}
    operations = (properties.get("operation") or {}).get("enum") or []
    if not operations:
        # No operation enum: show the fields it takes, required ones first.
        required = list((spec.input_schema or {}).get("required") or ())
        optional = [name for name in properties if name not in required]
        fields = [f"{name}*" for name in required] + optional
        return " ".join(fields[:4]) + (" …" if len(fields) > 4 else "") if fields else "no inputs"
    shown = list(operations[:4])
    if len(operations) > len(shown):
        shown.append("…")
    return f"operation: {'|'.join(shown)}"


def _tool_summary(spec: Any) -> str:
    """First sentence of the contract description, plus how to ask in words."""

    text = " ".join((spec.description or "").split())
    first, _, _rest = text.partition(". ")
    summary = (first or text).rstrip(".")
    example = _TOOL_EXAMPLES.get(spec.name, "")
    if example.startswith("ti auto") or example.startswith("ti do"):
        return f"{summary}. Ask in words, or call the contract with ti tools run {spec.name}."
    return f"{summary}. Call it with ti tools run {spec.name} --input 'JSON'."


def _print_native_tool_groups() -> None:
    from .tools import specs

    global _TOOL_NAME_WIDTH

    available = {spec.name: spec for spec in specs()}
    grouped: set[str] = set()
    sections = list(_TOOL_GROUPS)
    leftover = [name for name in available if not any(name in names for _, names in sections)]
    if leftover:
        sections.append(("OTHER TOOLS", tuple(sorted(leftover))))
    for title, names in sections:
        present = [name for name in names if name in available]
        if not present:
            continue
        grouped.update(present)
        print()
        print(paint(title, PALETTE.violet + PALETTE.bold))
        for name in present:
            spec = available[name]
            _entry(name, _tool_shape(spec),
                   _TOOL_EXAMPLES.get(name, f"ti tools describe {name}"),
                   _tool_summary(spec), width=_TOOL_NAME_WIDTH)


def print_tools_help() -> None:
    print(_heading("ti tools — workspace files, host facts, and forensics"))
    print(paint("WHAT: The file commands, plus every native tool contract ti auto picks from.", PALETTE.text))
    print(paint("WHEN: You want structured file work, a host fact, or a compromise check "
                "without inventing shell pipelines.", PALETTE.text))
    print()
    _legend(fields=True)
    print()
    print(paint("FILE COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("map", "ti tools map [WHERE] [--depth N] [--symbols]", "ti tools map . --depth 3",
           "Prints a directory tree so you can see the shape of a project quickly. --depth limits "
           "how far down it walks and --symbols adds top-level Python definitions.")
    _entry("find", "ti tools find NAME [WHERE] [--type file|directory|any]", "ti tools find \"*.yaml\" .",
           "Finds entries by name or glob pattern. Narrow the results with --type when you want "
           "only files or only directories.")
    _entry("search", "ti tools search TEXT [WHERE] [--glob G] [--regex]",
           "ti tools search TODO . --glob \"*.py\"",
           "Searches inside file contents and reports each hit as file:line:column with the "
           "matching line. Uses ripgrep when installed, otherwise a stdlib walk. --glob restricts "
           "which files are read.")
    _entry("read", "ti tools read FILE [--start A] [--end B]", "ti tools read README.md --start 1 --end 40",
           "Prints a file with line numbers, optionally just the range you ask for. Omit FILE "
           "entirely to list what is in the current directory.")
    _entry("write", "ti tools write FILE --content TEXT [--overwrite]",
           "ti tools write hello.py --content \"print(1)\"",
           "Creates a workspace file atomically. Nested paths are allowed; overwrite stays off "
           "unless you pass --overwrite.")
    _entry("edit", "ti tools edit FILE --old TEXT --new TEXT",
           "ti tools edit app.py --old \"foo\" --new \"bar\"",
           "Replaces an exact text occurrence and prints a unified diff. Refuses to write when "
           "the match count is not exactly one.")
    print()
    print(paint("READING THE SHAPE", PALETTE.violet + PALETTE.bold))
    print(paint("  WHERE is optional and defaults to . (this directory, searched recursively).", PALETTE.muted))
    print(paint("  Quote globs like \"*.py\" so the shell does not expand them before TACU sees them.", PALETTE.muted))
    print(paint("  Text matching is literal; add --regex for patterns. Case is ignored unless --case-sensitive.",
                PALETTE.muted))
    print(paint("  Add --json to map, find, search, read, write, or edit when a script consumes the output.", PALETTE.muted))
    _print_native_tool_groups()
    print()
    print(paint("DISCOVERY", PALETTE.violet + PALETTE.bold))
    _entry("list", "ti tools list", "ti tools list",
           "The same tools with their risk level and full purpose line.")
    _entry("describe", "ti tools describe TOOL", "ti tools describe process",
           "Shows one tool's input contract and its risk level, so you know what fields it accepts "
           "before calling it.")
    _entry("examples", "ti tools examples", "ti tools examples",
           "Opens a longer guide with worked recipes for the file tools and the host tools.")
    print()
    print(paint("ADVANCED (JSON)", PALETTE.violet + PALETTE.bold))
    _entry("run", "ti tools run TOOL --input 'JSON'",
           "ti tools run process --input '{\"operation\":\"top_cpu\",\"limit\":10}'",
           "Calls a tool contract directly with a validated JSON object, skipping the planner "
           "entirely. Run describe on the tool first to learn its fields.")
    print()
    print(paint("TRY NEXT: ti tools map . --depth 3   ·   ti help auto   ·   ti tools examples", PALETTE.muted))
    _more("auto", "run", "health")


def print_run_help() -> None:
    print(_heading("ti run — your command, then an answer"))
    print(paint("WHAT: You name the argv. TACU runs it and answers -q from its stdout.", PALETTE.text))
    print(paint("WHEN: You already know the command (ifconfig, ping, docker inspect, …).", PALETTE.text))
    print(paint("RULE: Put -- before the command. No shell unless you pass --shell.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("basic", "ti run -q QUESTION -- COMMAND", "ti run -q what is my primary IP -- ifconfig",
           "Runs the command exactly as written, then answers your question from its stdout. "
           "Nothing about the command is rewritten or guessed.", ai=True)
    _entry("shell", "ti run --shell -q QUESTION -- COMMAND",
           "ti run --shell -q summarize failed tests -- make test",
           "Same as above but routed through a shell, which you need for pipes, globs, and && "
           "chains. Without it the argv is executed directly.", ai=True)
    _entry("timeout", "ti --timeout SECONDS run -q QUESTION -- COMMAND",
           "ti --timeout 900 run -q summarize -- nmap -sV host",
           "Raises the time limit for slow commands like scans or builds. Default is 900 seconds "
           "(15 minutes). --timeout is a global flag and must come before the subcommand.", ai=True)
    print()
    print(paint("NOT THIS: translation → ti ask · unknown host recipes → ti auto · raw colorize → ti inspect",
                PALETTE.muted))
    _more("ask", "auto", "inspect", "docker")


def print_ask_help() -> None:
    print(_heading("ti ask — language only (no host commands)"))
    print(paint("WHAT: Translate, explain, rewrite, or analyze text you already have.", PALETTE.text))
    print(paint("WHEN: Words/tone/meaning — not “what’s using CPU on this Mac”.", PALETTE.text))
    print(paint("PIPES: Finite stdout is classified (JSON/CSV/logs) and filtered before any model call.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("ask", "ti ask QUESTION", "ti ask translate this into polite language",
           "Answers from the local model alone, with no shell and no planning step. Best for "
           "rewriting, translating, and explaining.", ai=True)
    _entry("pipe", "COMMAND | ti ask QUESTION", "cat app.json | ti ask what keys are present",
           "Takes whatever you pipe in, works out whether it is JSON, CSV, or log text, and answers "
           "questions about it. For secrets, extract first: ti juicy FILE — do not pipe the raw dump here.", ai=True)
    _entry("juicy", "ti juicy FILE --ask QUESTION  ·  ti data ask NAME QUESTION",
           "ti data ask secrets is ada@example.com in the data",
           "Extract locally (ti juicy FILE). Questions filter the inventory first, then the "
           "model sees only that slice — never the whole dump. Same words as any other data "
           "question. juicy info / jcy info / juicy details are aliases.")
    print()
    print(paint("NARROW THE INPUT FIRST", PALETTE.violet + PALETTE.bold))
    _entry("keys", "… | ti ask --keys A,B QUESTION", "cat app.json | ti ask --keys name,version summarize",
           "Keeps only the JSON keys you name before anything reaches the model, which keeps large "
           "documents inside the context window.", ai=True)
    _entry("cols", "… | ti ask --cols A,B QUESTION", "cat rows.csv | ti ask --cols host,port summarize",
           "The same narrowing for CSV, selecting columns by header name.", ai=True)
    _entry("grep", "… | ti ask --grep TEXT [--head N] QUESTION", "cat app.log | ti ask --grep ERROR --head 40",
           "Reduces a log to the matching lines and then to the first N of them, so a huge file "
           "becomes a readable slice.", ai=True)
    _entry("no-ai", "… | ti ask --no-ai QUESTION", "cat data.json | ti ask --no-ai what keys",
           "Runs the filtering step and prints the result without ever calling the model — a quick "
           "way to check what the model would have seen.")
    print()
    print(paint("HOW BIG CAN THE INPUT BE", PALETTE.violet + PALETTE.bold))
    print(paint("  Piping is streamed, so a huge file will not exhaust memory — but only the first",
                PALETTE.text))
    print(paint("  and last 250 KB reach the model. Past that TACU prints a loud TRUNCATED warning",
                PALETTE.text))
    print(paint("  telling you what share it actually read. --grep is the exception: it is matched",
                PALETTE.text))
    print(paint("  against every byte of the stream, so a hit in the middle is never missed.",
                PALETTE.text))
    print()
    print(paint("  For anything over a few hundred MB, narrow it first and let TACU reason on the rest:",
                PALETTE.muted))
    print(paint("    rg 'pattern' huge.csv | ti ask what stands out", PALETTE.muted))
    print(paint("    awk -F, '{print $1\",\"$3}' huge.csv | ti ask --cols id,email summarize", PALETTE.muted))
    print(paint("    head -50000 huge.csv | ti ask --cols name,version summarize", PALETTE.muted))
    print()
    print(paint("TRY NEXT: ti help auto   ·   ti help run   ·   ti help juicy", PALETTE.muted))
    _more("auto", "run", "juicy")


def print_auto_help() -> None:
    print(_heading("ti auto — TACU inspects this Mac"))
    print(paint("WHAT: Native OS recipes for CPU, network, files, apps — then a short answer.", PALETTE.text))
    print(paint("WHEN: You want a host fact and do not already have the argv.", PALETTE.text))
    print(paint("SAFE reads run now. Writes / installs / process changes pause for your review.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("auto", "ti auto INTENT", "ti auto which process is consuming most CPU",
           "Matches your intent to a native OS recipe and runs it when it only reads. Anything that "
           "writes, installs, or kills a process stops for approval first.", ai=True)
    _entry("do", "ti do INTENT", "ti do find all images on Desktop",
           "Uses the same planner but always shows you the command before running it, and waits for "
           "execute, edit, or abort. The cautious version of auto.", ai=True)
    _entry("dry-run", "ti auto --dry-run INTENT", "ti auto --dry-run top tcp 443 destinations",
           "Prints the plan and stops. Nothing executes, which makes it a safe way to learn what "
           "TACU would do.", ai=True)
    _entry("steps", "ti auto --max-steps N INTENT", "ti auto --max-steps 3 why is my disk full",
           "Caps how many commands the planner may chain together, keeping open-ended questions "
           "from wandering.", ai=True)
    _entry("syntax", "ti syntax search TEXT", "ti syntax search cpu",
           "Looks up the exact argv a previous run produced, so you can rerun it directly instead "
           "of planning again.")
    print()
    print(paint("NOT THIS: translation → ti ask · known argv → ti run / ti inspect", PALETTE.muted))
    _more("do", "ask", "run", "syntax")


def print_web_help() -> None:
    print(_heading("ti web — local search, guarded reading"))
    print(paint("WHAT: Local SearXNG search + guarded public page reads → cited local-model answer.", PALETTE.text))
    print(paint("WHEN: You need current web facts without cloud APIs (TACU's own tacu-searxng container).", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("ask", "ti web QUERY", "ti web current macOS security updates",
           "Searches, opens the most promising public pages, and writes an answer with citations "
           "you can check.", ai=True)
    _entry("snippets", "ti web --snippets QUERY", "ti web --snippets ransomware trends",
           "Answers from the search result cards alone without opening any page — faster, and "
           "enough when you just want the lay of the land.", ai=True)
    _entry("read", "ti web --read N QUERY", "ti web --read 3 zero-day CVE this week",
           "Sets how many pages get opened. Raise it for depth, or use 0 to disable reading "
           "altogether.", ai=True)
    _entry("fetch", "ti web fetch URL", "ti web fetch https://example.com/",
           "Reads one public page you already know about, skipping the search step entirely.")
    _entry("health", "ti web health", "ti web health",
           "Confirms TACU's tacu-searxng container is running (127.0.0.1:8080, or the next free "
           "port if 8080 is taken). Check this first when web commands fail.")
    _entry("no-ai", "ti web --no-ai QUERY", "ti web --no-ai macos hardening",
           "Lists the sources that were found and stops there, with no synthesis, so you can read "
           "the originals yourself.")
    print()
    print(paint("Options come before the query. Failures are explicit — no cloud fallback.", PALETTE.muted))
    _more("ask", "safety")


def print_data_help() -> None:
    print(_heading("ti data — question a file too big to read"))
    print(paint("WHAT: Load a large file into a temporary store you can query in milliseconds.",
                PALETTE.text))
    print(paint("WHEN: The file is far past the 500 KB that fits in a model prompt.", PALETTE.text))
    print(paint("READS: CSV · TSV · JSON · NDJSON/JSONL · XLSX/XLSM · PCAP/PCAPNG/CAP · "
                "SQLite · registry hive · Burp XML/JSON · text .bak", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("LOAD", PALETTE.violet + PALETTE.bold))
    _entry("load", "ti data load FILE [--name NAME] [--ttl HOURS] [--header|--no-header]",
           "ti data load big.csv",
           "Streams FILE into its own database. Without --name the handle is dt1, then dt2, so "
           "the name in ti data list stays short. CSV headers are detected automatically; use "
           "--header or --no-header only when an ambiguous first row is detected incorrectly. "
           "Query later with that name or the id.")
    _entry("name", "ti data load FILE --name NAME", "ti data load capture.pcap --name dns",
           "Sets a short handle when dt1 is not descriptive enough. Names must be unique.")
    _entry("path", "ti data load FILE --path KEY [--name NAME]", "ti data load api.json --path items",
           "For JSON where the records sit under a key, such as {\"items\": [ … ]}. Only needed "
           "when the file has several arrays and the wrong one is picked.")
    _entry("sheet", "ti data load FILE --sheet NAME [--name NAME]", "ti data load books.xlsx --sheet Q3",
           "Picks a worksheet. Without it the first sheet is loaded and the others are named "
           "for you.")
    _entry("format", "ti data load FILE --format csv|json|ndjson|xlsx|pcap|sqlite|text|registry|burp",
           "ti data load dump.bin --format pcap",
           "Forces a reader when the extension is missing or wrong. Detection is automatic "
           "for the usual suffixes, including .bak.")
    _entry("pcap", "ti data load FILE.pcap [--name NAME]", "ti data load capture.pcapng --name dns",
           "Turns a Wireshark capture into one row per packet. packet is the 1-based frame "
           "number (Wireshark No.) — keep it in queries and reports so you can jump back. "
           "src_name and dst_name are filled "
           "from DNS answers, TLS SNI, and HTTP Host inside the same file — so TCP to a WAF IP "
           "still matches the site you asked about. Nothing is looked up on the network. "
           "Tables color src/src_port/src_name sage and dst/dst_port/dst_name rose. "
           "Ask for a display filter and TACU will quote field names from "
           "utils/wireshark_filters.csv when that catalog is in the workspace.")
    _entry("enrich", "ti data enrich NAME|ID", "ti data enrich wireshark",
           "Rebuilds an already-loaded capture with those name columns. Needs the original pcap "
           "still on disk (ti data show NAME prints the path).")
    _entry("burp", "ti data load FILE [--name NAME]", "ti data load history.xml --name http",
           "Burp HTTP history as rows. Detected by content, not the filename — Save items XML "
           "works with or without a .xml suffix. TACU decodes base64 request/response and "
           "extracts host, location, form, cookie, and juicy so you can query logins and "
           "redirects without reading the HTML. item is 1-based export order (jump back to "
           "that selected history row in Burp); burp_id is the dump's own id when present. "
           "Other XML is refused (not loaded as CSV). "
           "Parser path: dump proxy history / site map / audit items to JSON or NDJSON. "
           "A .burp project file is proprietary — export first.")
    _entry("hive", "ti data load FILE.bak [--name NAME]", "ti data load SOFTWARE.bak --name hive",
           "A Windows registry hive (regf header — SYSTEM, SOFTWARE, NTUSER.DAT, or a copy "
           "from RegBack / a restore-point snapshot) becomes one row per value: key, name, "
           "type, data.")
    _entry("bak", "ti data load FILE.bak [--name NAME]", "ti data load notes.bak --name notes",
           "Sniffs a backup: SQLite, JSON/CSV, text, pcap, or a registry hive. Microsoft SQL "
           "Server .bak is a restore stream, not a table dump — export with bcp or SSMS, then "
           "ti data load FILE.csv.")
    print()
    print(paint("QUERY", PALETTE.violet + PALETTE.bold))
    _entry("list", "ti data list", "ti data list",
           "Shows id, name, the first words of the source file, row count, and time left. "
           "Query with either the NAME or the ID.")
    _entry("show", "ti data show NAME|ID", "ti data show dt1",
           "Describes every column — type, how many non-null, how many distinct, example values — "
           "without printing any rows. Start here.")
    _entry("head", "ti data head NAME|ID [-n ROWS]", "ti data head dt1 -n 5",
           "Prints the first rows so you can see the real shape of the data.")
    _entry("ask", "ti data ask NAME|ID QUESTION", "ti data ask dt1 which region sold most",
           "Plain language. Sales/counts still become SQL. Questions about any juicy kind "
           "(passwords, JWTs, PAN, AWS keys, private keys, cards, IPs, URLs, phones, …) "
           "or juicy info / jcy info / juicy details read the inventory. "
           "A specific value (is ada@example.com in the data, is 9870000043 in the table) "
           "is filtered first; only those hits (or a clear miss) go to the model. "
           "The unfiltered dump is never sent.", ai=True)
    _entry("query", "ti data query NAME|ID \"SELECT …\"",
           "ti data query dt1 \"SELECT status, COUNT(*) FROM data GROUP BY status\"",
           "Runs one read-only SELECT yourself. The table is always called data. Writes are refused "
           "and long queries are stopped.")
    _entry("search", "ti data search NAME|ID TEXT", "ti data search dt1 timeout",
           "Finds rows where any column contains the text, without you writing SQL.")
    _entry("juicy", "ti data juicy NAME|ID [--kind KIND] [--grep TEXT] [QUESTION]",
           "ti data juicy secrets is ada@example.com in the data",
           "Without a question: grouped inventory, no model. "
           "With a question: the same filter-then-model path as ti data ask. "
           "--kind and --grep narrow the view (and the slice sent to the model).")
    _entry("rm", "ti data rm NAME|ID | --all", "ti data rm dt1",
           "Removes a dataset now instead of waiting for it to expire.")
    _entry("gc", "ti data gc", "ti data gc",
           "Deletes everything past its TTL. Runs by itself on every ti data call.")
    print()
    print(paint("NAME OR ID", PALETTE.violet + PALETTE.bold))
    print(paint("  NAME is dt1, dt2, … or whatever you passed to --name. ID is the 8-character",
                PALETTE.muted))
    print(paint("  value in the first column of ti data list. Both work on show, head, ask,",
                PALETTE.muted))
    print(paint("  query, search, juicy, enrich, and rm.", PALETTE.muted))
    print()
    print(paint("TYPICAL SESSION", PALETTE.violet + PALETTE.bold))
    print(paint("  ti data load huge.csv                       becomes dt1", PALETTE.muted))
    print(paint("  ti data load capture.pcap --name dns        packets as rows, named dns", PALETTE.muted))
    print(paint("  ti data enrich dns                          fill src_name/dst_name from this capture",
                PALETTE.muted))
    print(paint("  ti data load history.xml --name http        Burp Save items / JSON dump", PALETTE.muted))
    print(paint("  ti data show dt1                            learn the columns", PALETTE.muted))
    print(paint("  ti data juicy dt1                           full inventory, no model",
                PALETTE.muted))
    print(paint("  ti data juicy dt1 --kind indian-phone       one kind, no model",
                PALETTE.muted))
    print(paint("  ti data juicy dt1 --grep 9870000043         one value, no model",
                PALETTE.muted))
    print(paint("  ti data juicy dt1 is 9870000043 in the data  filter, then the model",
                PALETTE.muted))
    print(paint("  ti data ask dt1 is ada@example.com in the data",
                PALETTE.muted))
    print(paint("  ti data ask dt1 what should I rotate first  filtered inventory, then the model",
                PALETTE.muted))
    print(paint('  ti data query dt1 "SELECT ... GROUP BY ..." or write it yourself',
                PALETTE.muted))
    print(paint("  ti data show ae715a83                       same dataset, by id", PALETTE.muted))
    print()
    print(paint("NESTED DATA (JSON)", PALETTE.violet + PALETTE.bold))
    print(paint("  Nested objects become dotted columns: {\"user\":{\"id\":1}} gives user_id.",
                PALETTE.muted))
    print(paint("  Lists and deeper levels are kept as JSON text, so nothing is lost — reach in",
                PALETTE.muted))
    print(paint("  with json_extract(col, '$.key'), or expand a list with json_each(data.col).",
                PALETTE.muted))
    print(paint("  ti data ask is told which columns hold JSON and writes this for you.",
                PALETTE.muted))
    print(paint("  Use --depth 1 if flattening produces too many columns.", PALETTE.muted))
    print()
    print(paint("HOW ASK WORKS", PALETTE.violet + PALETTE.bold))
    print(paint("  The model is shown the column names and types — never the rows. It writes a "
                "query,", PALETTE.muted))
    print(paint("  sees a small result, and repeats until it can answer, up to --steps queries.",
                PALETTE.muted))
    print(paint("  Only SELECT is ever allowed, so a wrong query fails instead of changing data.",
                PALETTE.muted))
    print(paint("  Use --sql-only to see the query it would run without running it.", PALETTE.muted))
    print()
    print(paint("LIFETIME", PALETTE.violet + PALETTE.bold))
    print(paint(f"  Datasets expire after {int(DEFAULT_TTL_HOURS)} hours by default and are swept "
                "automatically.", PALETTE.muted))
    print(paint("  Use --ttl to keep one longer, or ti data rm to drop it immediately.",
                PALETTE.muted))
    print(paint("  Nothing is uploaded and the original file is never modified.", PALETTE.muted))
    print()
    print(paint("TRY NEXT: ti data load FILE.csv   ·   ti data list   ·   ti data show dt1",
                PALETTE.muted))
    _more("ask", "juicy", "backup")


def print_backup_help() -> None:
    print(_heading("ti backup — save and restore everything"))
    print(paint("WHAT: Packs every TACU database and setting into one portable .tar.gz.", PALETTE.text))
    print(paint("WHEN: Before a reinstall or OS upgrade, and on a schedule you trust.", PALETTE.text))
    print(paint("WHERE: Any path — pen drive, iCloud Drive, Google Drive, Dropbox. No cloud account needed.",
                PALETTE.text))
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("create", "ti backup create [DEST] [--include-artifacts]", "ti backup create ~/Dropbox",
           "Writes a dated archive. Give a folder and the name is generated, or name the .tar.gz "
           "yourself. Around 3 MB unless you add raw artifacts.")
    _entry("list", "ti backup list [FOLDER]", "ti backup list ~/Dropbox",
           "Shows the TACU backups in a folder with their date, version, and size. Other archives "
           "in the folder are ignored.")
    _entry("show", "ti backup show ARCHIVE", "ti backup show ~/Dropbox/tacu-backup-20260827.tar.gz",
           "Describes one archive — when it was taken, on which machine, and what is inside — "
           "without unpacking it.")
    _entry("restore", "ti backup restore ARCHIVE [--merge]", "ti backup restore ~/tacu-backup.tar.gz",
           "Puts the data back. By default the archive replaces your local databases; --merge keeps "
           "what you have and only adds turns and clips that are missing.")
    print()
    print(paint("WHAT IS SAVED", PALETTE.violet + PALETTE.bold))
    print(paint("  history.db retained turns · clipboard.db tray · harness.db · config.json · ghost history",
                PALETTE.muted))
    print(paint("  artifacts/ (raw command output) only with --include-artifacts — it is the bulk of the size.",
                PALETTE.muted))
    print(paint("  runtime/ is skipped on purpose: ./install.sh rebuilds the virtualenv.", PALETTE.muted))
    print()
    print(paint("SAFETY", PALETTE.violet + PALETTE.bold))
    print(paint("  Restore snapshots your current state first, so a wrong archive is never fatal.", PALETTE.muted))
    print(paint("  Databases are copied with SQLite's online backup API — safe even mid-write.", PALETTE.muted))
    print()
    print(paint("TRY NEXT: ti backup create ~/Desktop   ·   ti backup list ~/Desktop", PALETTE.muted))
    _more("health", "review", "clip")


def print_inspect_help() -> None:
    print(_heading("ti inspect — colorize, no model"))
    print(paint("WHAT: Readable colorized stdout for a command you already know.", PALETTE.text))
    print(paint("WHEN: Zero AI, no planning, no flag rewrites — just see the output clearly.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("basic", "ti inspect -- COMMAND", "ti inspect -- ifconfig",
           "Runs the command and colorizes its output so it is easier to read. The -- is required "
           "so the command's own flags are never treated as TACU options.")
    _entry("shell", "ti inspect --shell -- COMMAND", "ti inspect --shell -- ls -la | head",
           "The same colorized view, but routed through a shell so pipes, globs, and redirection "
           "behave the way you expect.")
    print()
    print(paint("Need an answer from stdout → ti run -q … -- CMD", PALETTE.muted))
    _more("run", "ask", "auto")


def print_workspace_help() -> None:
    print(_heading("ti workspace — focused project directory"))
    print(paint("WHAT: A directory boundary for file tools. Interactive sessions keep the shell you launched from; the workspace is shown separately.", PALETTE.text))
    print(paint("WHEN: You want ti tools / ti do writes confined, or a dedicated project folder.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("menu", "ti workspace", "ti workspace",
           "Opens a numbered menu to enter, create, or switch the workspace without memorizing subcommands.")
    _entry("show", "ti workspace show|path", "ti workspace show",
           "Prints the configured workspace path. Does not change this shell's directory.")
    _entry("enter", "ti workspace enter|go|open", "ti workspace enter",
           "Opens a focused shell already inside the workspace. Type exit to return to the previous shell.")
    _entry("create", "ti workspace create [DIR]", "ti workspace create ~/Projects/Assessment",
           "Creates the directory if needed, selects it as the workspace, then offers to enter. Omit DIR for a prompt.")
    _entry("use", "ti workspace use [DIR]", "ti workspace use ~/Projects/Existing",
           "Selects an existing directory as the workspace. Omit DIR for a guided prompt.")
    print()
    print(paint("File tools may write only inside this directory; everything outside it is read-only.", PALETTE.muted))
    _more("tools", "auto", "health")


def print_docker_help() -> None:
    print(_heading("ti docker — tools already in a container"))
    print(paint("WHAT: Run a command inside an existing Docker container, then answer -q from its stdout.", PALETTE.text))
    print(paint("WHEN: The scanner or tool lives in the image, not on the host PATH.", PALETTE.text))
    print(paint("RULE: Put -- before the container command, the same as ti run. TACU does not add mounts, networks, or capabilities.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("docker", "ti docker CONTAINER -q QUESTION -- COMMAND",
           "ti docker kali -q explain these SMB findings -- nxc smb 10.0.0.5",
           "Runs COMMAND in a container that already exists, captures the result, then answers your question. "
           "Nothing extra is mounted or privileged.", ai=True)
    print()
    print(paint("Host command you already know → ti run -q … -- CMD", PALETTE.muted))
    _more("run", "inspect", "ask")


def print_extract_help() -> None:
    print(_heading("ti juicy — extract, filter, then ask"))
    print(paint("ALIASES:  ti juicy  =  ti extract juicy  =  ti extract ji",
                PALETTE.green + PALETTE.bold))
    print(paint("  Same command, same flags, same scan. `ti help extract` and `ti help juicy`",
                PALETTE.muted))
    print(paint("  open this page. `ji` is the short extract kind: ti extract ji FILE",
                PALETTE.muted))
    print()
    print(paint("WHAT: Discover secrets and identifiers locally, then question only the matching slice.",
                PALETTE.text))
    print(paint("WHEN: A dump, a project tree, or a loaded table — never pipe the raw dump to the model.",
                PALETTE.text))
    print()
    _legend()
    print()
    print(paint("WORKFLOW", PALETTE.violet + PALETTE.bold))
    print(paint("  1. Extract  —  ti juicy FILE|DIR          inventory on disk, no model",
                PALETTE.muted))
    print(paint("  2. View     —  ti data load FILE && ti data juicy NAME",
                PALETTE.muted))
    print(paint("  3. Ask      —  ti juicy FILE --ask QUESTION",
                PALETTE.muted))
    print(paint("              or ti data ask NAME QUESTION  /  ti data juicy NAME QUESTION",
                PALETTE.muted))
    print(paint("  The harness filters first (kind, email, phone, token). Only that slice",
                PALETTE.text))
    print(paint("  reaches the model. A miss is sent as 0 hits so the model can say no.",
                PALETTE.text))
    print()
    print(paint("STEP 1 — EXTRACT (no model)", PALETTE.violet + PALETTE.bold))
    _entry("file", "ti juicy FILE [-o OUT] [--min-confidence LEVEL]",
           "ti juicy juicy_test_data.csv -o findings.csv",
           "Prints a grouped inventory (kind, value, where, confidence, how it can be misused) "
           "and writes CSV (kind, category, value, source file, source file line number, "
           "packet, item, confidence, fingerprint, redacted, context). "
           "LINE is the dump file line. PACKET is the Wireshark frame number when the dump "
           "has one (pcap load or a CSV with a packet/No. column). ITEM is the Burp history "
           "item (1-based export order). Blank when the source has no such id. "
           "Confidence: critical / high / medium / low. Terminal values are never masked.")
    _entry("tree", "ti juicy DIR [-o OUT] [--reports DIR] [--resume]",
           "ti juicy ./source-code",
           "Walks a source-code root. Each first-level folder is one project. "
           "Writes DIR/_juicy_reports/payment-service_report.jsonl (and .csv), "
           "mobile-app_report.jsonl, MASTER_SUMMARY.csv, ROTATION_REPORT.csv. "
           "JSON/CSV keep values in the clear (same as the terminal), plus a SHA-256 "
           "fingerprint for correlation. LINE, PACKET, and ITEM sit on every row so you "
           "can jump back to the editor, Wireshark, or Burp. -o FILE copies the master CSV. "
           "--resume skips unchanged files. --all-files scans any non-binary.")
    _entry("pipe", "COMMAND | ti extract juicy [-o OUT]",
           "cat juicy_test_data.csv | ti extract juicy -o findings.csv",
           "Same scan on stdin. Prefer this over piping the raw file into ti ask. "
           "ti extract juicy FILE is identical to ti juicy FILE.")
    _entry("turn", "ti juicy --turn N [-o OUT]",
           "ti juicy --turn 42 -o findings.csv",
           "Scans a retained answer instead of a file. Omit N to use the latest turn.")
    _entry("table", "ti data load FILE && ti data juicy NAME",
           "ti data load juicy_test_data.csv --name secrets && ti data juicy secrets",
           "Same inventory after the file is a queryable table. No model until you ask. "
           "See FILE TYPES below for how each dump becomes columns.")
    print()
    print(paint("FILE TYPES — how values land, and which native id comes back",
                PALETTE.violet + PALETTE.bold))
    _entry("source", "ti juicy FILE.py|.env|.yml|.json|…",
           "ti juicy payment-service/.env",
           "Line-oriented scan. where is path:line. PACKET and ITEM stay blank.")
    _entry("csv", "ti juicy FILE.csv  ·  ti data load FILE.csv",
           "ti juicy export.csv -o findings.csv",
           "Header row names the columns. Credential-named columns (password, api_key, email) "
           "are findings even without key=value. A packet or No. column is copied onto every "
           "hit so Wireshark CSV exports keep the frame number. Same for item / burp_id.")
    _entry("json", "ti data load FILE.json [--path KEY]",
           "ti data load api.json --path items --name api",
           "Each object becomes a table row (nested keys flattened). Scan with ti data juicy. "
           "Use --path when records sit under a key. NDJSON/JSONL is one object per line.")
    _entry("xlsx", "ti data load FILE.xlsx [--sheet NAME]",
           "ti data load books.xlsx --sheet Q3 --name books",
           "First sheet by default. Cells become columns; then the same juicy scan as CSV.")
    _entry("pcap", "ti data load FILE.pcap --name dns",
           "ti data load capture.pcapng --name dns && ti data juicy dns",
           "Binary capture — do not ti juicy the .pcap. One row per frame. packet is the "
           "1-based Wireshark No. Reports and where labels say packet N so you can jump to "
           "that frame. src_name/dst_name come from DNS, SNI, and Host in the same file.")
    _entry("burp", "ti data load history.xml --name http",
           "ti data load history.xml --name http && ti data juicy http",
           "Burp Save items XML (or JSON/NDJSON dump). item is 1-based export order — the "
           "Nth selected history row in that file. burp_id is the id from the dump when "
           "present. ti juicy on the XML also stamps item from <item>/<issue> tags plus the "
           "XML line. A .burp project file is proprietary — export first.")
    _entry("sqlite", "ti data load FILE.db [--name NAME]",
           "ti data load app.sqlite --name app",
           "Existing tables are not rewritten. Query with SQL, or ti data juicy to scan "
           "cell text. Row ids stay whatever the database already has.")
    _entry("text", "ti juicy FILE.txt|.log|.html|.sql|.har",
           "ti juicy notes.log",
           "Plain text, HTML, SQL dumps, HAR: path:line. Load with ti data load FILE --format "
           "text when you want a table of lines instead of a file scan.")
    _entry("hive", "ti data load FILE.bak --name hive",
           "ti data load SOFTWARE.bak --name hive && ti data juicy hive",
           "Registry hive → one row per value (key, name, type, data). No packet/item.")
    print()
    print(paint("STEP 2 — NARROW WITHOUT ASKING (still no model)", PALETTE.violet + PALETTE.bold))
    _entry("kind", "ti juicy FILE|DIR --kind KIND[,KIND]",
           "ti juicy ./exports --kind indian-phone,email",
           "Keep one or more kinds. Aliases work: phone, jwt, aws, pan.")
    _entry("grep", "ti juicy FILE|DIR --grep TEXT",
           "ti juicy ./exports --grep 9870000043",
           "Keep findings whose value contains TEXT. Phone digits are normalised, so "
           "9870000043 matches 91 9870000043. Fast path on a large tree.")
    _entry("table", "ti data juicy NAME --kind KIND --grep TEXT",
           "ti data juicy secrets --grep 9870000043",
           "Same flags on a loaded table, still no model.")
    print()
    print(paint("STEP 3 — ASK (filter, then the model)", PALETTE.violet + PALETTE.bold))
    _entry("table", "ti data ask NAME QUESTION  ·  ti data juicy NAME QUESTION",
           "ti data ask secrets is ada@example.com in the data",
           "Load a ti juicy CSV (kind/value) and TACU reads those rows — it does not "
           "re-detect passwords inside the value column. "
           "Examples: is mobile number 9713442354 in the data table; "
           "tell me if abc@gmail.com is there. "
           "The harness filters; the model answers from that slice only.")
    _entry("file", "ti juicy FILE --ask QUESTION",
           "ti juicy juicy_test_data.csv --ask is mobile number 9713442354 in the data",
           "Extract, filter, then ask in one command. Quotes are optional. "
           "The model never sees the unfiltered dump.",
           ai=True)
    print()
    print(paint("Loaded table → ti data juicy NAME QUESTION   ·   file/tree → ti juicy PATH --ask QUESTION",
                PALETTE.muted))
    _more("data", "ask", "copy")


def print_save_help() -> None:
    print(_heading("ti save — export a retained turn"))
    print(paint("WHAT: Write an entire answer to a markdown, text, or JSON file.", PALETTE.text))
    print(paint("WHEN: You want the turn outside TACU — a ticket, a report, or another tool.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("save", "ti save [TURN] [--format md|txt|json] [--output FILE]",
           "ti save 42 --format md",
           "Exports the whole turn. Omit TURN for the latest answer. --output names the file; otherwise a default name is used.")
    print()
    print(paint("One L### line → ti copy TURN:LINE   ·   identifiers only → ti extract juicy --turn N", PALETTE.muted))
    _more("copy", "review", "extract")


def print_safety_help() -> None:
    print(_heading("ti help safety — quoting & guardrails"))
    print(paint("WHAT: How questions are joined, where -- is required, and what the shell still owns.", PALETTE.text))
    print(paint("WHEN: A question with quotes, ?, or * is swallowed, or run/docker looks ambiguous.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("ask", "ti ask QUESTION", "ti ask explain the phrase '\"zero trust\"'",
           "Ordinary multiword questions do not need outer quotes. Empty '' and \"\" groups are ignored. "
           "To keep literal quotes, nest them as in the example.")
    _entry("run", "ti run -q QUESTION -- COMMAND",
           "ti run -q what is my primary IP -- ifconfig",
           "For run and docker, -- after -q is mandatory. Ambiguous input runs nothing.")
    _entry("zsh", "eval \"$(ti shell-init SHELL)\"",
           "eval \"$(command ticu shell-init zsh)\"",
           "Passes ?, *, and brackets literally to ti. Reload after install: source ~/.zshrc. "
           "|, >, ;, &, $, and parentheses are still processed by the shell first — quote those when they are question content.")
    print()
    print(paint("Old quoted commands remain fully supported.", PALETTE.muted))
    _more("ask", "run", "health")


def print_tacu_help() -> None:
    print(_heading("ti tacu help — static help, then local-model examples"))
    print(paint("WHAT: The same shape + example + description help, plus extra examples from the local model.", PALETTE.text))
    print(paint("WHEN: You already know the command family and want more pasteable recipes grounded on that page.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("static", "ti help [COMMAND]", "ti help workspace",
           "Built-in reference only. Never calls the model. Same page as COMMAND --help.")
    _entry("model", "ti tacu help [TOPIC]", "ti tacu help workspace",
           "Prints that static page first, then asks the local model for extra examples in the same layout.")
    _entry("detail", "ti tacu help TOPIC DETAIL", "ti tacu help tools search",
           "The extra words after the topic steer the model toward one subcommand or flag still listed in the static help.")
    print()
    print(paint("ti help COMMAND never calls the model. ti tacu help is the only help path that does.", PALETTE.muted))
    _more("ask", "tools", "data")


def print_all_help() -> None:
    print(_heading("ti all — full capability tutorial"))
    print(paint("WHAT: A snapshot of every command family, then an optional deep dive into one topic.", PALETTE.text))
    print(paint("WHEN: You want the map, not a single command's shape + example page.", PALETTE.text))
    print()
    _legend()
    print()
    print(paint("COMMANDS", PALETTE.violet + PALETTE.bold))
    _entry("all", "ti all", "ti all",
           "Prints the capability snapshot. In a terminal it then offers a numbered deep dive.")
    _entry("topic", "ti all TOPIC", "ti all workspace",
           "Skips the menu and opens the dense help page for that topic.")
    print()
    print(paint("One command's shape + example page → ti help COMMAND", PALETTE.muted))
    _more("ask", "auto", "run", "juicy")


_DENSE_HELP = {
    "clip": print_clip_help,
    "syntax": print_syntax_help,
    "setup": print_health_help,
    "health": print_health_help,
    "doctor": print_health_help,
    "config": print_health_help,
    "review": print_review_help,
    "memory": print_copy_help,
    "copy": print_copy_help,
    "tools": print_tools_help,
    "commands": print_run_help,
    "run": print_run_help,
    "questions": print_ask_help,
    "ask": print_ask_help,
    "auto": print_auto_help,
    "do": print_auto_help,
    "web": print_web_help,
    "inspect": print_inspect_help,
    "backup": print_backup_help,
    "restore": print_backup_help,
    "data": print_data_help,
    "dataset": print_data_help,
    "workspace": print_workspace_help,
    "docker": print_docker_help,
    "extract": print_extract_help,
    "juicy": print_extract_help,
    "save": print_save_help,
    "safety": print_safety_help,
    "tacu": print_tacu_help,
    "all": print_all_help,
    "tutorial": print_all_help,
    "guide": print_all_help,
}

_BARE_DENSE_COMMANDS = frozenset({
    "tools", "run", "ask", "analyze", "auto", "do", "propose", "plan",
    "web", "inspect", "juicy", "extract", "ji",
})


def help_intercept_target(argv: list[str]) -> str | None:
    """Command whose dense help should replace argparse, or None to keep parsing."""

    if not argv:
        return None
    cmd = argv[0]
    rest = argv[1:]
    if rest and rest[-1] in {"-h", "--help"}:
        return cmd
    if not rest and cmd.casefold() in _BARE_DENSE_COMMANDS:
        return cmd
    return None


def show_command_help(name: str) -> bool:
    key = ALIASES.get(name.casefold(), name.casefold())
    printer = _DENSE_HELP.get(key)
    if printer:
        printer()
        return True
    if key not in TOPICS:
        return False
    print(_heading(TOPICS[key][0]))
    print()
    _show_topic(name, heading=False)
    print()
    _more("ask", "auto", "run", "clip", "review", "health")
    return True


_CHOICE_ROWS = (
    ("ask", "questions", "when you want words — translate, explain, or a pipe. No command runs.", True),
    ("auto", "auto", "when you want TACU to inspect this Mac — CPU, IP, Desktop, apps.", True),
    ("run", "commands", "when you already know the command — capture stdout and answer -q.", True),
    ("inspect", "inspect", "when you want raw colorized output — no model, no planning.", False),
    ("juicy", "extract", "when you want secrets or identifiers from a dump or tree — extract locally first.", False),
)

# Canonical top-level parsers that `ti help` must name. The release test compares
# this catalog with argparse, so adding a command without documenting it fails.
# User-facing aliases are listed beside their canonical command in the overview.
OVERVIEW_COMMANDS = (
    "ask", "web", "do", "auto", "run", "docker", "inspect", "history",
    "evidence", "copy", "clip", "syntax", "save", "extract", "juicy",
    "data", "backup", "all", "completion", "shell-init", "version",
    "models", "model", "config", "plugins", "doctor", "setup",
    "workspace", "tools", "clear",
)


def print_choice_guide(*, highlight: str | None = None) -> None:
    _zone("PICK ONE")
    selected = {
        "do": "auto",
        "questions": "ask",
        "commands": "run",
        "extract": "juicy",
        "ji": "juicy",
    }.get(highlight or "", highlight)
    for name, _topic_key, when, uses_ai in _CHOICE_ROWS:
        mark = "▸ " if name == selected else "  "
        name_color = PALETTE.green + PALETTE.bold
        when_color = PALETTE.accent if name == selected else PALETTE.text
        sparkle = f"{_AI_SPARKLE} " if uses_ai else ""
        print(_command(((f"{mark}{name:<8}", name_color), (f"{sparkle}{when}", when_color))))


def _catalog_row(
    command: str,
    usage: str,
    when: str,
    does: str,
    how: str,
    *,
    ai: bool = False,
) -> None:
    """One catalog entry: command · usage, then when / does / how (inspiration: help matrix)."""

    lead = f"{_AI_SPARKLE} " if ai else ""
    print(_command((
        (f"  {command:<9}", PALETTE.green + PALETTE.bold),
        (f"{lead}{usage}", PALETTE.accent),
    )))
    print(paint(f"           when {when}  ·  does {does}  ·  how {how}", PALETTE.muted))


def _footer_box(title: str, lines: list[str]) -> None:
    print(paint(f"┌ {title}", PALETTE.violet + PALETTE.bold))
    for line in lines:
        print(paint(f"│ {line}", PALETTE.text))


def print_quick_help() -> None:
    """Top-level progressive help: pick a mode, see examples, drill with ti help <cmd>."""

    print(banner())
    print()
    print(paint("Native OS recipes first. Model only when a parser cannot answer.", PALETTE.text))
    print()
    print_choice_guide()
    print()
    _legend()
    print()

    _zone("ASK — words only")
    _entry("ask", "ti ask QUESTION", "ti ask translate this into polite language",
           "Answers in plain language using the local model. It never runs a host command, "
           "so use it for wording, meaning, and explanations rather than facts about this Mac.", ai=True)
    _entry("pipe", "COMMAND | ti ask [--keys A,B] QUESTION",
           "cat app.json | ti ask --keys name,version summarize",
           "Reads piped stdout, detects JSON/CSV/logs, and trims it before the model sees anything. "
           "Add --no-ai to stop after the filter and just print the trimmed data.", ai=True)
    print()

    _zone("AUTO — inspect this Mac")
    _entry("auto", "ti auto INTENT", "ti auto which process is consuming most CPU",
           "Describe the fact you want and TACU picks a native OS recipe for it. Safe read-only "
           "commands run immediately; anything that writes or installs pauses for your approval.", ai=True)
    _entry("do", "ti do INTENT", "ti do find all images on Desktop",
           "The same planner as auto, but every step is shown first and you choose execute, edit, "
           "or abort. Reach for this when you want to see the command before it touches anything.", ai=True)
    print()

    _zone("RUN / INSPECT — you know the command")
    _entry("run", "ti run -q QUESTION -- COMMAND", "ti run -q what is my primary IP -- ifconfig",
           "Runs the command you name, then answers your question from its stdout. The -- separates "
           "your question from the command so flags like -sV are never mistaken for TACU options.", ai=True)
    _entry("inspect", "ti inspect -- COMMAND", "ti inspect -- ifconfig",
           "Runs the command and colorizes the output for readability. No model, no planning, and "
           "no flag rewriting — what you typed is exactly what runs.")
    print()

    _zone("FINDINGS — extract locally")
    _entry("juicy", "ti juicy FILE|DIR [--ask QUESTION]",
           "ti juicy dump.csv --ask is ada@example.com in the data",
           "Scans a file or project tree for secrets and identifiers locally. Inventory first; "
           "--ask filters the findings before the model sees that slice.")
    _entry("extract", "ti extract juicy|ji FILE|DIR [-o OUT]",
           "ti extract juicy scan.txt -o findings.csv",
           "The explicit extractor form of ti juicy. It uses the same scanner and flags; ji is "
           "the short extraction kind. No model runs unless you add --ask.")
    print()

    _zone("DATA — large and structured files")
    _entry("data", "ti data load|show|head|ask|query|search|juicy|rm|gc|enrich …",
           "ti data load big.csv --name logs",
           "Streams CSV, JSON, PCAP, Burp, SQLite, registry, XLSX, or text into a temporary "
           "read-only store, then queries small result slices instead of prompting with the file.")
    print()

    _zone("WEB / TOOLS / CONTAINERS")
    _entry("web", "ti web QUERY", "ti web current macOS security updates",
           "Searches through TACU's tacu-searxng container, reads the top public pages, and answers "
           "with citations. Starts the container on 127.0.0.1:8080 (or the next free port). "
           "No cloud fallback.", ai=True)
    _entry("tools", "ti tools map|find|search|read|write|edit …", "ti tools map . --depth 3",
           "Structured file operations that stay inside the workspace guard, so you get predictable "
           "output instead of hand-written shell pipelines. See ti help tools for each shape.")
    _entry("docker", "ti docker CONTAINER -q QUESTION -- COMMAND",
           "ti docker kali -q explain these SMB findings -- nxc smb 10.0.0.5",
           "Runs a command inside an existing container, then answers -q from that stdout. TACU "
           "does not add mounts, networks, or capabilities. See ti help docker.", ai=True)
    print()

    _zone("MEMORY / EXPORT")
    _entry("review", "ti review [--list|search TEXT]", "ti review search dns",
           "Browses retained turns so you can find and reuse an older answer. ti history, ti menu, "
           "and ti report are aliases for the same command.")
    _entry("evidence", "ti evidence [TURN]", "ti evidence 42",
           "Shows the secured raw command-output artifact attached to a retained turn; omit TURN "
           "to use the latest one.")
    _entry("copy", "ti copy [last|TURN][:LINE]", "ti copy last:1",
           "Copies a whole answer, one L### line, a range, or a fenced block to the OS clipboard.")
    _entry("clip", "ti clip [N|add TEXT]", "ti clip 3",
           "Keeps a numbered tray of reusable snippets. ti tray is the same command.")
    _entry("syntax", "ti syntax [search TEXT|N]", "ti syntax search cpu",
           "Pasteable argv cookbook from successful auto/do runs and built-in seeds. "
           "ti syntax 3 copies recipe 3; ti copy --command does the same from a turn.")
    _entry("save", "ti save [TURN] [--format md|txt|json] [--output FILE]",
           "ti save 42 --format md",
           "Exports an entire retained answer. Omit TURN for the latest response.")
    _entry("clear", "ti clear --yes", "ti clear --yes",
           "Deletes the private retained-turn history only after the explicit --yes confirmation.")
    _entry("backup", "ti backup create|list|restore …", "ti backup create ~/Dropbox",
           "Packs every database and setting into one portable .tar.gz, and restores it after a crash.")
    print()

    _zone("SETUP / SHELL")
    _entry("doctor", "ti doctor [--json]", "ti doctor",
           "Checks RAM, disk, Ollama, models, Docker, SearXNG, workspace, and PATH. ti health is "
           "the same command.")
    _entry("model", "ti model current|list|use NAME|reset", "ti model use gemma4:12b-mlx",
           "Shows or changes the persistent model. ti models is the direct installed-model list.")
    _entry("config", "ti config show|update|reset", "ti config update --context-turns 5",
           "Shows or saves model and conversation-context preferences.")
    _entry("setup", "ti setup [--workspace DIR]", "ti setup --workspace ~/TACU-Workspace",
           "Runs first-time setup or repairs the model, Docker search service, and workspace.")
    _entry("plugins", "ti plugins", "ti plugins",
           "Lists loaded providers, middleware plugins, and built-in tool profiles.")
    _entry("workspace", "ti workspace [show|enter|create DIR|use DIR]", "ti workspace enter",
           "Sets the directory file tools may write in, or opens a focused shell inside it. "
           "Bare ti workspace opens a guided menu.")
    _entry("completion", "ti completion [zsh|bash|fish|powershell]",
           "eval \"$(ti completion zsh)\"",
           "Prints deterministic tab-completion code for the selected shell.")
    _entry("shell-init", "ti shell-init [zsh|bash|fish|powershell]",
           "eval \"$(ti shell-init zsh)\"",
           "Prints completion plus TACU punctuation and ghost-prompt integration.")
    _entry("version", "ti version", "ti version",
           "Prints the installed TACU version; ti --version is equivalent.")
    _entry("all", "ti all [TOPIC]", "ti all data",
           "Opens the full capability snapshot or jumps directly to one tutorial topic. "
           "ti tutorial and ti guide are aliases.")
    print()

    _footer_box("PROGRESSIVE HELP", [
        "ti help                    this overview (static; never calls the model)",
        "ti help COMMAND            shape + example + what it does, for one command",
        "                           e.g. ti help ask · ti help juicy · ti help tools · ti help model",
        "  core topics              ask auto do run inspect web docker tools juicy extract data",
        "  state topics             review evidence copy clip syntax save clear backup workspace",
        "  setup topics             doctor setup model models config plugins completion shell-init version all",
        "ti tacu help [TOPIC]       same static help, then local-model examples",
        "                           e.g. ti tacu help data · ti tacu help tools search",
        "ti tools examples          longer native-tool recipe guide",
        "ti all                     full tutorial snapshot",
    ])
    _footer_box("ALIASES", [
        "analyze = ask · propose/plan = do · companion/focus = run",
        "history/menu/report = review · tray = clip · dataset = data · tool = tools",
        "health = doctor · tutorial/guide = all · extract ji = extract juicy",
    ])
    _footer_box("GHOST + TAB (zsh)", [
        "Dim grey after the cursor is a suggestion — not typed text",
        "→ or End / Ctrl-E accept · Esc reject · Tab completes short names (never accepts ghost)",
        "Must reload after install:  eval \"$(ti shell-init zsh)\"",
    ])
    _footer_box("GLOBAL OPTIONS", [
        "--no-ai            filter or list sources only; never call the model",
        "--dry-run          show the plan and stop",
        "--timeout SECONDS  raise the limit for slow commands (default 900 / 15 minutes; before the subcommand)",
        "-h / --help        the same shape + example help for one command",
        "paging             first 20 lines; Enter next line, Space next page, q stop",
    ])
    print(paint("└", PALETTE.violet + PALETTE.bold))


def run_ai_help(words: list[str], *, chat: Callable[[list[dict[str, str]]], str]) -> int:
    """Print matching static help, then local-model examples grounded on that text."""

    tokens = [token for token in words if token]
    buf = io.StringIO()
    with redirect_stdout(buf):
        if not tokens:
            print_quick_help()
            known = True
        else:
            known = show_command_help(tokens[0])
    static_raw = buf.getvalue()
    static = strip_ansi(static_raw)
    if static_raw:
        print(static_raw, end="" if static_raw.endswith("\n") else "\n")
    if not known and tokens:
        print(paint(f"No static help topic named {tokens[0]!r}; the model will still try.", PALETTE.muted))
    print()
    print(paint("✨ EXAMPLES (local model)", PALETTE.accent + PALETTE.bold))
    topic = " ".join(tokens) if tokens else "choosing a TACU command"
    detail = " ".join(tokens[1:]) if len(tokens) > 1 else ""
    system = (
        "You are TACU's help assistant. Ground every flag and command in the STATIC HELP below. "
        "Do not invent flags, commands, or options that are not in the static help. "
        "Give 2 to 4 extra examples that are NOT already shown after '|  e.g.' in the static help. "
        "Output ONLY those examples as lines with exactly four fields separated by ' | ': "
        "short-name | SYNTAX SHAPE | pasteable ti command | one sentence describing what it does. "
        "SYNTAX SHAPE uses UPPERCASE for values the user supplies, [brackets] for optional, and a|b for choices. "
        "No markdown, no numbering, no intro, no closing remark."
    )
    user = f"STATIC HELP:\n{static[:12_000] or '(overview: pick ask, auto, run, tools, data, or help)'}\n\n"
    user += f"User asked for help on: {topic}"
    if detail:
        user += f"\nSpecifically: {detail}"
    try:
        answer = chat([{"role": "system", "content": system}, {"role": "user", "content": user}])
    except Exception as error:
        print(paint(f"Static help is above. The model could not add examples: {error}", PALETTE.muted))
        return 0 if known else 2
    _print_ai_help_examples(answer)
    return 0


def _parse_ai_help_entries(answer: str) -> list[tuple[str, str, str, str]]:
    """Parse `name | syntax | example | description` lines from the model."""

    entries: list[tuple[str, str, str, str]] = []
    text = (answer or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            text = text.split("\n", 1)[1]
    for raw in text.splitlines():
        line = raw.strip().lstrip("-*").strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip().strip("`") for part in line.split("|")]
        if len(parts) != 4:
            continue
        name, syntax, example, does = parts
        if not name or not syntax:
            continue
        if name.casefold() in {"short-name", "name"}:
            continue
        entries.append((name[:_ENTRY_WIDTH], syntax, example, does))
    return entries


def _print_ai_help_examples(answer: str) -> None:
    """Render model extras with the same syntax | e.g. | description layout as static help."""

    text = (answer or "").strip()
    if not text:
        print(paint("(empty model reply)", PALETTE.muted))
        return
    entries = _parse_ai_help_entries(text)
    if entries:
        for name, syntax, example, does in entries:
            _entry(name, syntax, example, does)
        return
    print(paint(text, PALETTE.text))


def dispatch_help(rest: list[str]) -> int:
    """`ti help` is the chooser. `ti help run` is the run topic, not argparse flags."""

    tokens = [token for token in rest if token]
    if not tokens or tokens in (["-h"], ["--help"]):
        print_quick_help()
        return 0
    topic = tokens[0]
    if topic.casefold() in {"tools", "tool"} and len(tokens) > 1 and tokens[1].casefold() in {"examples", "guide"}:
        print_tool_guide()
        return 0
    if show_command_help(topic):
        return 0
    print(paint(f"Unknown help topic: {topic}", PALETTE.red), file=sys.stderr)
    print("Try: ti help · ti tacu help TOPIC · ti help ask · ti help juicy · ti help auto · ti help run · ti all",
          file=sys.stderr)
    return 2


def print_tool_guide() -> None:
    print(logo())
    print(_heading("NATIVE TOOL RECIPES"))
    print(paint("Simple commands stay inside TACU's workspace guard, structured result, and audit trail.", PALETTE.text))
    sections = (
        ("MAP A DIRECTORY", "ti tools map PATH --depth 3", "Use --depth 4 or 5 for a wider tree; --symbols adds top-level Python symbols."),
        ("FIND FILES", "ti tools find '*.yaml' PATH --type file", "Use --case-sensitive or --case-insensitive; insensitive is the default."),
        ("FIND DIRECTORIES", "ti tools find Config PATH --type directory", "Use --type any to return both files and directories."),
        ("SEARCH TEXT", "ti tools search WORD PATH --glob '*.py' --case-insensitive", "Ripgrep when installed; otherwise a stdlib walk. Output is file:line:column plus the matching line."),
        ("REGEX SEARCH", "ti tools search 'Password\\s*=' PATH --regex --case-sensitive", "Regex is opt-in; both case modes are explicit and mutually exclusive."),
        ("READ LINES", "ti tools read FILE --start 40 --end 90", "Omit FILE to list files in this directory; Tab completes names after flags."),
        ("WRITE FILE", "ti tools write src/hello.py --content 'print(1)'", "Atomic create; add --overwrite to replace an existing file."),
        ("EDIT FILE", "ti tools edit app.py --old 'foo' --new 'bar'", "Exact-match replace with a unified diff; fails if the match count is not 1."),
        ("ADVANCED", "ti tools run TOOL --input '{JSON}'", "Use ti tools describe TOOL first to see its validated contract and risk level."),
        ("HOST PROCESS", "ti tools run process --input '{\"operation\":\"top_cpu\",\"limit\":10}'", "Native CPU/RAM process ranking; no GNU ps flags or pipes."),
        ("HOST NETWORK", "ti tools run network --input '{\"operation\":\"connections\",\"state\":\"ESTABLISHED\"}'", "TCP sockets with destination-port ranking; state can be ESTABLISHED, LISTEN, ANY, or NOT_ESTABLISHED."),
        ("HOST SERVICE", "ti tools run service --input '{\"operation\":\"list\"}'", "launchd services on macOS; start/stop require review."),
        ("HOST PACKAGE", "ti tools run package --input '{\"operation\":\"outdated\"}'", "Homebrew list/search/info/outdated; install is gated."),
        ("HOST SECURITY", "ti tools run security --input '{\"operation\":\"gatekeeper\"}'", "Gatekeeper, codesign, quarantine, and SHA-256 without invented flags."),
        ("HOST FORENSICS", "ti tools run forensics --input '{\"operation\":\"sweep\"}'", "Correlated endpoint check: outbound with owning process and signature, exposed listeners, persistence, credential readers. Operations: sweep, outbound, listening, persistence, secret_access."),
        ("HOST DOCKER", "ti tools run docker --input '{\"operation\":\"ps\"}'", "Running containers with name, image, and network. start/stop/rm/rmi/pull need ti do."),
        ("HOST OLLAMA", "ti tools run ollama --input '{\"operation\":\"running_models\"}'", "Loaded models and size. pull/rm/stop need ti do."),
        ("HOST GIT", "ti tools run git --input '{\"operation\":\"status\"}'", "Repo status, log, diff, branch, remote. add/commit/push need ti do."),
    )
    for title, command, meaning in sections:
        print()
        print(paint(title, PALETTE.accent + PALETTE.bold))
        print(paint("  " + command, PALETTE.yellow))
        print(paint("  " + meaning, PALETTE.muted))
    print()
    print(paint("Tip: add --json to map, find, search, read, write, or edit for scripts and downstream processing.", PALETTE.green))


TOPICS = {
    "forensics": ("TI FORENSICS — IS THIS MACHINE CLEAN?", (
        "One question, correlated answer. TACU ties each connection to the process that owns it,",
        "that process to its executable, and the executable to its location and signing authority.",
        "A finding is raised only when more than one weak signal agrees, so a signed binary in a",
        "normal place is never flagged and an unsigned binary in /tmp that also holds a socket is.",
        "Checks that need root are named as not inspected rather than skipped silently.",
        "Everything is a native read: ti do shows the same plan, ti auto still refuses invented shell.",
        "",
        "Full sweep:",
        "  ti auto am i compromised",
        "  ti auto check my machine for malware",
        "Individual checks:",
        "  ti auto is anything calling home              # outbound, with the owning process",
        "  ti auto is something reading my ssh keys      # who holds credential files open",
        "  ti auto is a process stealing my aws credentials",
        "  ti auto what starts automatically at login    # persistence entries",
        "  ti auto which ports are reachable from outside",
        "One destination:",
        "  ti auto am i connected to example.com",
        "  Matched by DNS address, reverse DNS, or the TLS certificate the endpoint serves,",
        "  so a site behind a CDN or WAF is still attributed. The answer names which was used.",
        "Raw contract:",
        "  ti tools run forensics --input '{\"operation\":\"sweep\"}'",
        "  operations: sweep, outbound, listening, persistence, secret_access",
        "",
        "Going deeper with sudo:",
        "  ti do am i compromised          # then approve the plan; add elevated to the step",
        "  TACU never asks for, reads, or stores your password. Authenticate yourself first with",
        "  `sudo -v`; TACU then runs a fixed list of read-only commands with `sudo -n` and reports",
        "  exactly which ones. Without a valid credential it prints what it would have run and stops.",
        "",
        "Limits worth knowing:",
        "  A snapshot, not a recording. A callback that connects and exits between runs is missed.",
        "  Signed is not the same as safe, and unsigned is not the same as malicious.",
        "  Without sudo, other users' processes, root cron and system daemons are reported as",
        "  not inspected rather than skipped silently.",
    )),
    "automation": ("INTENT-FIRST EXECUTION", (
        "ti auto and ti do plan host commands. ti ask talks to the model. ti run uses a command you name.",
        "Read-only discovery (Desktop, Downloads, process lists, app metadata) may leave the workspace.",
        "Writes, opens, installs, and process changes still pause for review.",
        "Examples:",
        "  ti auto which process is consuming most CPU",
        "  ti do find all images on Desktop",
        "  ti ask translate this into polite language",
        "  ti run -q what is my primary IP -- ifconfig",
    )),
    "auto": ("TI AUTO — TACU INSPECTS THIS MAC", (
        "Use this when you want a host fact and you do not already have a command.",
        "TACU picks a native recipe (process, network, filesystem, apps) and runs SAFE reads now.",
        "Not for translation, tone, or explanation — that is ti ask.",
        "Not for a command you already know — that is ti run or ti inspect.",
        "Failed or mismatched results retry with native recipes, at most five times.",
        "TACU cannot cd your shell; it would only change a child process.",
        "Create/serve uses the TACU workspace. If this directory differs, you can switch or keep.",
        "OS-critical paths (/System, /usr, /etc, …) cannot be created, edited, or deleted.",
        "When a native recipe is unclear, TACU shortlists capabilities; the model picks tool+operation,",
        "then a critic checks the goal (file content, server URL) and may correct once.",
        "Examples:",
        "  ti auto which process is consuming most CPU",
        "  ti auto top 5 running processes as per memory",
        "  ti auto find all images on Desktop",
        "  ti auto create a simple index.html and open it in Chrome",
        "  ti auto --dry-run top outbound TCP destination ports",
    )),
    "do": ("TI DO — REVIEW THEN RUN", (
        "What: the same planner as ti auto, but every step waits for you.",
        "How: TACU proposes an argument-safe command. You type execute, edit, or abort.",
        "When: you want to see the recipe before it runs, or the step is permission-gated.",
        "Typing execute authorizes that exact command. It still cannot change this shell's directory.",
        "Language work (translate, rephrase) is sent to the model instead of a command plan.",
        "Examples:",
        "  ti do find all images on Desktop",
        "  ti do find duplicate large files in this workspace",
        "  ti do --dry-run top tcp 443 destinations",
    )),
    "web": ("WEB RESEARCH — LOCAL SEARCH, GUARDED READING", (
        "Search goes only to TACU's tacu-searxng container (127.0.0.1:8080, or the next free port); no search API key is used.",
        "The normal command keeps eight sources, reads the top three public pages, and asks the local model for a cited answer.",
        "Fetched content is untrusted evidence. TACU uses GET only, no cookies, public addresses only, same-origin redirects, and hard byte/context bounds.",
        "Search and page reading fail explicitly; there is no silent cloud fallback.",
        "Examples:",
        "  ti web current macOS security updates",
        "  ti web --snippets ransomware trends 2026",
        "  ti web --results 12 --read 5 compare current container scanners",
        "  ti web search local AI model benchmarks",
        "  ti web fetch https://example.com/article",
        "  ti web health",
        "  ti web --json search current security advisories",
        "Options must precede the query so natural question words remain intact.",
    )),
    "questions": ("TI ASK — LANGUAGE ONLY, NO COMMAND RUNS", (
        "Use this when you want words changed or explained. TACU does not plan or run host commands.",
        "Translate, rephrase, rewrite, summarize, or interpret output you already captured.",
        "Everything after ask is one question. Pipe finite command output in as evidence.",
        "Pipes are classified (JSON / CSV / logs) and filtered before any model call.",
        "  cat data.json | ti ask what keys are present",
        "  cat data.json | ti ask --keys name,status summarize",
        "  cat report.csv | ti ask --cols host,port --grep open which rows",
        "  cat app.log | ti ask --grep ERROR --head 40",
        "  cat data.json | ti ask --no-ai what keys are present",
        "A command before | must finish by itself; TACU cannot change its arguments.",
        "For host facts (CPU, IP, Desktop files) use ti auto so a native recipe runs.",
        "If you already know the command and want an answer from its stdout, use ti run.",
        "Examples:",
        "  ti ask translate this into polite language",
        "  ti ask explain why DNS records have a TTL",
        "  ifconfig | ti ask which interface has my LAN address",
        "  ls -la | ti ask which file was last modified",
        "  docker ps | ti ask which containers are unhealthy",
    )),
    "commands": ("TI RUN — YOUR COMMAND, THEN AN ANSWER", (
        "Use this when you already know the command and want TACU to answer -q from its stdout.",
        "How: ti run -q QUESTION -- COMMAND. The -- boundary is required. No shell unless --shell.",
        "Not for translation — that is ti ask. Not for raw colorized output — that is ti inspect.",
        "ti auto may replace GNU/Linux flags with a macOS native recipe. ti run keeps your argv.",
        "Ctrl+C always stops cleanly.",
        "Examples:",
        "  ti run -q what is my primary IP -- ifconfig",
        "  ti run -q were all packets successful -- ping -c 5 HOST",
        "  ti --timeout 600 run -q summarize services -- nmap -sV HOST",
        "  ti run -q what image is this container using -- docker inspect CONTAINER",
        "  ti run --shell -q summarize failed tests -- make test",
    )),
    "inspect": ("INSPECT — COLORIZE, NO MODEL", (
        "Use this when you already know the command and want readable raw stdout — zero AI.",
        "It does not call a model, does not plan steps, and does not rewrite flags.",
        "Not for translation (ti ask), host recipes (ti auto), or a -q answer (ti run).",
        "The -- before the command is required, the same as ti run.",
        "There is no --all flag. To see every interface, run: ti inspect -- ifconfig",
        "Examples:",
        "  ti inspect -- ifconfig",
        "  ti inspect -- ps aux",
        "  ti inspect -- mdls -name kMDItemFSCreationDate /Applications/Falcon.app",
    )),
    "docker": ("DOCKER & CONTAINER TOOLS", (
        "Run a tool already installed in a container, capture its result, then ask about it.",
        "TACU does not silently add privileges, mounts, networks, or capabilities.",
        "Examples:",
        "  ti docker kali -q explain these SMB findings -- nxc smb 10.0.0.5",
        "  ti docker scanner -q prioritize fixes -- trivy image app:latest --format json",
    )),
    "workspace": ("FOCUSED WORKSPACES", (
        "Interactive TACU sessions keep the shell directory you launched from; the selected workspace is shown separately.",
        "ti workspace opens a guided menu; ti workspace enter opens a focused shell inside the workspace.",
        "Examples:",
        "  ti workspace",
        "  ti workspace create ~/Projects/Assessment",
        "  ti workspace enter",
    )),
    "memory": ("MEMORY, COPY, CLIP & SAVE", (
        "Answers show a left gutter L001, L002, … — placeholders only, not part of the text.",
        "Decorative markdown (**bold**, fancy quotes) is stripped on screen and on copy.",
        "What you see after L### is exactly what ti copy / ti clip will paste (code fences kept).",
        "",
        "Copy from a turn:",
        "  ti copy                 whole latest answer (same as ti copy last)",
        "  ti copy last            same as ti copy",
        "  ti copy last:1          only L001 of the latest answer",
        "  ti copy last:2-3        lines 2 through 3 of the latest answer",
        "  ti copy 42              whole turn 42",
        "  ti copy 42:3            only line 3 of turn 42 (use the L003 gutter)",
        "  ti copy 42:10-14        lines 10 through 14",
        "  ti copy last --block 1  first ``` code/command block of the latest answer",
        "  ti copy last:3 --to-clip  put that line into the tray (not OS paste yet)",
        "  ti copy --command       latest OS-flavored recipe argv (see ti syntax)",
        "  ti copy --command 3     recipe #3 · ti copy --command cpu  (search)",
        "",
        "Command cookbook (pasteable argv from auto/do + built-in seeds):",
        "  ti syntax / ti syntax search cpu",
        "  ti syntax 3 · ti syntax show 3 · ti syntax seed",
        "",
        "Clipboard tray (side-channel, max 50 — does not cover your TTY):",
        "  ti clip                 list numbered tray items",
        "  ti clip add \"text\"",
        "  ti clip add --from-turn 42:3",
        "  ti clip 3               copy tray #3 into the OS clipboard, then paste normally",
        "  ti clip show 3 · ti clip edit 3 \"…\" · ti clip rm 3",
        "  ti clip search dns · ti clip clear --yes",
        "",
        "Tip: blank lines still get an L### number. If copy says blank, try the next L number.",
        "Split-pane tray (top/bottom 30%) needs tmux/zellij — TACU will not take over Terminal scroll.",
        "",
        "Also: ti review search dns · ti history · ti menu · ti save 42 --format md · ti extract juicy scan.txt -o out.csv",
    )),
    "clip": ("CLIPBOARD TRAY", (
        "Tray # numbers match `ti clip list`. After clear (or deleting the last item), the next add is #1.",
        "While items remain, numbers stay stable (gaps are OK) so `ti clip 3` keeps meaning the same slot.",
        "  ti clip / ti clip list",
        "  ti clip add \"brew upgrade\"",
        "  ti copy 42:3 --to-clip",
        "  ti clip 3          → OS clipboard (Cmd/Ctrl-V to paste in Terminal or Outlook)",
        "  ti clip show 3 · ti clip edit 3 \"…\" · ti clip rm 3 · ti clip search brew",
        "Interactive: :clip · :clip 3 · :clip add text",
    )),
    "review": ("REVIEW TURNS — LIST, SEARCH, BROWSE", (
        "Retained answers (max 100). Same commands: ti review · ti history · ti menu · ti report.",
        "  ti review                 interactive browse",
        "  ti review --list          table of ID / MODEL / QUERY",
        "  ti review search dns      filter query + response + model",
        "  ti history find CPU       same as search",
        "Then: ti copy last:1 · ti save 42 --format md · open ID in the menu.",
        "Interactive menu: type search text, /dns, [a]ll, or a turn ID.",
        "Also: ti help memory · ti help clip · ti clip search …",
    )),
    "syntax": ("COMMAND COOKBOOK — PASTEABLE ARGV", (
        "Indexed recipes pair a capability op with OS-flavored shell argv you can paste.",
        "Successful ti auto / ti do runs upsert pasteable argv from tool recipe fields.",
        "Built-in seeds cover process list, listening TCP, connections, ollama list.",
        "Examples:",
        "  ti syntax",
        "  ti syntax search cpu",
        "  ti syntax 3",
        "  ti syntax show 3",
        "  ti copy --command",
        "  ti copy --command 3",
        "  ti syntax add -- /usr/bin/sw_vers",
        "  ti syntax seed",
    )),
    "tools": ("NATIVE TOOLS — SIMPLE AND ADVANCED", (
        "Simple commands translate into the same bounded, validated, and audited core contracts.",
        "A relative path uses the selected TACU workspace; an explicit absolute directory selects that directory.",
        "Directory maps:",
        "  ti tools map . --depth 3",
        "  ti tools map ~/Projects/App --depth 5 --symbols",
        "Find files or directories by name/glob and case policy:",
        "  ti tools find settings.py . --type file --case-insensitive",
        "  ti tools find Config ~/Projects/App --type directory --case-sensitive",
        "  ti tools find 'cache*' . --type any",
        "Search file contents (ripgrep when installed, otherwise a stdlib walk):",
        "  ti tools search authentication . --case-insensitive",
        "  ti tools search 'Password\\s*=' . --regex --glob '*.py' --case-sensitive",
        "Read an exact numbered line range:",
        "  ti tools read src/app.py --start 40 --end 90",
        "  ti tools read --start 5          (lists files in this directory)",
        "Write or edit a workspace file:",
        "  ti tools write src/hello.py --content 'print(1)'",
        "  ti tools edit app.py --old 'foo' --new 'bar'",
        "Discover contracts or use advanced JSON input:",
        "  ti tools list",
        "  ti tools describe search_code",
        "  ti tools run repo_map --input {JSON_OBJECT}",
        "  ti tools run process --input {\"operation\":\"top_cpu\",\"limit\":10}",
        "  ti tools run network --input {\"operation\":\"connections\",\"state\":\"ESTABLISHED\"}",
        "  ti tools examples",
    )),
    "setup": ("CONFIG SETUP — MODELS & HEALTH", (
        "Doctor checks hardware, Ollama, models, workspace, and command availability.",
        "Examples:",
        "  ti doctor",
        "  ti config",
        "  ti config update --model qwen2.5-coder:7b --context-turns 5",
        "  ti config show",
        "  ti model",
        "  ti model use qwen2.5-coder:7b",
        "  ti models",
        "  ti setup",
        "  ti plugins",
    )),
    "safety": ("NATURAL QUESTIONS & GUARDRAILS", (
        "Ordinary multiword questions do not need outer quotes.",
        "Question marks and single/double-quoted groups do not end a TACU question.",
        "Empty quote groups ('' and \"\") are ignored; surrounding question words stay joined.",
        "For run/docker, -- is mandatory after -q; ambiguous input runs nothing.",
        "TACU's zsh integration passes ?, *, and brackets literally to ti/ticu.",
        "After installing in an open zsh: source ~/.zshrc",
        "Or activate directly: eval \"$(command ticu shell-init zsh)\"",
        "The shell still processes structural operators such as |, >, ;, &, $ and parentheses first.",
        "Quote or escape those structural operators when they are literal question content.",
        "To preserve literal quotes: ti ask explain the phrase '\"zero trust\"'",
        "Old quoted commands remain fully supported.",
    )),
    "tacu": ("TI TACU HELP — MODEL-ASSISTED EXAMPLES", (
        "ti tacu help TOPIC asks the local model for examples on top of static help.",
        "ti help COMMAND stays the dense built-in reference and never calls the model.",
        "Examples:",
        "  ti tacu help",
        "  ti tacu help data",
        "  ti tacu help data ask --ttl",
        "  ti tacu help tools search",
        "  ti help data",
    )),
}

ALIASES = {
    "0": "auto", "do": "do", "auto": "auto", "propose": "do", "plan": "do",
    "automation": "auto",
    "w": "web", "web": "web", "search": "web", "fetch": "web",
    "1": "questions", "ask": "questions", "analyze": "questions", "2": "commands", "run": "commands",
    "i": "inspect", "inspect": "inspect", "colorize": "inspect",
    "3": "docker", "containers": "docker", "4": "workspace",
    "5": "memory", "history": "review", "review": "review", "report": "review", "menu": "review", "r": "review",
    "copy": "memory", "clip": "clip", "tray": "clip", "clipboard": "clip",
    "syntax": "syntax", "recipe": "syntax", "recipes": "syntax", "cookbook": "syntax", "s": "syntax",
    "6": "tools", "tools": "tools", "tool": "tools",
    "7": "setup", "health": "setup", "config": "setup", "doctor": "setup",
    "model": "setup", "models": "setup", "plugins": "setup", "version": "setup",
    "completion": "setup", "shell-init": "setup",
    "8": "safety", "quotes": "safety",
    "backup": "backup", "restore": "backup", "9": "backup", "b": "backup",
    "data": "data", "dataset": "data", "10": "data", "d": "data",
    "tacu": "tacu",
    "save": "save", "extract": "extract", "juicy": "extract", "ji": "extract", "j": "extract",
    "evidence": "review", "clear": "review",
    "all": "all", "tutorial": "all", "guide": "all",
}


def _show_topic(name: str, *, heading: bool = True) -> bool:
    key = ALIASES.get(name.casefold(), name.casefold())
    printer = _DENSE_HELP.get(key)
    if printer:
        printer()
        return True
    topic = TOPICS.get(key)
    if not topic:
        return False
    title, lines = topic
    if heading:
        print()
        print(_heading(title))
    for line in lines:
        if not line.strip():
            print()
            continue
        color = PALETTE.accent if line.lstrip().startswith(("ti ", "ifconfig", "docker ", "nmap ", "ls ", "ex:")) else PALETTE.text
        print(paint(line, color))
    return True


def run_tutorial(topic: str | None = None) -> int:
    print(logo())
    print(paint("FULL CAPABILITY SNAPSHOT", PALETTE.accent + PALETTE.bold))
    print()
    rows = (
        ("0", "automation", "Describe intent; review commands or use bounded autopilot"),
        ("W", "web", "Search locally, read public pages safely, and cite sources"),
        ("1", "questions", "Ask directly or analyze piped output"),
        ("2", "commands", "Run a command and request one exact answer"),
        ("I", "inspect", "Colorize a command you already know; no AI"),
        ("3", "docker", "Run tools inside existing containers"),
        ("4", "workspace", "Keep work focused in one directory"),
        ("5", "memory", "Browse turns, copy L### lines, and use the clipboard tray"),
        ("R", "review", "Search and open retained turns (ti review search …)"),
        ("C", "clip", "Persistent clipboard tray — add, search, paste to OS clipboard"),
        ("S", "syntax", "OS command cookbook — ti syntax / ti copy --command"),
        ("J", "juicy", "Extract identifiers locally; ask only the matching slice"),
        ("D", "data", "Load a large file, query it, or run ti data juicy"),
        ("B", "backup", "Pack and restore TACU databases and settings"),
        ("6", "tools", "Use coding and native host tools"),
        ("7", "Config setup", "Check health, models, providers, and installation"),
        ("8", "safety", "Learn natural-query syntax and guardrails"),
    )
    for number, name, summary in rows:
        print(_command(((f"  [{number}] ", PALETTE.violet), (f"{name:<13}", PALETTE.green + PALETTE.bold),
                        (summary, PALETTE.text))))
    print()
    print(paint("Flow: capture → normalize → extract facts → prune noise → answer → retain one turn", PALETTE.muted))
    if topic:
        if not _show_topic(topic):
            print(paint(f"Unknown tutorial topic: {topic}", PALETTE.red), file=sys.stderr)
            print("Choose: " + ", ".join(TOPICS), file=sys.stderr)
            return 2
        return 0
    if not sys.stdin.isatty():
        print()
        print("Deep dive with: ti all TOPIC")
        print("Topics: " + ", ".join(TOPICS))
        return 0
    while True:
        try:
            choice = input(paint("Deep dive [0-8/W/I/C/R/S/J/D/B], or [q] quit > ", PALETTE.muted)).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in {"", "q", "quit", "back"}:
            return 0
        if not _show_topic(choice):
            print(paint("Choose 0-8, W, I, C, R, S, J, D, B, a topic name, or q.", PALETTE.red))
