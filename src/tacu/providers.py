"""Built-in Ollama provider and provider plugin loading."""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from importlib import metadata
from typing import Any, Iterable, Protocol

from .core import DEFAULT_BACKUP_MODEL, DEFAULT_KEEP_ALIVE, DEFAULT_TIMEOUT_SECONDS, TacuError


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        return default
    return min(maximum, max(minimum, value))


# A full listing is a legitimate answer and a long one. Asking for the names of
# 77 files needs more room than 4096 tokens leaves once a model has spent some of
# them thinking, and the ceiling only costs anything on the retry path.
_MAX_NUM_PREDICT = 8192
_RETRY_NUM_PREDICT = 2048


def _bounded_env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, "") or default)
    except ValueError:
        return default
    return min(maximum, max(minimum, value))


def _assistant_parts(message: dict[str, Any]) -> tuple[str, str]:
    content = message.get("content") if isinstance(message.get("content"), str) else ""
    thinking = message.get("thinking") if isinstance(message.get("thinking"), str) else ""
    return content, thinking


def _assistant_text(message: dict[str, Any]) -> str:
    """Gemma 4 MLX on Ollama 0.32.14 often fills `thinking` and leaves `content` empty."""

    content, thinking = _assistant_parts(message)
    return (content or thinking).strip()


class ModelProvider(Protocol):
    model: str

    def models(self) -> list[str]: ...
    def chat(self, messages: list[dict[str, str]], *, stream: bool) -> Iterable[str]: ...


class OllamaProvider:
    def __init__(self, base_url: str, model: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = _bounded_env_int("TACU_NUM_CTX", 8192, 2048, 131072)
        # Gemma 4 spends the first tokens on hidden thinking; 256 often never reaches `content`.
        self.num_predict = _bounded_env_int("TACU_NUM_PREDICT", 1024, 32, _MAX_NUM_PREDICT)
        self.repeat_penalty = _bounded_env_float("TACU_REPEAT_PENALTY", 1.1, 1.0, 2.0)
        self.keep_alive = os.environ.get("TACU_KEEP_ALIVE", DEFAULT_KEEP_ALIVE)

    def models(self) -> list[str]:
        payload = self._json_request("GET", "/api/tags")
        return [item["name"] for item in payload.get("models", []) if isinstance(item.get("name"), str)]

    def reply_budgets(self) -> list[int]:
        """Budgets TACU will try, smallest first.

        A single fixed budget only ever suits the machine it was measured on:
        256 was too small once, and 1024 is too small for a model that reasons
        at length or starts repeating. The harness owns this escalation so a
        working answer never depends on the user setting an environment variable.
        """

        # Two attempts, not three. A middle rung helps nothing: a reply cut off at
        # the limit needs the widest budget, and a model looping on its own
        # reasoning will loop at every budget. The third rung only ever cost
        # another minute of the user's time before failing the same way.
        ladder = [self.num_predict, _MAX_NUM_PREDICT]
        budgets: list[int] = []
        for budget in ladder:
            if budget > (budgets[-1] if budgets else 0):
                budgets.append(budget)
        return budgets

    def chat(self, messages: list[dict[str, str]], *, stream: bool) -> Iterable[str]:
        budgets = self.reply_budgets()
        outcome: dict[str, Any] = {}
        for index, budget in enumerate(budgets):
            outcome = {}
            final = index == len(budgets) - 1
            yield from self._chat_once(self.model, messages, stream=stream,
                                       outcome=outcome, num_predict=budget,
                                       can_retry=not final)
            # Two ways a budget runs out. Only hidden reasoning came back, cut off
            # mid-thought; or the answer itself was cut off partway — "there are 31
            # files" followed by twenty of them. Neither is an answer, so widen the
            # budget and ask again rather than presenting half a list as complete.
            if outcome.get("answered_from_thinking") and not final:
                # Reasoning is not an answer. Ask once more for the answer itself
                # rather than printing the scratchpad and calling it a reply.
                messages = list(messages) + [{
                    "role": "user",
                    "content": ("Answer the question directly now. Give the answer itself, "
                                "not your reasoning about how to find it, and do not "
                                "describe tools you are going to call."),
                }]
                continue
            if not outcome.get("spent_budget_thinking") and not outcome.get("truncated"):
                return
            if final:
                break
        if outcome.get("truncated"):
            # The longest attempt still ran out. Say so: an answer that stops in the
            # middle and does not admit it is worse than one that admits it.
            yield ("\n\n_This answer was cut off at the "
                   f"{budgets[-1]}-token reply limit and is incomplete. Ask for a "
                   "narrower slice, or raise the limit with TACU_NUM_PREDICT._")
            return
        yield ("TACU retried up to a "
               f"{budgets[-1]}-token reply and {self.model} still returned only internal "
               "reasoning, which usually means it is repeating itself rather than "
               "answering. A lighter model handles this better: "
               "ti config update --model qwen2.5-coder:7b")

    def chat_tools(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
                   *, num_predict: int | None = None,
                   temperature: float = 0.1) -> dict[str, Any]:
        """One turn with native tool calling: returns the content and the calls.

        The model decides the next single action rather than writing a whole plan
        up front, which is the difference between adapting to what a file actually
        contains and guessing at it beforehand.
        """

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {"num_ctx": self.num_ctx,
                        "num_predict": self.num_predict if num_predict is None else num_predict,
                        "temperature": temperature,
                        "repeat_penalty": self.repeat_penalty},
        }, ensure_ascii=False).encode()
        request = urllib.request.Request(f"{self.base_url}/api/chat", data=payload,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                event = json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise TacuError(f"{self.model} refused the request: {detail[:300]}") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise TacuError(f"Ollama did not answer within {self.timeout}s: {error}") from error
        message = event.get("message") or {}
        content, thinking = _assistant_parts(message)
        calls: list[dict[str, Any]] = []
        for raw in message.get("tool_calls") or []:
            function = raw.get("function") or {}
            name = str(function.get("name") or "").strip()
            if not name:
                continue
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except ValueError:
                    arguments = {}
            calls.append({"name": name,
                          "arguments": arguments if isinstance(arguments, dict) else {}})
        return {"content": (content or "").strip(), "thinking": (thinking or "").strip(),
                "tool_calls": calls, "done_reason": event.get("done_reason", "")}

    def _chat_once(self, model: str, messages: list[dict[str, str]], *, stream: bool,
                   outcome: dict[str, Any] | None = None,
                   num_predict: int | None = None,
                   can_retry: bool = False) -> Iterable[str]:
        record = outcome if outcome is not None else {}
        budget = self.num_predict if num_predict is None else num_predict
        # Do not send think:false — Ollama 0.32.14 Gemma MLX often returns empty content with it.
        payload = json.dumps({
            "model": model,
            "messages": messages,
            "stream": stream,
            "keep_alive": self.keep_alive,
            # repeat_penalty guards against the degenerate loops that make a model
            # burn a whole budget re-listing the same tokens instead of answering.
            "options": {"num_ctx": self.num_ctx, "num_predict": budget, "temperature": 0.1,
                        "repeat_penalty": self.repeat_penalty},
        }, ensure_ascii=False).encode()
        request = urllib.request.Request(f"{self.base_url}/api/chat", data=payload,
                                         headers={"Content-Type": "application/json"}, method="POST")
        try:
            response = urllib.request.urlopen(request, timeout=self.timeout)
            if stream:
                content_bits: list[str] = []
                thinking_bits: list[str] = []
                done_reason = ""
                with response:
                    for raw_line in response:
                        if not raw_line.strip():
                            continue
                        event = json.loads(raw_line)
                        if event.get("error"):
                            raise TacuError(str(event["error"]))
                        if event.get("done") and isinstance(event.get("done_reason"), str):
                            done_reason = event["done_reason"]
                        content, thinking = _assistant_parts(event.get("message") or {})
                        if content:
                            # Held rather than emitted: a reply cut off at the token
                            # limit is retried with a wider budget, and text already
                            # handed to the caller cannot be taken back.
                            content_bits.append(content)
                        elif thinking:
                            thinking_bits.append(thinking)
                if content_bits:
                    if done_reason == "length" and can_retry:
                        record["truncated"] = True
                        return
                    if done_reason == "length":
                        record["truncated"] = True
                    yield "".join(content_bits)
                    return
                if thinking_bits:
                    if done_reason == "length":
                        # Cut off mid-thought: the reasoning is unfinished, not an answer.
                        record["spent_budget_thinking"] = True
                        return
                    # Finished normally with an empty `content`. Sometimes that is
                    # the Gemma MLX quirk this fallback exists for and `thinking`
                    # holds the answer; sometimes it is a scratchpad that ends
                    # "I will call network_tools.list_active_connections()" and
                    # never does. Which one it is cannot be told from the words —
                    # only from the fact that it arrived on the reasoning channel,
                    # so record that and let the caller decide.
                    record["answered_from_thinking"] = True
                    if can_retry:
                        # Hold it. Text already handed to the caller cannot be
                        # taken back, and the retry exists to replace this.
                        return
                    yield "".join(thinking_bits)
                return
            with response:
                event = json.load(response)
            message = event.get("message") or {}
            content, thinking = _assistant_parts(message)
            if content.strip():
                if event.get("done_reason") == "length":
                    record["truncated"] = True
                    if can_retry:
                        return
                yield content.strip()
            elif thinking.strip():
                record["answered_from_thinking"] = True
                if event.get("done_reason") == "length":
                    record["spent_budget_thinking"] = True
                    return
                if can_retry:
                    return
                yield thinking.strip()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            missing = error.code in {404, 400} and "not found" in detail.casefold()
            if missing and model != DEFAULT_BACKUP_MODEL:
                self.model = DEFAULT_BACKUP_MODEL
                yield from self._chat_once(DEFAULT_BACKUP_MODEL, messages, stream=stream,
                                           outcome=record, num_predict=budget)
                return
            raise TacuError(f"Ollama returned HTTP {error.code}: {detail}") from error
        except urllib.error.URLError as error:
            raise TacuError(f"Cannot reach Ollama at {self.base_url}. Start Ollama and retry: {error.reason}") from error
        except TimeoutError as error:
            raise TacuError(f"Ollama did not respond within {self.timeout} seconds. The request was stopped.") from error

    def _json_request(self, method: str, path: str) -> dict:
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{self.base_url}{path}", method=method), timeout=10) as response:
                return json.load(response)
        except urllib.error.URLError as error:
            raise TacuError(f"Cannot reach Ollama at {self.base_url}: {error.reason}") from error


def provider_is_local(client: ModelProvider) -> bool:
    """Return true only for an explicitly local plugin or a loopback Ollama endpoint."""

    if getattr(client, "local", False) is True:
        return True
    if not isinstance(client, OllamaProvider):
        return False
    host = urlsplit(client.base_url).hostname
    if not host:
        return False
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def provider_names() -> list[str]:
    names = ["ollama"]
    try:
        names.extend(point.name for point in metadata.entry_points(group="tacu.providers"))
    except TypeError:
        names.extend(point.name for point in metadata.entry_points().get("tacu.providers", []))
    return sorted(set(names))


def load_provider(name: str, *, base_url: str, model: str,
                  timeout: int = DEFAULT_TIMEOUT_SECONDS) -> ModelProvider:
    if name == "ollama":
        return OllamaProvider(base_url, model, timeout)
    try:
        points = metadata.entry_points(group="tacu.providers")
    except TypeError:
        points = metadata.entry_points().get("tacu.providers", [])
    for point in points:
        if point.name == name:
            return point.load()(base_url=base_url, model=model)
    raise TacuError(f"Unknown provider {name!r}. Installed providers: {', '.join(provider_names())}")
