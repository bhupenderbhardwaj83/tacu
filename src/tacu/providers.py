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
        self.num_predict = _bounded_env_int("TACU_NUM_PREDICT", 1024, 32, 4096)
        self.keep_alive = os.environ.get("TACU_KEEP_ALIVE", DEFAULT_KEEP_ALIVE)

    def models(self) -> list[str]:
        payload = self._json_request("GET", "/api/tags")
        return [item["name"] for item in payload.get("models", []) if isinstance(item.get("name"), str)]

    def chat(self, messages: list[dict[str, str]], *, stream: bool) -> Iterable[str]:
        yield from self._chat_once(self.model, messages, stream=stream)

    def _chat_once(self, model: str, messages: list[dict[str, str]], *, stream: bool) -> Iterable[str]:
        # Do not send think:false — Ollama 0.32.14 Gemma MLX often returns empty content with it.
        payload = json.dumps({
            "model": model,
            "messages": messages,
            "stream": stream,
            "keep_alive": self.keep_alive,
            "options": {"num_ctx": self.num_ctx, "num_predict": self.num_predict, "temperature": 0.1},
        }, ensure_ascii=False).encode()
        request = urllib.request.Request(f"{self.base_url}/api/chat", data=payload,
                                         headers={"Content-Type": "application/json"}, method="POST")
        try:
            response = urllib.request.urlopen(request, timeout=self.timeout)
            if stream:
                yielded = False
                thinking_bits: list[str] = []
                with response:
                    for raw_line in response:
                        if not raw_line.strip():
                            continue
                        event = json.loads(raw_line)
                        if event.get("error"):
                            raise TacuError(str(event["error"]))
                        content, thinking = _assistant_parts(event.get("message") or {})
                        if content:
                            yielded = True
                            yield content
                        elif thinking:
                            thinking_bits.append(thinking)
                if not yielded and thinking_bits:
                    yield "".join(thinking_bits)
                return
            with response:
                event = json.load(response)
            text = _assistant_text(event.get("message") or {})
            if text:
                yield text
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            missing = error.code in {404, 400} and "not found" in detail.casefold()
            if missing and model != DEFAULT_BACKUP_MODEL:
                self.model = DEFAULT_BACKUP_MODEL
                yield from self._chat_once(DEFAULT_BACKUP_MODEL, messages, stream=stream)
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
