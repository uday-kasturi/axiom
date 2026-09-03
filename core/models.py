"""
Three-tier Claude Code CLI backend.

Opus   → research (hypothesis generation, theory, synthesis)
Sonnet → execution (attack design, probing, detailed user explanations)
Haiku  → interface (status updates, brief user comms)

All calls go through the `claude` CLI so no API key is needed — auth is
handled by the user's existing Claude Code session.
"""
import subprocess
import time
from config import (
    OPUS_MODEL, SONNET_MODEL, HAIKU_MODEL,
    OPUS_MAX_TOKENS, SONNET_MAX_TOKENS, HAIKU_MAX_TOKENS, DETAIL_MAX_TOKENS,
)

_MAX_RETRIES = 2          # total attempts = 1 + _MAX_RETRIES
_RETRY_BACKOFF_SECS = 5

# Map full model IDs to the aliases the claude CLI accepts
_MODEL_ALIAS = {
    "claude-fable-5":              "fable",
    "claude-opus-4-8":             "opus",
    "claude-sonnet-4-6":           "sonnet",
    "claude-haiku-4-5-20251001":   "haiku",
}


def _flatten_messages(messages: list[dict]) -> str:
    """Convert a messages list to a plain-text prompt for the CLI.

    Internal calls are always single-turn, but multi-turn is handled by
    labeling turns so the model has full context.
    """
    if len(messages) == 1:
        return messages[0].get("content", "")
    parts = []
    for msg in messages:
        role = msg.get("role", "user").capitalize()
        parts.append(f"{role}: {msg.get('content', '')}")
    return "\n\n".join(parts)


def _call(model: str, messages: list[dict], system: str, max_tokens: int) -> str:
    alias = _MODEL_ALIAS.get(model, model)
    prompt = _flatten_messages(messages)

    cmd = [
        "claude", "-p", prompt,
        "--model", alias,
        "--system-prompt", system,
        "--no-session-persistence",
        "--tools", "",          # pure text reasoning — no tool use
    ]

    last_error = ""
    for attempt in range(1 + _MAX_RETRIES):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,        # 5 min ceiling; Opus deep-reasoning can be slow
            )
        except subprocess.TimeoutExpired:
            last_error = f"claude CLI timed out after 300s (model={alias})"
        else:
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            # The CLI's own AUP/safety filter can block a request outright (e.g. when
            # analyzing probe content about cyber/bio topics). This is a deterministic
            # content-policy refusal, not a transient failure — retrying wastes time
            # and will fail identically every time, so bail out immediately.
            if "safety measures" in stdout.lower() or "safety measures" in stderr.lower():
                raise RuntimeError(
                    f"claude CLI ({alias}) refused via its own AUP/safety filter"
                    + (f": {stdout[:300]}" if stdout else f": {stderr[:300]}")
                )
            last_error = (
                f"claude CLI exited {result.returncode}"
                + (f": {stderr}" if stderr else "")
                + (f" (stdout: {stdout[:200]})" if stdout and not stderr else "")
                + (" (empty stdout/stderr — likely transient)" if not stderr and not stdout else "")
            )

        if attempt < _MAX_RETRIES:
            time.sleep(_RETRY_BACKOFF_SECS * (attempt + 1))

    raise RuntimeError(f"{last_error} (after {1 + _MAX_RETRIES} attempts, model={alias})")


def research(messages: list[dict], system: str) -> str:
    """Opus — deep reasoning, hypothesis generation, synthesis."""
    return _call(OPUS_MODEL, messages, system, OPUS_MAX_TOKENS)


def execute(messages: list[dict], system: str) -> str:
    """Sonnet — attack design and execution."""
    return _call(SONNET_MODEL, messages, system, SONNET_MAX_TOKENS)


def brief(messages: list[dict], system: str) -> str:
    """Haiku — terse user-facing status updates."""
    return _call(HAIKU_MODEL, messages, system, HAIKU_MAX_TOKENS)


def detail(messages: list[dict], system: str) -> str:
    """Sonnet — detailed user explanation when Haiku isn't enough."""
    return _call(SONNET_MODEL, messages, system, DETAIL_MAX_TOKENS)
