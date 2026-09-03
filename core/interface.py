"""
User-facing communication layer.

Haiku handles all status and brief output.
Sonnet steps in only when the user explicitly asks for more detail.
"""
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from core import models

console = Console()

_HAIKU_SYSTEM = """You are the user interface for Axiom, a research-grade AI red teaming engine.
Communicate status, findings, and updates in 1-3 sentences maximum.
Be direct. Use technical language — the user is a security researcher.
Never pad responses. If nothing is happening, say so in one sentence."""

_SONNET_SYSTEM = """You are providing a detailed technical explanation for a security researcher
using Axiom, an AI red teaming engine. Be thorough, precise, and technical.
Structure your response clearly. Include specific details about findings, methods, and implications."""


def status(msg: str, *, polish: bool = False) -> None:
    """Print a status update.

    By default the message is printed verbatim (fast, free). Pass polish=True
    to route it through Haiku for rephrasing — only worth it for raw/messy input,
    not for the already-formatted status strings the engine emits.
    """
    if not polish:
        console.print(f"[dim cyan]◆[/] {msg}")
        return
    try:
        response = models.brief(
            [{"role": "user", "content": f"Provide a brief status update: {msg}"}],
            _HAIKU_SYSTEM,
        )
    except Exception:
        response = msg
    console.print(f"[dim cyan]◆[/] {response}")


def finding(title: str, summary: str, confidence: float) -> None:
    """Display a finding with severity coloring."""
    color = "red" if confidence >= 0.85 else "yellow" if confidence >= 0.4 else "dim"
    label = "CONFIRMED" if confidence >= 0.85 else "PARTIAL" if confidence >= 0.4 else "WEAK"
    console.print(Panel(
        f"[bold]{summary}[/bold]\n[dim]confidence: {confidence:.0%}[/dim]",
        title=f"[{color}][{label}] {title}[/]",
        border_style=color,
    ))


def explain(context: str) -> str:
    """Sonnet gives a detailed explanation when the user asks for more."""
    response = models.detail(
        [{"role": "user", "content": f"Explain in detail: {context}"}],
        _SONNET_SYSTEM,
    )
    console.print(Panel(response, title="[blue]Detail[/]", border_style="blue"))
    return response


def ask(prompt: str) -> str:
    """Prompt the user for input."""
    return console.input(f"[bold cyan]?[/] {prompt} ")


def error(msg: str) -> None:
    console.print(f"[red]✗[/] {msg}")


def info(msg: str) -> None:
    console.print(f"[dim]  {msg}[/]")
