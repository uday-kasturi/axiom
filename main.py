#!/usr/bin/env python3
"""
Axiom — research-grade AI red team engine

Opus   → research and hypothesis generation
Sonnet → attack design and execution
Haiku  → user interface (Sonnet for detail on request)
"""
import click
from dotenv import load_dotenv
from rich.console import Console
from rich.rule import Rule

load_dotenv()
console = Console()


@click.group()
def cli():
    """Axiom — AI model red team engine."""
    pass


@cli.command()
@click.option("--name",        required=True,  help="Human-readable target name (e.g. 'GPT-4o')")
@click.option("--model-id",    required=True,  help="Model identifier for the API (e.g. 'gpt-4o')")
@click.option("--api-type",    required=True,  type=click.Choice(["anthropic", "openai", "http", "local", "musespark"]))
@click.option("--api-key-env", default=None,   help="Env var holding the target API key (omit for local/Ollama)")
@click.option("--endpoint",    default=None,   help="API endpoint URL (required for http/local; musespark: path to muse_auth.json; default local: http://localhost:11434/v1)")
@click.option("--context",     default="",     help="Path to a file with extra context (papers, model card, notes)")
@click.option("--skip-catalog", is_flag=True,  help="Skip known-attack sweep, go straight to novel hypotheses")
@click.option("--eval-aware",   is_flag=True,  help="Target is known to detect evaluation contexts and modify behaviour (e.g. Muse Spark). Activates stealth probe design.")
def run(name, model_id, api_type, api_key_env, endpoint, context, skip_catalog, eval_aware):
    """Run a full red team session against a target model."""
    from target.profiler import build_profile, TargetAdapter
    from core.research import run_catalog_sweep, run_hypothesis_loop
    from core import interface

    console.print(Rule(f"[bold red]AXIOM[/] → {name}", style="red"))

    extra_context = ""
    if context:
        import pathlib
        p = pathlib.Path(context)
        if p.is_file():
            try:
                extra_context = p.read_text()
            except (OSError, UnicodeDecodeError) as e:
                interface.error(f"Could not read context file {context}: {e}")
                raise SystemExit(1)
        else:
            interface.error(f"Context file not found: {context}")
            raise SystemExit(1)

    if eval_aware:
        interface.status(f"Eval-aware mode ON — stealth probe design active. Target will not know it's being tested.")

    interface.status(f"Building threat model for {name}...")
    profile = build_profile(
        name=name,
        model_id=model_id,
        api_type=api_type,
        api_key_env=api_key_env,
        api_endpoint=endpoint,
        extra_context=extra_context,
        eval_aware=eval_aware,
    )
    if profile.attack_surfaces:
        interface.status(f"Threat model ready. Attack surfaces: {', '.join(profile.attack_surfaces[:3])}...")
    else:
        interface.status("Threat model ready. (No discrete attack surfaces parsed; full analysis retained for hypothesis generation.)")

    adapter = TargetAdapter(profile)
    catalog_results = []

    if not skip_catalog:
        catalog_results = run_catalog_sweep(adapter, profile)
        hits = [r for r in catalog_results if r["signal_type"] in ("confirmed", "partial")]
        interface.status(f"Catalog sweep done. {len(hits)} signals ({len([r for r in hits if r['signal_type']=='confirmed'])} confirmed).")

    confirmed = run_hypothesis_loop(adapter, profile, catalog_results, eval_aware=eval_aware)

    console.print(Rule(style="red"))
    if confirmed:
        interface.status(f"Session complete. {len(confirmed)} confirmed vulnerabilities. Check findings/.")
    else:
        interface.status("Session complete. No confirmed vulnerabilities. Partial signals saved for follow-up.")


@cli.command()
@click.argument("finding_path")
def explain(finding_path):
    """Ask Sonnet to explain a saved finding in detail."""
    import pathlib
    from core import interface
    p = pathlib.Path(finding_path)
    if not p.exists():
        interface.error(f"Not found: {finding_path}")
        return
    if not p.is_file():
        interface.error(f"Not a file: {finding_path}")
        return
    try:
        text = p.read_text()
    except (OSError, UnicodeDecodeError) as e:
        interface.error(f"Could not read {finding_path}: {e}")
        return
    if not text.strip():
        interface.error(f"File is empty: {finding_path}")
        return
    interface.explain(text)


@cli.command()
def findings():
    """List all saved disclosure reports."""
    from config import FINDINGS_DIR
    reports = sorted(FINDINGS_DIR.glob("*.md"))
    if not reports:
        console.print("[dim]No findings yet.[/]")
        return
    for r in reports:
        console.print(f"  [cyan]{r.name}[/]")


if __name__ == "__main__":
    cli()
