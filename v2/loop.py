"""
Axiom v2 main loop.

generate → test → measure → select → repeat

Usage:
    python -m v2.loop --generations 5 --batch-size 10
    python -m v2.loop --seeds-only          # run catalog seeds, then stop
    python -m v2.loop --triage              # print triage queue from saved archive
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from v2.archive.map_elites import Archive
from v2.featurizer.features import featurize, score_reliability
from v2.harness.runner import Harness, DEFAULT_ENDPOINT
from v2.proposer.op_stats import OperatorStats
from v2.proposer.propose import Proposer
from v2.types import ScoredCandidate

console = Console()

_ARCHIVE_PATH   = Path("findings/v2_archive.pkl")
_DEFAULT_N      = 10
_DEFAULT_BATCH  = 8
_DEFAULT_GEN    = 5
_DEFAULT_TEMP   = 0.7
_R_MIN_TRIAGE   = 0.30


def run_loop(
    generations: int  = _DEFAULT_GEN,
    batch_size: int   = _DEFAULT_BATCH,
    n_trials: int     = _DEFAULT_N,
    seeds_only: bool  = False,
    endpoint: str     = DEFAULT_ENDPOINT,
    archive_path: Path = _ARCHIVE_PATH,
    api_type: str     = "ollama",
    model_id: str     = "qwen3:14b",
) -> Archive:
    archive   = Archive.load_or_new(archive_path)
    harness   = Harness(endpoint=endpoint, api_type=api_type, model_id=model_id)
    op_stats  = OperatorStats()
    proposer  = Proposer(op_stats=op_stats)

    # ------------------------------------------------------------------
    # Generation 0: seed from v1 catalog
    # ------------------------------------------------------------------
    from attacks.catalog import CATALOG

    if archive.n_cells() == 0:
        console.print("\n[bold cyan]Generation 0 — seeding from v1 catalog + schema poisoning + targeted[/bold cyan]")
        from attacks.catalog import SCHEMA_POISONING_CATALOG
        from attacks.haiku_targeted import HAIKU_TARGETED_CATALOG
        seeds = proposer.propose_seeds(CATALOG)
        seeds += proposer.propose_schema_poison_seeds(SCHEMA_POISONING_CATALOG)
        seeds += proposer.propose_targeted_seeds(HAIKU_TARGETED_CATALOG)
        _run_and_insert(seeds, harness, archive, n_trials, generation=0)
        _print_gen_summary(archive, generation=0)
        archive.save()

    if seeds_only:
        return archive

    # ------------------------------------------------------------------
    # Generations 1..N: mutate from archive
    # ------------------------------------------------------------------
    for gen in range(1, generations + 1):
        console.print(f"\n[bold cyan]Generation {gen}[/bold cyan]")

        parents = archive.sample_parents(n=batch_size, strategy="uniform")
        if not parents:
            console.print("[yellow]Archive empty — nothing to mutate. Stopping.[/yellow]")
            break

        candidates = proposer.mutate_batch(parents, batch_size=batch_size, generation=gen)
        new_cells  = _run_and_insert(candidates, harness, archive, n_trials, generation=gen,
                                     op_stats=op_stats)

        _print_gen_summary(archive, generation=gen)
        console.print(op_stats.summary())
        archive.save()

        # Early stopping: no new cells for 5 consecutive generations
        if new_cells == 0:
            _stall_streak = getattr(run_loop, "_stall_streak", 0) + 1
            run_loop._stall_streak = _stall_streak
            if _stall_streak >= 5:
                console.print("[yellow]No new cells for 5 consecutive generations. Archive saturated — stopping.[/yellow]")
                break
        else:
            run_loop._stall_streak = 0

    return archive


def _run_and_insert(
    candidates,
    harness: Harness,
    archive: Archive,
    n_trials: int,
    generation: int,
    op_stats: Optional[OperatorStats] = None,
) -> int:
    """Run candidates, featurize, score, insert. Returns count of new/improved cells."""
    new_cells = 0
    for i, candidate in enumerate(candidates):
        console.print(
            f"  [{i+1}/{len(candidates)}] {candidate.origin} "
            f"op={candidate.mutation_op} "
            f"ch={candidate.probe_spec.target_channel.value} "
            f"think={candidate.probe_spec.mode.thinking}",
            end=" ... ",
        )
        bundle = harness.run(candidate, n=n_trials)

        if bundle.n_valid == 0:
            console.print(f"[red]all {len(bundle.results)} trials timed out/errored[/red]")
            if op_stats is not None:
                op_stats.update(candidate.mutation_op, candidate.probe_spec.mode.thinking, improved=False)
            continue

        descriptor, embedding   = featurize(bundle)
        reliability, k, n_valid = score_reliability(bundle)
        scored = ScoredCandidate(
            candidate=candidate,
            bundle=bundle,
            descriptor=descriptor,
            embedding=embedding,
            reliability=reliability,
            k_fired=k,
            n_valid=n_valid,
        )
        took_cell, novelty = archive.insert(scored)
        if took_cell:
            new_cells += 1

        if op_stats is not None:
            op_stats.update(candidate.mutation_op, candidate.probe_spec.mode.thinking, improved=took_cell)

        console.print(
            f"K/N={k}/{n_valid} ({reliability:.0%})  "
            f"novelty={novelty:.3f}  "
            f"cell={'[green]NEW/IMPROVED[/green]' if took_cell else 'no change'}  "
            f"desc={descriptor.cell_key()}"
        )

    return new_cells


def _print_gen_summary(archive: Archive, generation: int) -> None:
    summary = archive.generation_summary(generation)
    console.print(
        f"\n  [bold]Gen {generation} summary:[/bold] "
        f"total_cells={summary['total_cells']}  "
        f"new_this_gen={summary['new_this_gen']}  "
        f"mean_reliability={summary['mean_reliability']:.2f}  "
        f"mean_novelty={summary['mean_novelty']:.3f}"
    )


def print_triage(archive_path: Path = _ARCHIVE_PATH, r_min: float = _R_MIN_TRIAGE) -> None:
    archive = Archive.load_or_new(archive_path)
    queue   = archive.triage_queue(r_min=r_min)

    if not queue:
        console.print(f"[yellow]No elites with reliability >= {r_min:.0%}[/yellow]")
        return

    table = Table(title=f"Triage Queue (reliability >= {r_min:.0%}, ranked by novelty)")
    table.add_column("Rank",       style="dim")
    table.add_column("K/N",        style="green")
    table.add_column("Novelty",    style="cyan")
    table.add_column("Cell",       style="yellow")
    table.add_column("Op",         style="magenta")
    table.add_column("Gen",        style="dim")
    table.add_column("Candidate ID", style="dim")

    for rank, elite in enumerate(queue, 1):
        table.add_row(
            str(rank),
            f"{elite.k_fired}/{elite.n_valid} ({elite.reliability:.0%})",
            f"{elite.novelty_at_insert:.3f}",
            str(elite.descriptor.cell_key()),
            str(elite.candidate.mutation_op),
            str(elite.generation),
            elite.candidate.candidate_id[:8],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Axiom v2 novelty-search loop")
    parser.add_argument("--generations",  type=int,   default=_DEFAULT_GEN)
    parser.add_argument("--batch-size",   type=int,   default=_DEFAULT_BATCH)
    parser.add_argument("--n-trials",     type=int,   default=_DEFAULT_N)
    parser.add_argument("--seeds-only",   action="store_true")
    parser.add_argument("--triage",       action="store_true")
    parser.add_argument("--endpoint",     default=DEFAULT_ENDPOINT)
    parser.add_argument("--archive",      default=str(_ARCHIVE_PATH))
    parser.add_argument("--api-type",     default="ollama", choices=["ollama", "openai", "anthropic"])
    parser.add_argument("--model-id",     default="qwen3:14b")
    args = parser.parse_args()

    archive_path = Path(args.archive)

    if args.triage:
        print_triage(archive_path)
        return

    run_loop(
        generations=args.generations,
        batch_size=args.batch_size,
        n_trials=args.n_trials,
        seeds_only=args.seeds_only,
        endpoint=args.endpoint,
        archive_path=archive_path,
        api_type=args.api_type,
        model_id=args.model_id,
    )


if __name__ == "__main__":
    main()
