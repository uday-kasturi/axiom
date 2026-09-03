"""
inspect_archive.py — human-readable dump of Axiom v2 archive elites.

Usage:
    python inspect_archive.py                        # all cells
    python inspect_archive.py --min-reliability 0.6  # only high-reliability
    python inspect_archive.py --cell tool_args exfil_action none single True
"""
from __future__ import annotations

import argparse
import json
import textwrap
from pathlib import Path

from v2.archive.map_elites import Archive
from v2.types import ScoredCandidate


def dump_probe(sc: ScoredCandidate, rank: int) -> None:
    c = sc.candidate
    ps = c.probe_spec
    print(f"\n{'='*72}")
    print(f"RANK {rank}  |  K/N={sc.k_fired}/{sc.n_valid} ({sc.reliability:.0%})  "
          f"|  novelty={sc.novelty_at_insert:.3f}  |  gen={sc.generation}")
    print(f"Cell:      {sc.descriptor.cell_key()}")
    print(f"Op:        {c.mutation_op}  |  origin: {c.origin[:60]}")
    print(f"Marker:    {c.marker}")
    print(f"Thinking:  {ps.mode.thinking}  |  turns: {ps.mode.turns}")
    print(f"Channel:   {ps.target_channel.value}")

    if ps.tools:
        print(f"\n--- TOOLS ({len(ps.tools)}) ---")
        for t in ps.tools:
            print(f"  [{t.name}] {t.description}")
            if t.parameters:
                print(f"    params: {json.dumps(t.parameters, indent=6)[:300]}")

    print(f"\n--- MESSAGES ({len(ps.messages)}) ---")
    for i, turn in enumerate(ps.messages):
        role = turn.role.upper()
        content = turn.content or ""
        print(f"\n  [{i+1}] {role}:")
        print(textwrap.indent(textwrap.fill(content, width=76), "    "))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", default="findings/v2_archive.pkl")
    parser.add_argument("--min-reliability", type=float, default=0.0)
    parser.add_argument("--cell", nargs="+", help="filter by cell key components")
    args = parser.parse_args()

    archive = Archive.load_or_new(Path(args.archive))
    queue = archive.triage_queue(r_min=args.min_reliability)

    if not queue:
        print(f"No elites with reliability >= {args.min_reliability:.0%}")
        return

    if args.cell:
        cell_filter = tuple(
            v if v not in ("True", "False") else (v == "True")
            for v in args.cell
        )
        queue = [e for e in queue if e.descriptor.cell_key() == cell_filter]
        if not queue:
            print(f"No elites matching cell {cell_filter}")
            return

    print(f"\nAxiom v2 Archive — {len(queue)} elite(s) (min_reliability={args.min_reliability:.0%})")
    for rank, elite in enumerate(queue, 1):
        dump_probe(elite, rank)

    print(f"\n{'='*72}")


if __name__ == "__main__":
    main()
