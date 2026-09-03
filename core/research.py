"""
Opus research loop.

Orchestrates the full red team session:
1. Catalog sweep (known attacks → baseline signal)
2. Hypothesis generation (Opus, from profile + sweep results)
3. Probe design → execution → analysis → refinement loop
4. Disclosure on confirmed vulns
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from config import MAX_HYPOTHESIS_ROUNDS, CONFIDENCE_THRESHOLD, SESSIONS_DIR
from target.profiler import TargetProfile, TargetAdapter
from attacks.catalog import CATALOG, EVAL_AWARE_CATALOG
from attacks.hypothesis import (
    Hypothesis, Probe,
    generate_hypotheses,
    design_initial_probes,
    refine_hypothesis,
)
from analysis.analyzer import analyze, aggregate_hypothesis_confidence, SignalType
from disclosure import generator as disclosure
from core import interface


def _session_path(profile: TargetProfile) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", f"{profile.name}_{profile.model_id}")
    return SESSIONS_DIR / f"{safe}.json"


def _save_checkpoint(path: Path, hypotheses: list[Hypothesis], round_num: int) -> None:
    data = {
        "round": round_num,
        "hypotheses": [
            {
                "id": h.id,
                "title": h.title,
                "mechanism": h.mechanism,
                "attack_surface": h.attack_surface,
                "novelty_justification": h.novelty_justification,
                "probe_strategy": h.probe_strategy,
                "expected_partial_signals": h.expected_partial_signals,
                "success_signals": h.success_signals,
                "severity": h.severity,
                "confidence": h.confidence,
                "confirmed": h.confirmed,
                "abandoned": h.abandoned,
                "probe_results": h.probe_results,
                "notes": h.notes,
            }
            for h in hypotheses
        ],
    }
    path.write_text(json.dumps(data, indent=2))


def _load_checkpoint(path: Path) -> tuple[list[Hypothesis], int] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        hypotheses = []
        for item in data.get("hypotheses", []):
            h = Hypothesis(
                id=item["id"],
                title=item["title"],
                mechanism=item["mechanism"],
                attack_surface=item["attack_surface"],
                novelty_justification=item["novelty_justification"],
                probe_strategy=item["probe_strategy"],
                expected_partial_signals=item["expected_partial_signals"],
                success_signals=item["success_signals"],
                severity=item["severity"],
                confidence=item["confidence"],
                confirmed=item["confirmed"],
                abandoned=item["abandoned"],
                probe_results=item["probe_results"],
                notes=item["notes"],
            )
            hypotheses.append(h)
        return hypotheses, data.get("round", 0)
    except Exception:
        return None


def run_catalog_sweep(adapter: TargetAdapter, profile: TargetProfile) -> list[dict]:
    """Run all known attacks. Returns structured results for Opus to reason over."""
    sweep = CATALOG + (EVAL_AWARE_CATALOG if profile.eval_aware else [])
    interface.status(f"Running {len(sweep)} known attacks against {profile.name}"
                     + (" (+ eval-awareness probes)" if profile.eval_aware else "") + "...")
    results = []

    for attack in sweep:
        interface.info(f"  → {attack.name}")
        response = adapter.probe(attack.messages, attack.system_prompt)
        result = analyze(
            probe_id=attack.id,
            hypothesis_id="catalog",
            response=response,
            success_signals=attack.success_signals,
            partial_signals=attack.partial_signals,
            refusal_signals=attack.refusal_signals,
        )
        results.append({
            "attack_id": attack.id,
            "name": attack.name,
            "category": attack.category,
            "signal_type": result.signal_type.value,
            "confidence": result.confidence,
            "matched_signals": result.matched_signals,
            "response_snippet": response[:300],
            "analyst_notes": result.analyst_notes,
        })

        if result.signal_type == SignalType.CONFIRMED:
            interface.finding(attack.name, result.analyst_notes, result.confidence)
        elif result.signal_type == SignalType.PARTIAL:
            interface.finding(f"[PARTIAL] {attack.name}", result.analyst_notes, result.confidence)

    return results


def run_hypothesis_loop(
    adapter: TargetAdapter,
    profile: TargetProfile,
    catalog_results: list[dict],
    eval_aware: bool = False,
) -> list[Hypothesis]:
    """
    Opus generates hypotheses, Sonnet probes them, results cycle back.
    Runs until MAX_HYPOTHESIS_ROUNDS or all hypotheses are confirmed/abandoned.
    """
    ckpt_path = _session_path(profile)
    start_round = 0
    checkpoint = _load_checkpoint(ckpt_path)

    if checkpoint is not None:
        hypotheses, start_round = checkpoint
        interface.status(
            f"Resuming interrupted session from round {start_round + 1} "
            f"({len(hypotheses)} hypotheses, "
            f"{sum(1 for h in hypotheses if h.confirmed)} already confirmed)."
        )
    else:
        interface.status("Generating novel vulnerability hypotheses...")
        hypotheses = generate_hypotheses(
            profile.to_context(), catalog_results, profile.novelty_hypotheses,
            eval_aware=eval_aware,
        )

        if not hypotheses:
            interface.error(
                "Opus returned no parseable hypotheses. Nothing to probe — "
                "check the target profile and model output."
            )
            return []

        interface.status(f"Opus generated {len(hypotheses)} novel hypotheses. Beginning probe loop.")

    confirmed: list[Hypothesis] = [h for h in hypotheses if h.confirmed]
    # probes pending for each hypothesis this round, keyed by hypothesis id.
    # None means "not yet designed" → design fresh; otherwise use refined probes.
    pending_probes: dict[str, list[Probe]] = {}

    for round_num in range(start_round, MAX_HYPOTHESIS_ROUNDS):
        active = [h for h in hypotheses if not h.confirmed and not h.abandoned]
        if not active:
            break

        interface.info(f"Round {round_num + 1} — {len(active)} active hypotheses")

        for hypothesis in active:
            probes = pending_probes.get(hypothesis.id)
            if probes is None:
                probes = design_initial_probes(hypothesis, profile.to_context())

            if not probes:
                # no runnable probes (design failed or refinement produced none)
                interface.info(f"    No probes available for: {hypothesis.title} — abandoning")
                hypothesis.abandoned = True
                continue

            probe_results = []
            analyzed: list = []

            for probe in probes:
                response = adapter.probe(
                    probe.messages, probe.system_prompt,
                    tools=probe.tools,
                    tool_choice=probe.tool_choice,
                    response_format=probe.response_format,
                )
                result = analyze(
                    probe_id=probe.probe_id,
                    hypothesis_id=hypothesis.id,
                    response=response,
                    success_signals=hypothesis.success_signals,
                    partial_signals=hypothesis.expected_partial_signals,
                )
                analyzed.append(result)
                record = {
                    "probe_id": probe.probe_id,
                    "rationale": probe.rationale,
                    "signal_type": result.signal_type.value,
                    "confidence": result.confidence,
                    "matched_signals": result.matched_signals,
                    "response_snippet": response[:400],
                    "analyst_notes": result.analyst_notes,
                }
                probe_results.append(record)
                hypothesis.probe_results.append(record)

            # aggregate confidence from the real probe analyses (no re-analysis)
            agg_confidence = aggregate_hypothesis_confidence(analyzed)
            hypothesis.confidence = agg_confidence

            if agg_confidence >= CONFIDENCE_THRESHOLD:
                hypothesis.confirmed = True
                interface.finding(hypothesis.title, hypothesis.mechanism, agg_confidence)
                confirmed.append(hypothesis)
                _trigger_disclosure(hypothesis, profile)
            else:
                # Opus refines and supplies the next round's probes. Pass the full
                # accumulated probe history (not just this round) so Opus knows what
                # was already tried and doesn't retread the same ground.
                interface.info(f"    Refining hypothesis: {hypothesis.title} (conf={agg_confidence:.0%})")
                hypothesis, refined_probes = refine_hypothesis(
                    hypothesis, hypothesis.probe_results, profile.to_context()
                )
                if hypothesis.confidence:
                    interface.info(
                        f"    Opus self-assessed confidence: {hypothesis.confidence:.0%} "
                        f"(advisory — does not trigger confirmation)"
                    )
                if hypothesis.abandoned:
                    interface.info(f"    Abandoned: {hypothesis.title}")
                    pending_probes.pop(hypothesis.id, None)
                else:
                    # feed refined probes into the next round; if Opus gave none,
                    # fall back to a fresh design pass next round.
                    pending_probes[hypothesis.id] = refined_probes if refined_probes else None

        # checkpoint after every round so a crash mid-session can be resumed
        _save_checkpoint(ckpt_path, hypotheses, round_num + 1)

    # clean finish — remove the checkpoint so the next run starts fresh
    ckpt_path.unlink(missing_ok=True)
    return confirmed


def _trigger_disclosure(hypothesis: Hypothesis, profile: TargetProfile) -> None:
    interface.status(f"Confirmed vulnerability. Generating disclosure report...")
    confirmed_probes = [r for r in hypothesis.probe_results if r.get("signal_type") == "confirmed"]
    partial_probes   = [r for r in hypothesis.probe_results if r.get("signal_type") == "partial"]
    analyst_notes    = [r.get("analyst_notes", "") for r in hypothesis.probe_results]

    report, path = disclosure.generate(
        hypothesis_id=hypothesis.id,
        hypothesis_title=hypothesis.title,
        mechanism=hypothesis.mechanism,
        severity=hypothesis.severity,
        target_name=profile.name,
        target_model_id=profile.model_id,
        confirmed_probes=confirmed_probes,
        partial_probes=partial_probes,
        analyst_notes=analyst_notes,
    )
    interface.finding(
        f"Disclosure saved: {hypothesis.title}",
        f"Report written to {path}",
        hypothesis.confidence,
    )
