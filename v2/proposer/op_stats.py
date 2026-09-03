"""
UCB1 operator selector — learns which (MutationOp, thinking_mode) arms produce
NEW/IMPROVED archive cells and up-weights them over random static weights.

This is Phase 1 of the LLM-free attack proposer: no LLM involved, just a
multi-armed bandit that exploits patterns the MAP-Elites loop has already found.

UCB1 score: mean_reward + C * sqrt(ln(total_pulls) / arm_pulls)
  - mean_reward = fraction of pulls that produced a cell improvement
  - C controls exploration; default 1.0 keeps arms in play even when mean=0
  - arms with 0 pulls get score=inf (explore first)
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Optional

from v2.types import MutationOp

_C = 1.0  # UCB exploration constant

# Fall-back weights when UCB has no data yet (same as propose.py static weights)
_PRIOR: dict[MutationOp, float] = {
    MutationOp.CHANNEL_SWAP:      2.0,
    MutationOp.MODE_FLIP:         1.5,
    MutationOp.INJECTION_MOVE:    2.0,
    MutationOp.AFFORDANCE_EXPAND: 1.5,
    MutationOp.ROLE_REASSIGN:     1.5,
    MutationOp.TURN_SPLIT:        2.0,
    MutationOp.PARAPHRASE:        1.0,
}


@dataclass
class ArmStats:
    pulls:    int   = 0
    wins:     int   = 0

    def mean(self) -> float:
        return self.wins / self.pulls if self.pulls > 0 else 0.0

    def ucb1(self, total_pulls: int) -> float:
        if self.pulls == 0:
            return float("inf")
        return self.mean() + _C * math.sqrt(math.log(total_pulls) / self.pulls)


class OperatorStats:
    """
    Tracks UCB1 state over (MutationOp, thinking_mode) arms.

    'thinking_mode' is a bool: True = extended thinking enabled.
    Arms are keyed as (op, thinking_mode) so the policy can learn
    e.g. "MODE_FLIP + think=False works on Haiku" vs "INJECTION_MOVE + think=True
    works on Qwen3" independently.
    """

    def __init__(self) -> None:
        self._arms: dict[tuple[MutationOp, bool], ArmStats] = {}
        self._total_pulls = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(self, op: MutationOp, thinking: bool, improved: bool) -> None:
        """Record the outcome of one candidate evaluation."""
        key = (op, thinking)
        if key not in self._arms:
            self._arms[key] = ArmStats()
        arm = self._arms[key]
        arm.pulls += 1
        if improved:
            arm.wins += 1
        self._total_pulls += 1

    def pick_op(
        self,
        thinking: bool,
        exclude_paraphrase: bool = False,
    ) -> MutationOp:
        """
        Select the next mutation operator using UCB1 for the given thinking mode.

        Falls back to prior-weighted random when all arms are unobserved.
        """
        candidates = [op for op in MutationOp if op != MutationOp.SEED]
        if exclude_paraphrase:
            candidates = [op for op in candidates if op != MutationOp.PARAPHRASE]

        if self._total_pulls == 0:
            return _prior_sample(candidates)

        # Score each (op, thinking) arm
        scored = []
        for op in candidates:
            key = (op, thinking)
            arm = self._arms.get(key, ArmStats())
            score = arm.ucb1(self._total_pulls)
            scored.append((score, op))

        # If all arms are unobserved (all inf), fall back to prior sampling
        if all(math.isinf(s) for s, _ in scored):
            return _prior_sample(candidates)

        # Break ties stochastically among arms with the same UCB1 score
        max_score = max(s for s, _ in scored)
        best = [op for s, op in scored if math.isclose(s, max_score, rel_tol=1e-9)]
        return random.choice(best)

    def summary(self) -> str:
        """Human-readable table of arm stats for logging."""
        if not self._arms:
            return "OperatorStats: no data yet"
        lines = [f"OperatorStats (total_pulls={self._total_pulls}):"]
        for (op, thinking), arm in sorted(self._arms.items(), key=lambda x: -x[1].mean()):
            ucb = arm.ucb1(self._total_pulls) if self._total_pulls > 0 else float("inf")
            ucb_str = f"{ucb:.3f}" if not math.isinf(ucb) else "inf"
            lines.append(
                f"  {op.name:20s} think={str(thinking):5s}"
                f"  wins={arm.wins}/{arm.pulls}  mean={arm.mean():.2f}  ucb1={ucb_str}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _prior_sample(candidates: list[MutationOp]) -> MutationOp:
    """Weighted random sample using the static prior."""
    ops     = [op for op in candidates if op in _PRIOR]
    weights = [_PRIOR[op] for op in ops]
    total   = sum(weights)
    r = random.random() * total
    cum = 0.0
    for op, w in zip(ops, weights):
        cum += w
        if r < cum:
            return op
    return ops[-1]
