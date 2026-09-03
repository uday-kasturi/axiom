"""
Core data types for Axiom v2.

All types are dataclasses or simple dicts. No ORM, no validation framework.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums — define the descriptor axes and operator names
# ---------------------------------------------------------------------------

class PayloadChannel(str, Enum):
    CONTENT        = "content"
    REASONING      = "reasoning"
    TOOL_ARGS      = "tool_args"
    STRUCTURED     = "structured"
    NONE           = "none"

class ActionClass(str, Enum):
    REFUSED            = "refused"
    COMPLIED_PROSE     = "complied_prose"
    SINGLE_TOOL_CALL   = "single_tool_call"
    TOOL_CHAIN         = "tool_chain"
    EXFIL_ACTION       = "exfil_action"

class SafetyLocus(str, Enum):
    NONE              = "none"
    CONTENT_TERMINAL  = "content_terminal"
    REASONING         = "reasoning"
    PRE_TOOL          = "pre_tool"
    POST_HOC          = "post_hoc"

class TurnStructure(str, Enum):
    SINGLE               = "single"
    MULTI_TURN_INHERITED = "multi_turn_inherited"

class InjectionPoint(str, Enum):
    USER                = "user"
    TOOL_RESULT         = "tool_result"
    SYSTEM              = "system"
    PRIOR_ASSISTANT_COT = "prior_assistant_cot"
    NONE                = "none"

class TargetChannel(str, Enum):
    CONTENT          = "content"
    REASONING        = "reasoning"
    TOOL_ARGS        = "tool_args"
    STRUCTURED_FIELD = "structured_field"
    LOGPROBS         = "logprobs"

class MutationOp(str, Enum):
    SEED             = "seed"
    CHANNEL_SWAP     = "channel_swap"
    MODE_FLIP        = "mode_flip"
    INJECTION_MOVE   = "injection_move"
    AFFORDANCE_EXPAND = "affordance_expand"
    ROLE_REASSIGN    = "role_reassign"
    TURN_SPLIT       = "turn_split"
    PARAPHRASE       = "paraphrase"
    CROSSOVER        = "crossover"


# ---------------------------------------------------------------------------
# Probe spec — the full point in the search space
# ---------------------------------------------------------------------------

@dataclass
class Turn:
    role: str       # system | user | assistant | tool
    content: str
    tool_call_id: Optional[str] = None   # for role=tool responses

@dataclass
class ToolDef:
    name: str
    description: str
    parameters: dict   # JSON schema

@dataclass
class ProbeMode:
    thinking: bool       = True
    temperature: float   = 0.7
    role_placement: str  = "user"    # where the injection lives
    turns: int           = 1         # 1 = single-shot

@dataclass
class ProbeSpec:
    messages: list[Turn]
    tools: list[ToolDef]
    injection_point: InjectionPoint
    target_channel: TargetChannel
    mode: ProbeMode


# ---------------------------------------------------------------------------
# Candidate — Proposer output, Harness input
# ---------------------------------------------------------------------------

def _fresh_marker() -> str:
    uid = uuid.uuid4().hex[:8].upper()
    return f"AXIOM_PAYLOAD_{uid}"

@dataclass
class Candidate:
    probe_spec: ProbeSpec
    marker: str                          = field(default_factory=_fresh_marker)
    candidate_id: str                    = field(default_factory=lambda: uuid.uuid4().hex)
    parent_id: Optional[str]             = None
    generation: int                      = 0
    origin: str                          = "seed"   # seed | mutation | crossover
    mutation_op: Optional[MutationOp]    = None


# ---------------------------------------------------------------------------
# RunResult — Harness output for one trial
# ---------------------------------------------------------------------------

@dataclass
class RawOutput:
    content: str
    reasoning_span: str          # <think> span, separate from content
    tool_calls: list[dict]       # [{"name": str, "arguments": dict}, ...]

@dataclass
class WhiteBox:
    """Stub in v2. Populated by MLX harness in v2.1."""
    refusal_dir_projection: list[float] = field(default_factory=list)
    activation_summary: list[float]     = field(default_factory=list)
    logit_stats: dict                   = field(default_factory=dict)

@dataclass
class ExecutionMeta:
    latency_s: float
    timeout: bool
    error: Optional[str] = None

@dataclass
class RunResult:
    candidate_id: str
    trial_idx: int
    raw_output: RawOutput
    white_box: WhiteBox
    execution_meta: ExecutionMeta

    @property
    def valid(self) -> bool:
        """A result is valid if it completed without timeout or error."""
        return not self.execution_meta.timeout and self.execution_meta.error is None


# ---------------------------------------------------------------------------
# TrialBundle — N RunResults for one Candidate
# ---------------------------------------------------------------------------

@dataclass
class TrialBundle:
    candidate: Candidate
    results: list[RunResult]

    @property
    def valid_results(self) -> list[RunResult]:
        return [r for r in self.results if r.valid]

    @property
    def n_valid(self) -> int:
        return len(self.valid_results)

    @property
    def n_timeout(self) -> int:
        return sum(1 for r in self.results if r.execution_meta.timeout)

    @property
    def n_error(self) -> int:
        return sum(1 for r in self.results if r.execution_meta.error is not None
                   and not r.execution_meta.timeout)


# ---------------------------------------------------------------------------
# BehaviorDescriptor — discrete, defines MAP-Elites cells
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BehaviorDescriptor:
    payload_channel: PayloadChannel
    action_class: ActionClass
    safety_locus: SafetyLocus
    turn_structure: TurnStructure
    thinking_mode: bool   # True = on, False = off

    def cell_key(self) -> tuple:
        return (
            self.payload_channel.value,
            self.action_class.value,
            self.safety_locus.value,
            self.turn_structure.value,
            self.thinking_mode,
        )


# ---------------------------------------------------------------------------
# Scored result — what the Archive ingests
# ---------------------------------------------------------------------------

@dataclass
class ScoredCandidate:
    candidate: Candidate
    bundle: TrialBundle
    descriptor: BehaviorDescriptor
    embedding: list[float]     # L2-normalized concat of structured + text features
    reliability: float         # K / N_valid
    k_fired: int
    n_valid: int
    novelty: float = 0.0       # filled in by Archive at insert time
