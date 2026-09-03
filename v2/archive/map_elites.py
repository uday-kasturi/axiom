"""
Archive — MAP-Elites implementation.

Each cell retains the most reliable elite for that BehaviorDescriptor key.
Novelty is k-NN distance in the continuous embedding space, computed at
insert time. The archive is serialized to disk after every generation.
"""
from __future__ import annotations

import json
import pickle
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import numpy as np

from v2.types import BehaviorDescriptor, Candidate, ScoredCandidate, TrialBundle

_KNN_K       = 15
_R_MIN_TRIAGE = 0.30   # minimum reliability to surface in triage queue


@dataclass
class Elite:
    candidate: Candidate
    bundle: TrialBundle
    descriptor: BehaviorDescriptor
    embedding: list[float]
    reliability: float
    k_fired: int
    n_valid: int
    novelty_at_insert: float
    generation: int


class Archive:
    def __init__(self, path: Optional[Path] = None):
        self.path: Optional[Path] = path
        self._cells: dict[tuple, Elite] = {}
        self._all_embeddings: list[np.ndarray] = []   # for k-NN

    # ------------------------------------------------------------------
    # Insert
    # ------------------------------------------------------------------

    def insert(self, scored: ScoredCandidate) -> tuple[bool, float]:
        """
        Insert a ScoredCandidate.

        Returns (cell_improved, novelty_score).
        cell_improved is True if this candidate took or created a cell.
        """
        emb       = np.array(scored.embedding, dtype=np.float32)
        novelty   = self._query_novelty(emb)
        key       = scored.descriptor.cell_key()
        incumbent = self._cells.get(key)

        took_cell = False
        if incumbent is None or scored.reliability > incumbent.reliability:
            # Tie-break: equal reliability → keep higher novelty
            if (incumbent is None
                    or scored.reliability > incumbent.reliability
                    or (scored.reliability == incumbent.reliability
                        and novelty > incumbent.novelty_at_insert)):
                self._cells[key] = Elite(
                    candidate=scored.candidate,
                    bundle=scored.bundle,
                    descriptor=scored.descriptor,
                    embedding=scored.embedding,
                    reliability=scored.reliability,
                    k_fired=scored.k_fired,
                    n_valid=scored.n_valid,
                    novelty_at_insert=novelty,
                    generation=scored.candidate.generation,
                )
                took_cell = True

        self._all_embeddings.append(emb)
        return took_cell, novelty

    # ------------------------------------------------------------------
    # Novelty query
    # ------------------------------------------------------------------

    def _query_novelty(self, emb: np.ndarray) -> float:
        if not self._all_embeddings:
            return 1.0   # first insertion is maximally novel
        mat = np.stack(self._all_embeddings)
        dists = np.linalg.norm(mat - emb, axis=1)
        k = min(_KNN_K, len(dists))
        return float(np.mean(np.sort(dists)[:k]))

    def query_novelty(self, embedding: list[float]) -> float:
        return self._query_novelty(np.array(embedding, dtype=np.float32))

    # ------------------------------------------------------------------
    # Parent selection
    # ------------------------------------------------------------------

    def sample_parents(
        self,
        n: int = 1,
        strategy: str = "uniform",
        rng: Optional[np.random.Generator] = None,
    ) -> list[Candidate]:
        """
        Sample parent candidates from the archive.

        strategy="uniform"  — standard MAP-Elites, uniform over filled cells.
        strategy="novelty"  — sample proportional to novelty_at_insert.
        """
        if not self._cells:
            return []
        rng = rng or np.random.default_rng()
        elites = list(self._cells.values())

        if strategy == "novelty":
            weights = np.array([e.novelty_at_insert for e in elites], dtype=np.float32)
            weights = weights / weights.sum()
            chosen  = rng.choice(len(elites), size=min(n, len(elites)),
                                 replace=False, p=weights)
        else:
            chosen = rng.choice(len(elites), size=min(n, len(elites)), replace=False)

        return [elites[i].candidate for i in chosen]

    # ------------------------------------------------------------------
    # Triage queue
    # ------------------------------------------------------------------

    def triage_queue(self, r_min: float = _R_MIN_TRIAGE) -> list[Elite]:
        """Return elites with reliability >= r_min, sorted by novelty desc."""
        candidates = [e for e in self._cells.values() if e.reliability >= r_min]
        return sorted(candidates, key=lambda e: e.novelty_at_insert, reverse=True)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def n_cells(self) -> int:
        return len(self._cells)

    def elites(self) -> list[Elite]:
        return list(self._cells.values())

    def generation_summary(self, generation: int) -> dict:
        gen_elites = [e for e in self._cells.values() if e.generation == generation]
        return {
            "generation":    generation,
            "total_cells":   self.n_cells(),
            "new_this_gen":  len(gen_elites),
            "mean_reliability": (
                sum(e.reliability for e in self._cells.values()) / max(self.n_cells(), 1)
            ),
            "mean_novelty": (
                sum(e.novelty_at_insert for e in self._cells.values()) / max(self.n_cells(), 1)
            ),
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Optional[Path] = None) -> None:
        p = path or self.path
        if p is None:
            return
        p = Path(p)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path: Path) -> "Archive":
        with open(path, "rb") as f:
            return pickle.load(f)

    @classmethod
    def load_or_new(cls, path: Optional[Path]) -> "Archive":
        if path and Path(path).exists():
            arch = cls.load(path)
            arch.path = path
            return arch
        return cls(path=path)
