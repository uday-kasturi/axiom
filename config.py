from pathlib import Path

# Model tier assignments — non-negotiable
# TEMPORARY: Fable 5 is reporting "currently unavailable" — using Opus 4.8 for both
# tiers until Fable 5 is back. Revert to claude-fable-5 once it recovers.
OPUS_MODEL   = "claude-opus-4-8"           # research: hypothesis generation, theory building, result synthesis
SONNET_MODEL = "claude-opus-4-8"           # execution: attack design, target probing, detailed user explanations
HAIKU_MODEL  = "claude-haiku-4-5-20251001" # interface: status updates, brief comms with user

# Token budgets per tier
OPUS_MAX_TOKENS    = 8192
SONNET_MAX_TOKENS  = 4096
HAIKU_MAX_TOKENS   = 512
DETAIL_MAX_TOKENS  = 2048   # Sonnet when user asks for more than Haiku gives

# Research loop controls
MAX_HYPOTHESIS_ROUNDS = 10
PROBES_PER_HYPOTHESIS = 5
CONFIDENCE_THRESHOLD  = 0.85   # above this → confirmed vuln, trigger disclosure
PARTIAL_SIGNAL_THRESHOLD = 0.4  # above this → Opus treats as interesting, refines

# Paths
ROOT = Path(__file__).parent
FINDINGS_DIR   = ROOT / "findings"
SESSIONS_DIR   = FINDINGS_DIR / "sessions"
FINDINGS_DIR.mkdir(exist_ok=True)
SESSIONS_DIR.mkdir(exist_ok=True)
