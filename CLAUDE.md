# Axiom

Research-grade AI red team engine. Finds novel vulnerabilities in new model releases.

## Model tier — non-negotiable
- `OPUS_MODEL`   → research: hypothesis generation, theory building, result synthesis
- `SONNET_MODEL` → execution: attack design, target probing, detailed user explanations  
- `HAIKU_MODEL`  → interface: all user-facing status and brief output

Never move logic between tiers without explicit instruction.

## Architecture
- `core/models.py` — Anthropic client, one function per tier
- `core/research.py` — Opus orchestration loop
- `core/interface.py` — Haiku/Sonnet user comms
- `target/profiler.py` — target threat modeling + TargetAdapter (calls target APIs)
- `attacks/catalog.py` — known attack classes (baseline sweep)
- `attacks/hypothesis.py` — novel hypothesis generation and refinement loop
- `analysis/analyzer.py` — response classification (confirmed/partial/clean)
- `disclosure/generator.py` — structured disclosure report output
- `findings/` — saved disclosure reports (auto-generated, don't edit)

## Key invariants
- Partial signals (confidence 0.4–0.84) are more valuable than clean refusals — Opus must see them
- `CONFIDENCE_THRESHOLD = 0.85` triggers disclosure generation
- All probes go through `TargetAdapter.probe()` — never call target APIs directly
- Prompt caching is on by default for Opus/Sonnet system prompts

## Running
```bash
python main.py run --name "GPT-4o" --model-id "gpt-4o" --api-type openai --api-key-env OPENAI_API_KEY
python main.py findings
python main.py explain findings/<report>.md
```

## Env vars needed
- `ANTHROPIC_API_KEY` — always required (drives Opus/Sonnet/Haiku)
- Target API key in whatever env var you specify via `--api-key-env`
