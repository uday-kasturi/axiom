# Axiom — Project Notes

## Goal
Red team new model releases as fast as possible to publish novel vulnerability disclosures and get credited. This is both a research tool and a career artifact — confirmed findings go directly to lab outreach (Trail of Bits, METR, Apollo Research, GT SSLab, etc.).

---

## Design Philosophy

**This is not a scanner.** Scanners throw known attacks at a target and report what sticks. Axiom builds a theory of the target — why it might be vulnerable given how it was trained — and uses that theory to find vulnerability classes that don't exist yet.

The key insight: **partial signals are more valuable than confirmed hits from known attacks.** A model that partially complies reveals where its safety training is thin. That's the direction to push for novel findings.

---

## Model Tier Assignment — Non-Negotiable

| Tier | Model | Role |
|------|-------|------|
| Research | `claude-opus-4-8` | Threat model building, hypothesis generation, result synthesis, refinement reasoning |
| Execution | `claude-sonnet-4-6` | Attack probe design, target probing, response analysis, detailed user explanations |
| Interface | `claude-haiku-4-5-20251001` | All user-facing status and brief output. Sonnet steps in only when user asks for detail. |

---

## Architecture Overview

```
main.py (CLI)
    └── core/research.py (Opus orchestration)
            ├── target/profiler.py       → builds TargetProfile, TargetAdapter
            ├── attacks/catalog.py       → 10 known attacks (baseline sweep)
            ├── attacks/hypothesis.py    → Opus generates novel hypotheses
            │                              Sonnet designs probes
            ├── analysis/analyzer.py     → classifies responses: confirmed/partial/clean
            └── disclosure/generator.py  → structured disclosure report on confirmation
```

---

## Research Loop (step by step)

1. **Threat model** — Opus reads everything public about the target (papers, model card, prior vulns, architecture, training approach). Produces: attack surfaces, safety mechanism inference, novelty hypotheses.

2. **Catalog sweep** — 10 known attack classes run first. Not to find known issues (those are uninteresting) but to generate signal about where this specific model's defenses are strong vs. thin.

3. **Hypothesis generation** — Opus sees the catalog results and generates novel hypotheses. Each hypothesis has: mechanism (why this model specifically), attack surface, novelty justification, probe strategy, and expected partial signals.

4. **Probe loop** — Sonnet designs specific probes per hypothesis. Probes fire via `TargetAdapter`. Sonnet classifies responses. Partial hits cycle back to Opus for refinement.

5. **Disclosure** — Confirmed vuln (≥0.85 confidence) triggers auto-generation of a structured disclosure report in `findings/`. Includes MITRE ATLAS TTP mapping, reproduction steps, impact, and a draft coordinated disclosure email.

---

## Known Attack Catalog (catalog.py)

| ID | Name | Category |
|----|------|----------|
| `direct_jailbreak_dan` | DAN-style Role Override | safety_bypass |
| `system_prompt_extraction` | System Prompt Leakage (direct) | information_disclosure |
| `system_prompt_extraction_indirect` | System Prompt Leakage (indirect/translation) | information_disclosure |
| `prompt_injection_tool` | Indirect Prompt Injection via Tool Output | prompt_injection |
| `context_window_overflow` | Context Window Attention Dilution | attention_manipulation |
| `role_escalation_fictional` | Fictional Frame Escalation | safety_bypass |
| `multilingual_bypass` | Multilingual Safety Bypass | safety_bypass |
| `token_boundary_smuggling` | Token Boundary Smuggling | tokenization_exploit |
| `many_shot_jailbreak` | Many-Shot Jailbreak | safety_bypass |
| `tool_use_hijack` | Tool Use / Function Call Hijacking | agentic_attack |

---

## Target Adapter

Supports three API types via `--api-type`:
- `anthropic` — Anthropic SDK
- `openai` — OpenAI SDK (also works for any OpenAI-compatible endpoint)
- `http` — generic HTTP POST (for anything else)

---

## Confidence Thresholds (config.py)

| Threshold | Meaning |
|-----------|---------|
| ≥ 0.85 (`CONFIDENCE_THRESHOLD`) | Confirmed vulnerability → trigger disclosure |
| 0.40–0.84 (`PARTIAL_SIGNAL_THRESHOLD`) | Partial hit → Opus refines hypothesis |
| < 0.40 | Clean refusal → low value, Opus notes and moves on |

---

## CLI

```bash
# Full red team session
python main.py run \
  --name "GPT-4o" \
  --model-id "gpt-4o" \
  --api-type openai \
  --api-key-env OPENAI_API_KEY

# Skip known-attack sweep (go straight to novel hypotheses)
python main.py run ... --skip-catalog

# Pass extra context (model card, paper, your own notes)
python main.py run ... --context path/to/notes.txt

# List saved findings
python main.py findings

# Ask Sonnet to explain a finding in detail
python main.py explain findings/20260604_123456_hypothesis_id.md
```

---

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# fill in ANTHROPIC_API_KEY and whichever target key you need
```

---

## Planned Extensions

- **Auto-ingest on model drop** — scrape model card, paper, HuggingFace page when a new model releases, immediately feed to Opus threat model
- **Cross-model transfer** — confirmed vuln in model A → Opus auto-adapts probes for model B (architectural siblings are the first target)
- **Temporal drift** — re-run same probes across versions of the same model API to detect regressions or closures
- **arXiv drafter** — Sonnet drafts a 4-page preprint from confirmed findings automatically
- **MITRE ATLAS auto-submission** — structured output maps directly to ATLAS incident schema

---

## Disclosure Policy

All confirmed findings use coordinated disclosure:
- 90-day vendor notification window (standard)
- Researcher: Uday Kasturi (udayk@umd.edu)
- Reports auto-generated in `findings/` with a draft vendor email included
