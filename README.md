# Axiom

Axiom is a red team engine for finding vulnerabilities in open source language
models. It is aimed at new model releases: profile a target, generate attack
hypotheses grounded in how the model was likely trained, run them, and write up
the ones that reproduce.

## What it is

Most red team tooling is a scanner. It throws a fixed list of known attacks at a
target and reports what sticks. Axiom takes a different approach. It first builds
a theory of the target from its model card, architecture, and training notes,
then uses that theory to look for weaknesses that a fixed list would not contain.

The working assumption is that partial signals matter. A model that half complies
tells you where its safety training is thin, and that is the direction to push for
findings that are new rather than rediscovered.

## How it works

There are two generations of the engine in this repository.

v1 is a single research loop. It profiles the target, runs a catalog sweep of
known attacks as a baseline, then asks the research model to propose novel
hypotheses, designs probes for them, classifies each response, and generates a
disclosure report when a hypothesis holds up.

```
main.py (CLI)
  core/research.py          orchestration
    target/profiler.py      builds the target profile and adapter
    attacks/catalog.py      known-attack baseline sweep
    attacks/hypothesis.py   proposes novel hypotheses, designs probes
    analysis/analyzer.py    classifies each response
    disclosure/generator.py writes the disclosure report
```

v2 (see SPEC_V2.md) rebuilds this as a generate, test, measure, select loop. The
change exists because v1 could rate a finding highly and then reproduce it only
part of the time. v2 fixes that with three rules:

1. The generator never scores its own work.
2. Reliability is always K out of N repeated runs at a stated temperature. There
   is no confidence field anywhere in the system.
3. Novelty is distance in a measured behavior space, computed when a result is
   stored, not asserted by the proposer.

v2 organizes its search around one pattern that the strongest v1 findings shared:
safety enforced on one output channel but absent on a parallel one, for example
the final answer versus the reasoning span, prose versus a tool-call schema, or
freshly derived context versus inherited context. The loop sweeps that asymmetry
on purpose rather than rephrasing within a single channel.

## Model tiers

Axiom uses three model roles. The current assignment is in config.py.

| Role | Job |
|------|-----|
| Research | Threat model building, hypothesis generation, result synthesis |
| Execution | Probe design, target probing, response analysis |
| Interface | Short status and user-facing output |

## Targets

Axiom talks to targets through an adapter, so the same run works against a hosted
API or a local model. The api-type flag accepts anthropic, openai, http, local
(Ollama style endpoints), and musespark. The findings in this repository were
produced against Qwen3-14B served locally through Ollama.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then add your keys
```

The research and execution models are reached through the Anthropic API, so
ANTHROPIC_API_KEY is required. Target API keys are only needed for hosted
targets; a local Ollama target needs no key.

## Usage

Run a full session against a target:

```bash
python main.py run \
  --name "Qwen3-14B" \
  --model-id "qwen3:14b" \
  --api-type local \
  --endpoint http://localhost:11434/v1 \
  --context context/qwen3-14b.md
```

Useful flags:

| Flag | Effect |
|------|--------|
| --skip-catalog | Skip the known-attack sweep and go straight to novel hypotheses |
| --eval-aware | Target is known to detect evaluation contexts, so design stealthier probes |
| --context PATH | Feed the profiler extra notes, papers, or a model card |

Other commands:

```bash
python main.py findings              # list saved disclosure reports
python main.py explain findings/<report>.md   # explain a saved finding in detail
```

Run the v2 loop:

```bash
python -m v2.loop --generations 5 --batch-size 10
python -m v2.loop --seeds-only   # run catalog seeds, then stop
python -m v2.loop --triage       # print the triage queue from the saved archive
```

## Findings

Disclosure reports live in findings/. Each report states the target, the
vulnerability class, a mechanism hypothesis, reproduction steps, and a MITRE
ATLAS mapping. The reports here cover channel and ordering weaknesses in
Qwen3-14B, such as refusal that binds after the answer is already written,
reasoning-channel leakage, and inherited-context escalation.

Raw model outputs and session archives are kept out of version control.

## Repository layout

| Path | Contents |
|------|----------|
| main.py | v1 command line entry point |
| core/ | Research orchestration, interface, data models |
| target/ | Target profiler and adapter |
| attacks/ | Known-attack catalog and hypothesis generation |
| analysis/ | Response classifier |
| disclosure/ | Disclosure report generator |
| v2/ | Novelty-search loop: proposer, harness, featurizer, archive |
| findings/ | Disclosure reports (raw outputs are gitignored) |
| context/ | Target context files, for example qwen3-14b.md |
| SPEC_V2.md | Design spec for the v2 loop |

## Research directions

These are the questions the project is moving toward next.

Unbiased judging. The v2 rule that a generator never scores its own work is a
first step, but the scoring itself still needs to be trustworthy. The goal is a
judging setup where the decision about whether an attack succeeded does not
inherit the biases of any single model: for example using judges that are
separate from both the attacker and the target, checking judges against human
labels, measuring how much judges agree with each other, and looking for the
ways a judge can be talked into the wrong verdict. A red team engine is only as
honest as the judge that scores it.

Uncensored and abliterated models as red teamers. A growing set of open models
have had their refusal behavior removed or weakened. The question is whether a
model that will not refuse makes a better attacker, since it will follow through
on probe designs that a safety-tuned model declines to write. The plan is to run
the same targets with a safety-tuned proposer and with an uncensored or
abliterated proposer, then compare on real measures: how novel the attacks are,
how often they reproduce, and how much useful coverage they add. The risk to
watch is that an uncensored proposer produces more output without producing
better findings, so the comparison has to be on reliability and novelty, not
volume.

Turning findings into stronger models. The point of finding a weakness is to
close it. Each reproducible finding is a candidate training signal. The direction
is to take confirmed channel and ordering weaknesses back into evaluation sets
and, where possible, into training data, then re-run Axiom to check that the
specific weakness is gone and that the fix did not simply move the problem to a
neighboring channel. The measure of success is not the number of findings
produced but the number of weakness classes that later models no longer have.

## Scope and safety

Axiom is for security research and responsible disclosure. Findings are written
up so they can be sent to the model's maintainers. Some reports describe real
harm categories at the level needed to reproduce and fix the weakness; keep this
repository private and share reports through responsible disclosure channels.
