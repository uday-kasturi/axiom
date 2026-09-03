# Qwen3-14B — context for threat modeling

- Released April 2025 by Alibaba. Dense 14B model (not MoE — Qwen3-30B-A3B and
  Qwen3-235B-A22B are the MoE variants in the family).
- Key feature: **hybrid thinking mode**. The model can operate in "thinking" mode
  (emits a `<think>...</think>` reasoning block before the final answer, enabled
  by default / via `/think`) or "non-thinking" mode (direct answer, via `/no_think`
  or `enable_thinking=False` in the chat template).
- Served locally here via Ollama (`qwen3:14b`, Q4 quantization). The Ollama
  OpenAI-compat API returns the reasoning block in a separate `message.reasoning`
  field rather than inline `<think>` tags in `content`.
- Open-weight, Apache 2.0 license. Safety alignment is Alibaba's own RLHF/DPO
  pipeline — less publicly documented than OpenAI/Anthropic/Google approaches,
  and less independently red-teamed than frontier API models.

## Why this is interesting for novel hypotheses (not just OWASP-10)

1. **Thinking-mode behavioral delta**: does the model apply different (weaker)
   safety judgment when `/no_think` is set vs. default thinking mode, for the
   *same* prompt? Public benchmarks for Qwen3 safety mostly evaluate one mode at
   a time — the delta between modes for an identical prompt is undertested.

2. **Visible reasoning as an attack surface**: because the CoT is returned
   separately (not hidden, unlike o1/Claude extended thinking), it's possible to:
   - Inspect whether the model's *reasoning* concludes something harmful is "fine"
     even when its *final answer* refuses (a partial signal worth pursuing)
   - Seed a fake prior `<think>` block in the conversation history that already
     "concludes" a request is benign, and see if the model continues from that
     premise without re-deriving the safety judgment itself

3. **Reasoning-token exhaustion**: long/complex CoT can consume the full token
   budget before producing a final answer (observed during local testing — a
   100-token budget left `content` empty with the CoT mid-thought). Does forcing
   the model into a long reasoning chain (e.g. via a complex multi-constraint
   prompt) cause it to "settle" into compliance because the refusal-deciding step
   normally happens late in the CoT and gets truncated or skipped?
