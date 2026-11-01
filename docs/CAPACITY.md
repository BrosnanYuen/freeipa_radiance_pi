# Capacity: 200k context on one R9700

**Status: not yet measured.** PLAN §8 makes this a gate: do not advertise a
context window that has not been measured on the actual card.

## Published reference (do not extrapolate blindly)

From radiance's `docs/GUIDE.md` §4.4, Qwen3.8-27B MXFP4 on **two** R9700s,
`--tp 2`, 12 GiB per card reserved, `--max-num-batched-tokens 2048`:

| `--kv-cache-dtype` | KV pool | Change vs fp8 |
|---|---|---|
| `fp8` | 518,800 tokens | baseline |
| `fp8_v4` | 664,400 tokens | +28% |
| `k6_v4` | 755,184 tokens | +46% |

The documented serve recipe is `--tp 2 --max-num-seqs 32 --max-model-len
200000 --kv-cache-dtype fp8`. The single-card number differs and **must be
measured**.

`--kv-resident` (streaming KV) is **not supported** for Qwen3.5/3.6/3.8 dense
(`qwen35_*`); the engine ignores it with a warning. Do not use it here.

## E0 procedure

1. Boot once with `--debug-placement` and capture the `kv:` receipt line (the
   pool covers N% of the worst case and M full-length sessions).
2. Boot with the flags from `compose.yaml` and request a near-200k prompt built
   with the engine's own tokenizer. The edge allowlist deliberately does not
   expose `/tokenize`; run `curl` inside the edge network namespace:
   `docker compose exec radiance-edge curl -s http://127.0.0.1:8000/tokenize ...`
3. Record admission (yes/no), TTFT, prefill tok/s, decode tok/s, peak VRAM, and
   `M` full-length sessions. Also record the exact image digest and flags.
4. Write the result here and set `RADIANCE_CONTEXT_WINDOW` (and Pi's
   `contextWindow`) to the measured `ctx_max`, not to 200000 by default.

## Measurement record

| Field | Value |
|---|---|
| Date | _(fill after E0)_ |
| GPU / VRAM | Radeon AI PRO R9700, 32 GB |
| Image digest | `stilldeadcode/radiance@sha256:cccbc0b…` |
| Model | `qwen3.8-27b-mxfp4.rad` |
| Flags | `--tp 1 --max-model-len 200000 --kv-cache-dtype fp8 --max-num-seqs 1 --max-num-batched-tokens 2048 --num-speculative-tokens 0 --mm-max-patches 0` |
| KV pool (tokens) | _(measure)_ |
| `M` full-length sessions | _(measure)_ |
| Near-200k admission | _(measure)_ |
| TTFT / prefill tok/s | _(measure)_ |
| Decode tok/s | _(measure)_ |
| Peak VRAM | _(measure)_ |
| `ctx_max` | _(measure)_ |

## Ladder if `M < 1`

Apply in order, re-measuring after each step:

1. `--kv-cache-dtype fp8_v4` (+28% pool), then `k6_v4` (+46%). These are real
   quantisations; run the T11b quality check before adopting.
2. `--state-cache-dtype f16` (halves recurrent state; lossy; only if the
   model's plugin serves it).
3. `--max-num-seqs 1`, `--max-num-batched-tokens 2048` (already set).
4. `--mm-max-patches 0`, `--num-speculative-tokens 0` (already set).
5. Lower `--max-model-len` to the measured `ctx_max` and set Pi's
   `contextWindow` to the same value (`pi-krb run --context-window N`).
6. Add a second R9700 and use `--tp 2` with the documented recipe.

`--attn-prefill-fp8 qk|pv|both` speeds 200k prefill (about +15–20% with `both`)
but is lossy and does **not** add KV capacity. Consider it only after
admission passes.

## Performance budgets

| Metric | Target |
|---|---|
| Auth + proxy overhead with a cached service ticket | p50 < 10 ms, p95 < 25 ms |
| First request after `kinit` (TGS) | < 100 ms |
| Streaming first-token penalty | < 50 ms |
| 100 concurrent authenticated mock requests | no 5xx |
| Edge CPU at 10 req/s | < 20% of one core |
