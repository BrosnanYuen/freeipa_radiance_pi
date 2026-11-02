# Capacity: 200k context on one R9700

**Status: measured 2026-11-01.** A 197,952-token prompt was admitted on one
R9700 at `--max-model-len 200000`, with **M = 1.0** full-length session. Cold
TTFT was 145.4 s (1,361.8 tok/s prefill), decode 23.8 tok/s, peak VRAM 20.58 GiB.
The full receipt and measurement are in
[measurements/E0-2026-11-01.md](measurements/E0-2026-11-01.md).

`RADIANCE_CONTEXT_WINDOW=200000` and `CAPACITY_MEASURED=1` are now set, so the
GPU gate passes. The code still refuses an unmeasured value by default; the
shipped example remains `32768` / `0`.

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
   `docker compose exec radiance-gateway curl -s http://127.0.0.1:8000/tokenize ...`
3. Record admission (yes/no), TTFT, prefill tok/s, decode tok/s, peak VRAM, and
   `M` full-length sessions. Also record the exact image digest and flags.
4. Write the result here, set `RADIANCE_CONTEXT_WINDOW` to the measured
   `ctx_max`, and set `CAPACITY_MEASURED=1`. Do not leave either at the shipped
   development values (`32768` / `0`).

## Measurement record

| Field | Value |
|---|---|
| Date | 2026-11-01T08:00Z |
| GPU / VRAM | Radeon AI PRO R9700, gfx1201, 31.86 GiB usable |
| Image digest | `stilldeadcode/radiance@sha256:cccbc0bd6bfef1441e8fcf3ca8d10313d4e6d18a03d9c6ede3bcb15d95376668` |
| Model | `qwen3.8-27b-mxfp4.rad`, SHA-256 `a4908940…df4f8` |
| Flags | `--tp 1 --max-model-len 200000 --kv-cache-dtype fp8 --max-num-seqs 1 --max-num-batched-tokens 2048 --num-speculative-tokens 0 --mm-max-patches 0` |
| KV pool (tokens) | 200,000 (12,500 × 16-token blocks; 6.10 GiB attention + 146.81 MiB state) |
| `M` full-length sessions | **1.0** (100% of the worst case) |
| Near-200k admission | **yes**, 197,952 prompt tokens, HTTP 200, 197,984 total |
| TTFT / prefill tok/s | **145.356 s** cold / **1,361.8 tok/s**; warm 1.746 s with 196,608 cached tokens |
| Decode tok/s | **23.8** (128-token sample at ~198k context) |
| Peak VRAM | **20.58 GiB** (sysfs), engine budget 31.86 GiB total |
| `ctx_max` | **200,000** |

## Ladder if `M < 1`

Not applied: the fp8 measurement already gives `M = 1.0`. If a future model or
a smaller card needs it, apply in order, re-measuring after each step:

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

| Metric | Target | Measured |
|---|---|---|
| Auth + proxy overhead with a cached service ticket | p50 < 10 ms, p95 < 25 ms | **p50 1.77 ms, p95 2.22 ms** (50 requests, real model) |
| First request after `kinit` (TGS) | < 100 ms | not separately measured |
| Streaming first-token penalty | < 50 ms | ~1.7 s warm at 200k incl. prefix hit; not isolated |
| 100 concurrent authenticated mock requests | no 5xx | 100/100 HTTP 200 (mock; real engine is max-num-seqs 1) |
| Edge CPU at 10 req/s | < 20% of one core | not measured |

## What is now measured

The 18.04 GiB container is in `run/models/rad/`, hash-verified, and admitted at
197,952 tokens on one card. The measured `ctx_max` is 200,000, so `.env` carries
`RADIANCE_CONTEXT_WINDOW=200000` and `CAPACITY_MEASURED=1`.

The model-licence gate is separate: see [MODEL-LICENSES.md](MODEL-LICENSES.md).
