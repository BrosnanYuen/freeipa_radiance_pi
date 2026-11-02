# Model licence gate

Weights are licensed per model container, **not** by radiance's Apache-2.0
licence. Serving a model to other people can create obligations that the rest of
this stack does not have. This gate makes the decision explicit for every
`.rad` file in `RADIANCE_MODELS`.

## Rule

No model is served without an `allowed: true` record in
`$RADIANCE_MODELS/model-licenses.json`. `./scripts/up.sh --gpu` refuses to start
the engine when the gate fails, and `make license-check` runs the same check on
demand. A blocked model is blocked by *omission* from `models.json` as well; the
two mechanisms are redundant on purpose.

## Manifest

Place `model-licenses.json` beside the `.rad` containers:

```json
{
  "qwen3.8-27b-mxfp4.rad": {
    "license": "Apache-2.0",
    "allowed": true,
    "notes": "Internal use; upstream terms reviewed 2026-11-01."
  },
  "minimax-h3.rad": {
    "license": "Territory-restricted",
    "allowed": false,
    "notes": "Licence excludes the EU, UK, Republic of Korea and USA."
  }
}
```

Every field except `notes` is required. `allowed` is a boolean, not a string.
The checker exits non-zero when a container is undocumented, explicitly blocked,
or the manifest is malformed. Stale entries (a decision for a file that is no
longer present) are listed but do not fail the check.

## Current inventory

| Container | Licence | Decision | Notes |
|---|---|---|---|
| `qwen3.8-27b-mxfp4.rad` (18.04 GiB) | Apache-2.0 | allowed | Downloaded 2026-11-01 from `StillDeadcode/qwen3.8-27b-mxfp4`; SHA-256 `a4908940…df4f8` verified. Licence, model card, recipe and provenance are beside the file in `run/models/rad/`. |

The gate passes for the only supplied container. E0 has **not** been run, so the
200k context remains unmeasured; do not advertise it. See
[CAPACITY.md](CAPACITY.md).

## Evidence to keep with each decision

- the upstream model card or licence text and its retrieval date;
- the quantised container's provenance (who converted it, from which weights);
- any acceptable-use, territory, or non-commercial restriction;
- the decision owner and review date.

Store the one-page policy beside the model directory and link it from
[RUNBOOK.md](RUNBOOK.md). The manifest itself contains no secrets and is safe to
keep with the read-only model volume.

## Commands

```sh
make license-check                 # uses RADIANCE_MODELS from .env
python3 scripts/check_model_licenses.py --models-dir /srv/models/rad --json
```
