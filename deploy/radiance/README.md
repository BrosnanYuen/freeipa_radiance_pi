# radiance service

The real engine runs only in the `gpu` profile. It shares the edge's network
namespace (`network_mode: service:radiance-edge`), binds `127.0.0.1:8000` and
publishes no port. The edge injects the private API key on the loopback hop.

- `entrypoint.sh` reads `secrets/radiance_api_key` (0400 `${RADIANCE_UID}`),
  exports `RADIANCE_API_KEY`, and execs the image's own `radiance` binary.
  `--api-key-env RADIANCE_API_KEY` in `compose.yaml` keeps the key out of argv.
- `seccomp-radiance.json` is the upstream profile from
  `StillDeadcode/radiance` `deploy/compose/seccomp-radiance.json`
  (Apache-2.0), sha256
  `f2d45e2b897884f3cdad94f03503660175517bd2ab30968094a271af65a2bfcf`.
  Docker's default profile blocks `io_uring` and the NUMA calls ROCm makes, so
  this profile is **required** (`RADIANCE_SECCOMP` has no weak default).
- The flags in `compose.yaml` are the measured baseline from PLAN §6.3:
  one card (`--tp 1`), 200k requested, `fp8` KV, one sequence, 2048 batched
  tokens, no speculation, text only, no CORS.
- `docs/CAPACITY.md` records the E0 measurement; update `contextWindow` in
  Pi only after measuring.
