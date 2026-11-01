# Research: FreeIPA, radiance, and the Pi harness

**Prepared:** 2026-10-31 (America/Vancouver)
**Workspace:** `/home/brosnan/freeipa_radiance_pi` (remote: `github.com/BrosnanYuen/freeipa_radiance_pi`)
**Method:** primary sources only — project repositories, official docs sites, release notes. No component was cloned, built, installed, or benchmarked for this document; see [§12 Verification status](#12-verification-status). [§14](#14-addendum-verified-implementation-details-2026-10-31) adds facts verified after the main report (container docs, radiance guide/compose, FreeIPA CLI sources, Apache/mod_auth_gssapi, Pi source).

| Snapshot | Value |
|---|---|
| FreeIPA | `freeipa/freeipa` @ Codeberg, `master`, latest tag `release-4-13-4` (2026-09-07) |
| radiance | `StillDeadcode/radiance` @ Codeberg, `main`, version 1.15.1 (2026-10-31) |
| Pi | `pi.dev/docs/latest` (Pi 1.0 docs), npm `@earendil-works/pi-coding-agent` |
| Research date | 2026-10-31 |

---

## Contents

1. [Executive summary](#1-executive-summary)
2. [Why these three, and what this repo is](#2-why-these-three-and-what-this-repo-is)
3. [FreeIPA](#3-freeipa)
4. [radiance](#4-radiance)
5. [The Pi harness](#5-the-pi-harness)
6. [How the three fit together](#6-how-the-three-fit-together)
7. [Comparison matrix](#7-comparison-matrix)
8. [Licensing and compliance](#8-licensing-and-compliance)
9. [Risks and open questions](#9-risks-and-open-questions)
10. [Suggested next steps](#10-suggested-next-steps)
11. [Fact provenance](#11-fact-provenance)
12. [Verification status](#12-verification-status)
13. [Sources](#13-sources)
14. [Addendum: verified implementation details (2026-10-31)](#14-addendum-verified-implementation-details-2026-10-31)

---

## 1. Executive summary

The three projects sit at different layers of one stack:

| Layer | Project | Job |
|---|---|---|
| Identity, policy, audit | **FreeIPA** | Who a user or host is, what it may do, and what it can prove (Kerberos, LDAP, CA, DNS, HBAC, sudo) |
| Inference | **radiance** | Serves models (LLM, image, video, speech, music) over OpenAI/Anthropic/llama-server-compatible HTTP on AMD GPUs or CPU |
| Agent harness | **Pi** | Runs a terminal coding agent: model loop, tools, sessions, extensions, subprocess/RPC/SDK surfaces |

Three findings drive the rest of the document:

1. **Pi → radiance works today with configuration, not code.** radiance speaks OpenAI Chat Completions and Anthropic Messages; Pi already supports arbitrary OpenAI-compatible endpoints through `models.json`. No adapter is required for a first integration. The real work is model metadata (context window, tool-calling reliability) and deployment.
2. **FreeIPA does not authenticate the AI request path out of the box.** FreeIPA centralises *host and human* identity (Kerberos/LDAP, HBAC, sudo, certificates, DNS). radiance has a single shared bearer token and no user model; Pi has static keys, environment lookup, command-resolved keys, and provider extensions. App-level SSO therefore needs a gateway (e.g. Keycloak federated with FreeIPA, or `oauth2-proxy`), and radiance's own docs assume a TLS-terminating proxy in front of it.
3. **Maturity is asymmetric.** FreeIPA is a long-lived, security-audited enterprise component (4.13.4 shipped two CVEs with framework-wide access-control hardening). radiance is a fast-moving, largely single-maintainer project (1.15.1, RDNA4-first, minor releases landing within days of each other in October 2026). Pi 1.0 is recent, with an explicitly experimental harness-adapter ecosystem. Pin versions, test tool-calling, and expect churn.

**Bottom line:** the coherent architecture is *FreeIPA for the machines and people, radiance for inference, Pi as the client*, with a small auth gateway gluing the last two. Treat the FreeIPA ↔ radiance seam as design work, not configuration.

---

## 2. Why these three, and what this repo is

The workspace is nearly empty:

```
$ git log --oneline
4de2115 Add README.md file
803dfe4 Initial commit

$ ls -la
.git  LICENSE (35 KB, GPLv3 text)  README.md (2 bytes — blank)
```

So this repo is a **scaffold/holding repo**, not yet an implementation. Two consequences:

- **License choice is unresolved.** The root `LICENSE` is the GNU GPL v3 text (29 June 2007), while the three upstreams are GPLv3+ (FreeIPA), Apache-2.0 (radiance), and MIT (Pi). See [§8](#8-licensing-and-compliance).
- **There is no integration code yet.** Everything in [§6](#6-how-the-three-fit-together) is either documented capability or a proposed pattern, labelled accordingly.

### Name disambiguation

A few names are easy to confuse:

| Confusable | What it actually is |
|---|---|
| **radiance** (this doc) | AMD-GPU inference engine by StillDeadcode, Codeberg |
| **Radius** | Earendil's AI gateway (`radius.earendil.com`), a Pi provider — unrelated to radiance |
| **Pi** | Earendil's terminal coding agent (`pi.dev`) |
| **Pi Durable** | Earendil product shipped alongside Pi 1.0; not part of this stack |

Also note: the freeipa Codeberg repo is the current upstream home; the project migrated links from Pagure to Codeberg (commit *"Convert Pagure links to Codeberg"*, 2026-06-12).

---

## 3. FreeIPA

> **FreeIPA is an integrated Identity and Authentication solution for Linux/UNIX networked environments.** — repo description

### 3.1 What it is

FreeIPA is an integrated security information management system: centralised authentication, authorisation, and account information for users, groups, hosts, and services across a network of Linux machines. It is built from standard open-source components rather than reimplementing protocols:

| Component | Role in FreeIPA |
|---|---|
| **389 Directory Server** | Primary data store; multi-master LDAPv3 directory |
| **MIT Kerberos (KDC)** | Core of authentication; SSO tickets, keytabs |
| **Dogtag Certificate System** | Integrated CA/RA for certificates (host/service/user certs) |
| **ISC BIND** | Optional integrated DNS (dyndb), tightly coupled to Kerberos service discovery |
| **NTP** | Optional time service (Kerberos is clock-sensitive) |
| **SSSD** | Client-side integration (identity, auth, sudo, HBAC, autofs, SSH keys) |
| **certmonger** | Certificate lifecycle on hosts (request/renew via IPA CA) |
| **Samba / trust agents** | AD trust: cross-realm Kerberos, SID mapping, `ipa-adtrust-install` |

### 3.2 Architecture and management surfaces

- **Server**: one or more IPA masters in a domain (realm), full multi-master replication, replicated Kerberos and CA services. Replicas are normal deployment practice for redundancy.
- **Clients**: enrolled hosts (`ipa-client-install`), integrated via SSSD/PAM/NSS rather than raw LDAP binds.
- **APIs**: `ipa` CLI, Web UI, XML-RPC and JSON-RPC APIs, and a Python SDK (`ipalib`). The API is versioned and *validated at build time* against `API.txt` — a real compatibility contract.
- **Policy objects**: HBAC (host-based access control), sudo rules, SELinux user maps, automount maps, password/OTP policy, vaults, DNS zones, certificate profiles, privileges/RBAC.
- **Trusts**: two-way trust with Active Directory, including SID mapping and (in 4.13) trust namespace collision handling.

### 3.3 What the repository contains

`master` at 16,823 commits, 77 MiB, 40 branches, 167 tags. Language mix: Python 76.7%, C 10.5%, JavaScript 10.1%.

| Path | Contents |
|---|---|
| `install/` | Installer tooling, LDIF/schema, ACI templates, upgrade scripts, `freeipa-webui` submodule |
| `ipalib/` | Framework: plugins, RPC, parameters, errors, API versioning |
| `ipaserver/` | Server-side plugins (users, hosts, services, DNS, CA, trust, vault, OTP, RBAC) and the API/RPC framework |
| `ipaclient/`, `client/` | Client-side code and enrollment tooling |
| `ipapython/`, `ipaplatform/` | Shared Python utilities and per-distro platform abstraction |
| `ipatests/` | pytest functional/integration suites, Azure CI templates, test frameworks |
| `daemons/` | `ipa-otpd`, `ipa-kdb` (Kerberos KDB plugin), `ipa-custodia` vault daemon, and the 389-ds plugins (`ipa-slapi-plugins`, C) |
| `util/`, `asn1/`, `po/`, `selinux/`, `contrib/`, `doc/`, `pypi/`, `ipasphinx/` | Support, i18n, policy, docs, packaging |

Recent commits show active maintenance: dropping the Python `six` dependency (2026-10-28), a Kerberos KDB trust-context fix, trust namespace exclusions (`ipaNTTrustTLNExclusions`), and an `ipa-cacert-manage` password-visibility fix (CVE-2024-11029 related).

### 3.4 Build, test, and release engineering

From `BUILD.txt` and the repo:

- **Distro build**: RPM-first. `./makerpms.sh` (which also initialises the `freeipa-webui` submodule) → `dist/rpms` → `ipa-server-install`. Under the hood: `autoreconf -i && ./configure && make && make install`, with real work in spec `%pre/%post`.
- **Build deps**: `dnf builddep -D "with_wheels 1" -D "with_lint 1" -D "with_doc 1" --spec freeipa.spec.in`, with a `@freeipa/freeipa-master` COPR for bleeding edge.
- **Tests**: pytest. Two-session workflow: `make lite-server` in one shell, `make test` in another, after `kinit admin`. `make fastcheck` runs fast unit tests + lint on modified lines. DNS/XML-RPC suites skip themselves when the underlying install lacks those services.
- **API contract**: `makeapi` generates `API.txt`; validation is part of the build. Any API change requires a MAJOR/MINOR version bump and a committed `API.txt`.
- **CI**: `.github`, `.forgejo`, `.freeipa-pr-ci.yaml`, Azure templates under `ipatests/azure/templates/`.
- **Not relocatable**: IPA installs where the spec puts it.

This is a conventional, conservative, distro-integrated project. Expect packaging friction outside Fedora/RHEL.

### 3.5 Releases and current security posture

Documented releases (site + tags):

| Version | Date | Notes |
|---|---|---|
| 4.13.4 | 2026-09-07 | Security release: CVE-2026-79678, CVE-2026-76578 + stabilization |
| 4.13.3 | 2026-08-19 | Stabilization |
| 4.13.2 | 2026-07-16 | Stabilization |
| 4.13.1 | 2026-01-16 | Stabilization |
| 4.13.0 | 2025-12-04 | Feature release |
| 4.12.5 | 2025-09-30 | Previous series |

The 4.13.4 notes are worth reading for anyone deploying this stack:

- **CVE-2026-79678** — `idp-add` reached `ipapython.ipautil.template_str()`, which `eval()`s post-substitution tokens, *before* the LDAP ACI check. Any authenticated IPA principal could trigger it via `--organization`/`--base-url`. The fix not only patched `idp-add` but added an access-control check to *all* IPA API operations, consulting both managed permissions and implicit LDAP ACIs.
- **CVE-2026-76578** — an unauthenticated LDAP client (anonymous bind / SASL ANONYMOUS) could create a self-managed OTP token with empty `ipaTokenOwner`/`managedBy` that satisfied 389-ds's SELFDN evaluator, then inject an attacker-chosen Kerberos principal. Fix tightens self-service bind rules to require `ldap:///self` **and** `ldap:///all`, plus anonymous-deny ACIs and delegation scoping.

Takeaway: **pin ≥ 4.13.4**, and expect the access-control model itself to have changed on upgrade (ACI regeneration, upgrade scripts `21-*`).

### 3.6 Operating model and requirements

From the Quick Start Guide:

- **Supported platforms**: Fedora and Red Hat Enterprise Linux (RHEL 8/9 documentation is the reference user guide; the upstream user guide is unmaintained). Debian/Ubuntu packaging exists downstream but is not the supported path.
- **RAM**: absolute minimum ~1.2 GB to install with a CA; 2 GB recommended for a demo/test system.
- **Hostname/DNS**: static FQDN, resolvable forward and reverse, reverse must match, not `localhost`; use a reserved test domain (`ipa.test`) rather than a real one. Kerberos breaks if the hostname changes.
- **Firewall**: Kerberos, HTTP/HTTPS, DNS, NTP, LDAP/LDAPS (`freeipa-4` firewalld service).
- **Install**: `dnf install freeipa-server freeipa-server-dns` then `ipa-server-install` (interactive or flags). Admin access via `kinit admin`; Directory Manager is reserved for low-level tasks.
- **Docker**: a container exists and is positioned for quick, isolated testing; the RPM install remains the documented path.

### 3.7 Strengths and constraints

**Strengths**

- Standards-based (LDAP, Kerberos, X.509, DNS) — no proprietary lock-in; clients are ordinary Linux hosts.
- Real policy engine: HBAC, sudo, SELinux maps, automount, OTP, vaults, RBAC, AD trust.
- Strong API discipline (`API.txt` validation) and packaged, testable upgrades.
- Security team that does coordinated disclosure and framework-level fixes, not just point patches.

**Constraints**

- Heavy to operate: DNS + Kerberos + CA + LDAP + NTP, plus replication topology, backups, and clock hygiene.
- Distro-bound (RPM ecosystem); container/immutable-OS deployments are awkward.
- No general-purpose OIDC/OAuth2 authorisation server. It *consumes* external IdPs (`ipa idp-add` templates for Okta, Keycloak, Microsoft) so IPA users can log in to IPA itself; it is not a token issuer for your applications. Application SSO is conventionally LDAP bind, Kerberos/GSSAPI, or certificate auth — or a federated gateway such as Keycloak.
- Upgrades can rewrite ACIs and permissions (see 4.13.4); test upgrades, don't assume they are inert.

---

## 4. radiance

> **An inference server for AMD GPUs, in C++ and HIP: language models, and image, video, speech and music generation.** — README

### 4.1 What it is

A single-process inference engine targeting AMD hardware, with an HTTP server that is API-compatible with the ecosystems around OpenAI, Anthropic, and llama.cpp. It is not a wrapper around vLLM or llama.cpp; it reimplements the serving core and lifts selected text-frontend pieces from llama.cpp under MIT.

Key facts:

- **Stack**: C++20 + HIP; CMake 3.21+/Ninja; no Python in the engine (Python only in a few offline helpers such as `tools/pad_tp.py` and `tests/mkgolden.py`).
- **Hardware**: bundled device kernels (`libr4d`) target AMD RDNA4 (`gfx1200`, `gfx1201`). The engine starts on any AMD GPU family but needs a kernel library for that family. A GPU-less machine builds the host backend (`libavx`, AVX-512/AVX2) plus `libref` (plain C++ reference kernels); small models run interactively on a desktop CPU, 27B+ run slowly.
- **Reference deployment**: two 32 GB Radeon AI PRO R9700s; ROCm 10.1 or 7.2 with `hipcc`; Resizable BAR strongly recommended.
- **Repo**: 770 commits, 36 tags, 217 MiB; C++ 75.5%, HIP 19.7%.
- **Version**: 1.15.1, 2026-10-31.

### 4.2 Design thesis

The spec is explicit about *why* it exists. Serving four models on one card with vLLM took 24 monkey-patches, grouped into seven classes, each of which became a designed extension point:

| vLLM pain | Count | radiance answer |
|---|---|---|
| Kernel substitution | 7 | Kernel plugin hierarchy |
| Fusion coverage | 1 | Fusions are ops selection can choose |
| Per-step host cost / metadata sharing | 4 | Core-owned step batch, built once |
| KV group sizing for hybrid models | 1 | Hybrid KV groups are first-class |
| Speculative decode plumbing | 5 | Drafter declared by the model's own plugin |
| Chat template + tool parsing | 2 | Lifted/rewritten from llama.cpp |
| Platform detection | 2 | N/A |

Scope is stated both ways. **In**: continuous batching, paged KV, prefix caching, tensor parallelism, speculative decoding, hybrid KV (full + sliding-window + linear attention in one model), weight placement across VRAM/RAM/SSD with runtime re-placement, OpenAI/Anthropic/llama-server servers, embeddings, image generation, quantisation, and LoRA adapters served beside a base model. **Out**: training, pipeline parallelism, CUDA, disaggregated prefill.

### 4.3 Architecture in one page

**Three plugin types, C ABI only, loaded from `$RADIANCE_HOME`:**

| Plugin | Directory | Supplies |
|---|---|---|
| Kernel | `kernels/*.so` | Ops as "rows" with constraints, tunables, layouts, launch fns |
| Architecture | `architectures/*.so` | One architecture id × one quantisation scheme; declares weights, buffers, ops, chat format |
| Quantiser | under `$RADIANCE_HOME` (exact subdirectory not in the excerpt reviewed) | Encoding/decoding paths for weight formats |

Every plugin exports `rad_plugin_abi_version()` and `rad_plugin_info()`; mismatches are refused at load.

**Two-phase construction:**

1. **Declare.** The architecture plugin enumerates every weight, buffer, and op it will issue. The core resolves each op against the kernel hierarchy and reports *every* unresolved op together. It also produces the weight manifest, the buffer plan (activation liveness → one arena), and the tuning requests.
2. **Plan → Load → Serve.** The placement planner assigns each weight a tier and execution site against explicit pool budgets; weights are staged accordingly; then the engine serves.

**Kernel selection** is core-owned and absolute: plugins are queried in hierarchy order; the first plugin with a matching kernel wins, whatever a lower plugin offers (so user overrides are reliable). Within a plugin, highest priority wins, ties by declaration order. **Specificity is declared, not derived** — deliberate, because counting matched constraints would rank specialised kernels below broad ones.

**Shape domains:** parameters can be ranges (e.g. GEMM `M` from 1 to `max_tok`). The core builds a per-band **bucket table** so decode (M≈1), speculative verify (M≈64), and prefill (thousands) each hit an appropriate kernel. `--debug-graph` prints the table.

**Fusion is a selection, not a compiler pass:** the plugin asks for the fused op; if unresolved, it emits the unfused sequence. Fusion kernels declare the chain they replace (`replaces`), so byte-identical equivalence is testable.

**Observability** is first-class: `--debug-graph`, `--debug-selection`, `--debug-placement`, `--profile-ops`, `--live` (one `key=value` line when redirected). A `rad-tune` tool benchmarks tunable axes per machine into `$RADIANCE_HOME/tune/<machine>.tune` (UTF-8, diffable, editable).

**Correctness:** `libref` is both oracle and opt-in fallback; `RADIANCE_OP_ORACLE` can run a reference kernel beside a device issue on the engine's own shapes. Device misses with no host stand-in are fatal at startup (`RAD_E_NOKERNEL`), naming the ops.

### 4.4 Runtime, scheduling, and serving details

- **One process, one thread per tensor-parallel rank**, each owning one device — ranks share an address space, so no IPC or serialisation; the batch is shared by pointer.
- **Dispatch** writes AQL packets directly (~6 ns host time vs 0.5–1.3 µs for `hipLaunchKernel`), and decode passes are recorded and replayed, verified every 1024th play against a fresh issue.
- **Batching**: continuous batching, paged KV, prefix caching keyed by content for media, hybrid KV groups, chunked prefill.
- **Speculative decoding**: `--num-speculative-tokens auto` resolved from the drafter's declared depth; n-gram prompt lookup beneath it; block-drafter tree verification; rollback semantics differ for paged KV vs linear state.
- **Multimodal**: Qwen-VL, Gemma 4, LFM2-VL, GLM-5.3 processors; M-RoPE positions; encoding happens *between* steps, never inside one; data URLs only (no server-side fetch, to avoid SSRF).
- **Text frontend**: Jinja engine and reply-format analysis lifted from llama.cpp; reply parser rewritten as a single streaming pass; GBNF grammar masks; sampling on device with an explicit, documented deviation from llama.cpp's chain order (vLLM order: penalties → temperature → grammar mask → top-k → top-p/min-p/typical → XTC → pick), and a stateless counter-based RNG.
- **Server**: OpenAI (`/v1/chat/completions`, `/v1/completions`, `/v1/models`, `/v1/embeddings`, `/v1/images/*`, `/v1/responses`, `/v1/systemone`), Anthropic (`/v1/messages`, `/v1/messages/count_tokens`), llama-server native (`/completion`, `/infill`, `/props`, `/apply-template`), plus operational endpoints (`/health`, `/ping`, `/load`, `/version`, `/server_info`, `/diagnostics`, `/tokenize`, `/detokenize`, `/get_tokenizer_info`, `/reset_prefix_cache`), Prometheus `/metrics` with vLLM's metric names, and an HTML dashboard at `/` and `/dashboard`.

### 4.5 Models and containers

A `.rad` **container** holds weights, tokeniser, chat template, and any drafter. `--model` accepts a path *or* a Hugging Face repo id (fetched with `scripts/hfget.sh` into `~/.cache/radiance/hf`). `rad-convert` builds containers from HF checkpoints with `data/recipes/*.recipe`, supporting FP8, MXFP4, GPTQ/AWQ/AutoRound, int4/int8, ParoQuant, compressed-tensors, and SDXL single-file checkpoints.

The model table is broad (Qwen3.8, Qwen3.6, Ornith, Sage, MiniCPM5, Gemma 4, Nemotron 3.5, GLM-5.3-Flash, Qwen-Image, Krea, FLUX.3, LTX-2.5, MiniMax-H3/Music3, Breeze-TTS-2, Fish drama-3, EmbeddingGemma 2, Nemotron Embed/Rerank, Qwen3-ASR, SDXL finetunes). **Licensing is per model, not per project** — see [§8](#8-licensing-and-compliance).

Operational constraint from the README: *every model listens on the same port and most use both cards, so run one at a time.* Multi-model serving means multiple instances/ports with disciplined VRAM budgeting, or bigger hardware.

### 4.6 Authentication and security posture

- **One shared secret**: `--api-key KEY` requires `Authorization: Bearer KEY` or `X-Api-Key: KEY`.
- **No user accounts, no roles, no per-request identity.** Authorisation is "has the key" or "is on loopback".
- **1.15.1 hardening** (worth pinning for):
  - Keyless loopback-only routes now require a loopback socket, matching `Origin`, and a `Host` naming loopback or `--allow-host`; a TLS proxy on loopback no longer makes every client "local".
  - `--trusted-proxy CIDR` (repeatable): `X-Forwarded-For` from a vouched network names the caller in logs, but **authority still reads the socket**.
  - A 401 closes the connection; unread-body drains are bounded; multipart fields and buffered Anthropic tool arguments share JSON size/depth gates.
  - 500s carry a generic wire message (reason stays in the log); duplicate security-relevant headers are refused; empty `--api-key` is a startup error.
  - `hfget.sh` vets repo listing filenames before fetching and hashes each LFS download against its oid; `vendor/SHA256SUMS` pins vendored files.
- **TLS**: not terminated by radiance; deployments are expected to front it with a TLS proxy (the 1.15.1 proxy hardening implicitly confirms this model).

### 4.7 Build, deploy, test

**Docker** (recommended path): host needs Docker and an `amdgpu` driver supporting ROCm 10.1; no ROCm install needed.

```sh
docker pull stilldeadcode/radiance
git clone https://codeberg.org/StillDeadcode/radiance.git
cp -r radiance/deploy/compose ~/radiance-compose && cd ~/radiance-compose
cp .env.example .env                       # RADIANCE_MODELS, RADIANCE_API_KEY, GIDs
docker compose -f minicpm5-2b.yaml up -d
```

**Source**: Linux, git, C++20 compiler, CMake 3.21+, Ninja; ROCm 10.1 or 7.2 for device kernels.

```sh
git clone https://codeberg.org/StillDeadcode/radiance.git && cd radiance
./build.sh                                 # configure, build for cards present, run fast tests
./build.sh --no-hip                        # host backend only
```

**Run**:

```sh
export RADIANCE_HOME=$PWD/build/radiance_home
build/bin/radiance --model /srv/models/rad/minicpm5-2b-fp8.rad \
  --port 8000 --api-key "$RADIANCE_API_KEY"
```

**Tests**: `ctest --test-dir build -L fast` (<15 s), `-LE 'gpu|oot'` (~5 min, no card), `-L gpu`, `-L oot`; presets `fast`, `host`, `gpu`, `full`, `asan`. CI: Woodpecker (`.woodpecker.yml`) plus vendor hashing checks.

### 4.8 Maturity assessment

**Signals of engineering rigour**: an explicit design spec with trade-off tables; declared-not-derived kernel specificity; bucket tables instead of resolve-once; replay verification; two oracles; tuning cache designed for humans to read/diff; vendor pinning; per-release server-hardening lists.

**Signals of youth**: 1.x versioning with frequent minor bumps (1.7 → 1.15 in ~2 weeks of October 2026); one dominant author and maintainer; small issue/PR counts (10 issues, 15 PRs at snapshot); no stable release page (tags only); RDNA4-first hardware support with other families needing external kernel libraries; single shared API key as the entire auth model.

**Practical stance:** excellent fit for a single-team, single-tenant, AMD workstation/server with pinned versions and a trusted network. Not yet a drop-in multi-tenant inference platform.

---

## 5. The Pi harness

> **Pi is an extensible AI agent that works from your terminal.** Give it a goal and a working folder, and it can inspect files, run commands, edit content, and work through multi-step tasks. — docs

### 5.1 What "harness" means here

"Pi harness" is used in three overlapping senses, and it is worth being precise because integrations differ:

1. **Pi itself as an agent harness.** The runtime that owns the agent loop, tool execution, context assembly, session storage, and terminal UI. This is what `pi.dev/docs/latest` documents and what `@earendil-works/pi-coding-agent` ships.
2. **Harness adapters** that wrap Pi for another framework. Vercel's AI SDK lists Pi under [AI SDK Harnesses](https://ai-sdk.dev/providers/ai-sdk-harnesses/pi): `@ai-sdk/harness-pi` exposes `pi` / `createPi()`, and `HarnessAgent` drives `@earendil-works/pi-coding-agent`, with Pi running in the host Node process and using the sandbox as a remote filesystem and shell. Explicitly **experimental**.
3. **Community runtime packages** also exist (e.g. `pi-harness-runtime`, `@baryonlabs/pi-agent-harness`); their scope and stability vary, so verify before depending on them.

This document treats sense 1 as primary and notes 2–3 where relevant.

### 5.2 Install and first run

```sh
# Installer (pins dependencies; update with `pi update`)
curl -fsSL https://pi.dev/install.sh | sh

# npm (does not pin transitive deps; Node.js >= 22.19)
npm install -g --ignore-scripts @earendil-works/pi-coding-agent

# Nix (builds from source; update with `nix profile upgrade pi`)
nix profile add github:earendil-works/pi/stable

pi --version
```

Then: `cd /path/to/folder && pi`, `/login` (provider), `/model`, and a task. Sessions persist automatically; `pi --continue` resumes the most recent session for the folder.

### 5.3 How it works

- **Agent loop**: a submitted message joins the active branch; Pi builds a request from system prompt + active branch + tools + model settings; the provider streams text and tool calls; Pi records the response, executes tools, records results; repeat while tool results or queued messages require another turn.
- **Context**: the active branch supplies history; the system prompt is base instructions + discovered context files; tools and skill *descriptions* are declared, full skill instructions load on demand; extensions can add instructions or transform context. Prompt templates expand editor input. `@file` content, images, pasted text, and shell output become message content.
- **Sessions**: JSONL files; entries form a **tree** with parent IDs; each path is a branch; the branch ending at the current entry is history. Continue/fork/clone create branches; compaction inserts a summary entry that replaces older messages in later requests while original entries remain.
- **Interfaces**: interactive TUI, print mode (`-p`), JSON event stream (`--mode json`), RPC (`--mode rpc`), TypeScript SDK. All share the same agent and session machinery.

### 5.4 Tools and extension points

| Need | Mechanism |
|---|---|
| Persistent folder instructions | `AGENTS.md` / `CLAUDE.md` (context files) |
| Reusable prompt from `/` menu | Prompt template |
| Task-specific instructions + files | Skill |
| Executable tools, commands, event handlers | Extension (TypeScript module) |
| Custom terminal component | TUI extension |
| Unsupported model service | Custom provider |
| Distribute several resources | Pi package (npm/git) |

Built-in tools: `read`, `bash`, `edit`, `write`, `grep`, `find`, `ls` (plus `powershell` on Windows). Built-in extensions add `codemode` (JavaScript in a QuickJS sandbox that calls other tools, supports parallel calls and model classifiers/image models) and `tool_search` (deferred tool discovery). MCP servers are supported natively.

### 5.5 Model connectivity

- `/login` for built-in providers (Anthropic, OpenAI, DeepSeek, Google, OpenRouter, Bedrock, Vertex, Mistral, Groq, Cerebras, xAI, OpenCode, Qwen, MiniMax, Kimi, and more), via OAuth or API key; TypeSafe supplies classifier models rather than chat.
- `/model`, `/thinking`, `Ctrl+P` cycling, `/scoped-models`.
- **llama.cpp router** is integrated directly: `/login llama.cpp`, `/llama` to load/unload/download models, `/model` to select. Env fallback: `LLAMA_BASE_URL`, `LLAMA_API_KEY`.
- **Everything else** that speaks a supported API goes in `models.json` (Ollama, LM Studio, vLLM, SGLang, gateways — and radiance).

`models.json` provider fields (from the reference):

| Field | Notes |
|---|---|
| `baseUrl` | API base, e.g. `http://127.0.0.1:8000/v1` |
| `api` | `openai-completions`, `openai-responses`, `anthropic-messages`, `google-generative-ai`, … |
| `apiKey` | Literal, `$NAME` / `${NAME}`, or `!command` output |
| `headers` | Same resolution rules as `apiKey` |
| `authHeader` | Whether to send the key as `Authorization: Bearer` (default `false` — **set this deliberately**) |
| `compat` | Verified protocol differences (thinking format, tool strictness, usage-in-streaming, etc.) |
| `models[]` | `id` required; `name`, `reasoning`, `input`, `contextWindow` (default 128000), `maxTokens` (default 16384), `cost.*` |
| `modelOverrides` | Metadata-only changes to existing models |

### 5.6 Configuration layout

- **User**: `~/.pi/agent` (override with `PI_CODING_AGENT_DIR`) — `settings.json`, `keybindings.json`, `mcp.json`, `models.json`, `auth.json`, `AGENTS.md`/`CLAUDE.md`, `SYSTEM.md`, `APPEND_SYSTEM.md`, `extensions/`, `skills/`, `prompts/`, `themes/`.
- **Project**: `.pi/` — `settings.json`, `mcp.json`, `SYSTEM.md`, `APPEND_SYSTEM.md`, `extensions/`, `skills/`, `prompts/`, `themes/`. Loaded only after project trust.
- **Context files**: discovered from the agent dir, working dir, and parents; discovery does not require trust.

### 5.7 Security posture

Pi is explicit: project trust controls *which project resources load*, not *what tool calls may do*. Tools and extensions run with the permissions of the Pi process. The docs recommend containers or sandboxes for untrusted or unattended work, and warn that provider extensions can inspect credentials, prompts, tool definitions, and responses. For this stack that means: **Pi running on an enrolled FreeIPA host is a real identity boundary** (the OS user), and Pi's own `bash` tool is equivalent to a shell as that user.

### 5.8 Maturity

- Pi 1.0 (announced with Pi Durable) is recent; docs are versioned `latest`.
- npm package is the distribution point; installer and Nix pin dependencies, npm does not.
- Extension/provider APIs are documented but young; the AI SDK harness adapter is labelled experimental.
- MIT licensed.

---

## 6. How the three fit together

### 6.1 Layered view

```
            ┌──────────────────────────────────────────────┐
            │  Humans / automation                          │
            └───────────────┬──────────────────────────────┘
                            │ login, SSH, tickets
            ┌───────────────▼──────────────────────────────┐
            │  FreeIPA realm                                │
            │  users · hosts · HBAC · sudo · DNS · CA       │
            │  Kerberos KDC · LDAP · certmonger/SSSD        │
            └───────────────┬──────────────────────────────┘
                            │ host identity, TLS certs, policy
            ┌───────────────▼──────────────────────────────┐
            │  Agent host (IPA client)                      │
            │  ┌────────────────────────────────────────┐   │
            │  │ Pi harness (per OS user)                │   │
            │  │ tools: bash/edit/write/read …           │   │
            │  └───────────────┬────────────────────────┘   │
            │                  │ HTTP + bearer key          │
            │  ┌───────────────▼────────────────────────┐   │
            │  │ TLS/auth proxy (optional, recommended) │   │
            │  └───────────────┬────────────────────────┘   │
            └──────────────────┼────────────────────────────┘
                               │ /v1/chat/completions, /v1/messages …
            ┌──────────────────▼────────────────────────────┐
            │  radiance (AMD GPU / CPU)                      │
            │  OpenAI · Anthropic · llama-server APIs        │
            │  one shared API key · no per-user identity     │
            └───────────────────────────────────────────────┘
```

### 6.2 Pi → radiance (documented, works today)

radiance implements OpenAI Chat Completions with streaming, tool calls in/out, and logprobs; Pi implements the client side. The integration is a `models.json` entry.

**Step 1 — serve a model.**

```sh
export RADIANCE_API_KEY="$(openssl rand -hex 24)"
build/bin/radiance --model /srv/models/rad/qwen3.8-27b-fp8.rad \
  --port 8000 --api-key "$RADIANCE_API_KEY"
```

**Step 2 — smoke-test the endpoint (including tools).**

```sh
curl -s localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $RADIANCE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"m","messages":[{"role":"user","content":"hi"}],"max_tokens":50}'

curl -s localhost:8000/v1/models -H "Authorization: Bearer $RADIANCE_API_KEY"
```

**Step 3 — register the endpoint with Pi** in `~/.pi/agent/models.json`:

```json
{
  "$schema": "https://pi.dev/schemas/models.schema.json",
  "providers": {
    "radiance": {
      "name": "radiance (local AMD)",
      "baseUrl": "http://127.0.0.1:8000/v1",
      "api": "openai-completions",
      "apiKey": "$RADIANCE_API_KEY",
      "authHeader": true,
      "models": [
        {
          "id": "qwen3.8-27b",
          "name": "Qwen3.8 27B (radiance)",
          "reasoning": false,
          "input": ["text", "image"],
          "contextWindow": 200000,
          "maxTokens": 16384,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

**Step 4 — run Pi against it.**

```sh
export RADIANCE_API_KEY="…"
pi --model radiance/qwen3.8-27b

# non-interactive smoke test (CI, cron, scripts)
pi --print "List the files in this directory" --model radiance/qwen3.8-27b
```

**Why the fields matter**

| Field | Reason |
|---|---|
| `baseUrl …/v1` | radiance also serves without the `/v1` prefix; Pi expects the standard base |
| `api: openai-completions` | Pi's OpenAI Chat Completions implementation; radiance's native surface |
| `authHeader: true` | default is `false`; radiance expects `Authorization: Bearer` or `X-Api-Key` |
| `apiKey: "$RADIANCE_API_KEY"` | env interpolation; keeps the secret out of the file |
| `contextWindow` / `maxTokens` | Pi defaults to 128k/16k if omitted; set them to the served container's real limits |
| `input: ["text","image"]` | only if the container carries a vision tower and `--mm-max-patches` is set |
| `cost: 0` | required shape if `cost` is present; keeps cost accounting meaningful |

**Caveats and verification checklist** (all marked *unverified* here):

- [ ] **Tool calling.** radiance derives tool syntax from the model's chat template; a template the analyser cannot read means tool requests are *refused by name* rather than guessed. Verify a real tool round-trip with the specific container before relying on Pi.
- [ ] **Model id.** radiance's examples use `"m"` as an arbitrary id; Pi sends the configured `id`. Confirm the server does not require an exact id (the OpenAI surface generally ignores it).
- [ ] **`max_tokens` vs `max_completion_tokens`.** Pi auto-detects from URL for `openai-completions`; if requests fail, set `compat.maxTokensField`.
- [ ] **Streaming usage.** Set `compat.supportsUsageInStreaming` if the server omits usage in streamed chunks (radiance does report usage in Responses/Anthropic shapes; verify OpenAI streaming).
- [ ] **Thinking/reasoning.** If the container emits `reasoning_content`, decide whether Pi should treat it as reasoning (`reasoning: true`, `thinkingFormat`) or plain text; radiance's guide documents per-model template behaviour.
- [ ] **Prompt caching.** radiance has prefix caching; Pi's `promptCache` warms based on declared lifetimes. Only declare lifetimes you have measured.
- [ ] **Images.** data URLs only; Pi encodes images with resize limits before sending — check `inputLimits.images` against the model's patch budget.
- [ ] **Concurrency.** one model per port; Pi sessions are single-user, so this is usually fine, but multiple Pi processes contend for `--max-num-seqs`.

### 6.3 FreeIPA's role (and its limits)

**Where FreeIPA genuinely helps this stack**

| Capability | Use |
|---|---|
| Host identity + HBAC | Decide which machines may run Pi/radiance; revoke access centrally |
| SSSD/PAM/NSS | `pi` runs as an IPA user with centrally managed account lifecycle (disable, expire, 2FA/OTP) |
| sudo rules | Control who may restart radiance, read the model directory, edit `models.json` |
| Integrated DNS | Publish `radiance.ipa.test`, reverse records; Kerberos service discovery |
| Dogtag CA + certmonger | Issue and auto-renew TLS certificates for the proxy in front of radiance |
| Vault | Store the radiance API key / gateway client secret |
| Audit | Central account and access records; HBAC/sudo changes are attributable |

**Where it does not reach**

- **No OIDC/OAuth2 authorisation server** for your apps. `ipa idp-add` is the *reverse* direction: IPA consumes Okta/Keycloak/Microsoft as an identity provider.
- **No API-key issuance, quotas, or per-user rate limiting** for radiance.
- **radiance does not speak GSSAPI, LDAP, or mTLS**, so Kerberos tickets and service keytabs cannot be presented to it directly.
- **Pi does not speak GSSAPI** for model endpoints either; it has static keys, env, `!command`, and provider OAuth extensions.

### 6.4 App-level auth options (proposed)

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. Shared key + network isolation** | radiance `--api-key`, bound to loopback or a private interface, TLS proxy in front; key distributed via IPA vault/secret store | Simplest; matches radiance's design | One key for everyone; rotation is all-or-nothing; no attribution |
| **B. OIDC gateway** | Keycloak federated with FreeIPA (LDAP/Kerberos user store) issues tokens; `oauth2-proxy` or an API gateway validates them and injects radiance's key upstream | Real SSO, per-user audit, group-based authorisation | Extra component to operate; two identity systems to keep consistent |
| **C. Per-user keys via `!command`** | Pi `apiKey: "!ipa-token-helper"` or `"!op read …"`; helper returns a short-lived token from a gateway or vault, keyed to the IPA identity | No long-lived secret on disk; per-user attribution at the gateway | Requires the helper + issuer; Pi caches command output for the process lifetime |
| **D. Per-team instances** | Separate radiance instances/ports per team or project, each with its own key and model set | Blast-radius isolation; simple | VRAM-hungry; operational overhead |

For most teams, **A now, B later**: ship with loopback/TLS-proxy isolation and a vaulted key, then add Keycloak when multi-user attribution or quotas become requirements. Option C is the cleanest long-term fit with Pi's `!command` credential support, but it needs a token issuer that does not exist in this stack yet.

### 6.5 Gaps summary

| Gap | Impact | Workaround |
|---|---|---|
| radiance has one shared secret | No per-user identity/quotas | Gateway (B) or per-instance keys (D) |
| radiance terminates no TLS | Traffic must be protected | TLS proxy with IPA-issued cert |
| FreeIPA has no app OIDC issuer | Cannot mint tokens for Pi/radiance | Keycloak/`oauth2-proxy` federated with IPA |
| Pi has no Kerberos/GSSAPI for model APIs | Cannot reuse tickets | `!command` tokens or static keys |
| radiance is AMD/RDNA4-first | Hardware constraints | Host backend for dev; RDNA4 for production |
| Model licenses vary | Legal exposure | Per-container license review (§8) |
| Pi tools run with OS permissions | Prompt-injection blast radius | Sandbox/container, least-privilege users, HBAC |

---

## 7. Comparison matrix

| Dimension | FreeIPA | radiance | Pi |
|---|---|---|---|
| **Category** | Identity/authN/authZ + policy | Inference server / engine | Terminal agent harness |
| **Primary language** | Python (76.7%), C (10.5%), JS (10.1%) | C++ (75.5%), HIP (19.7%) | TypeScript (Node.js) |
| **License** | GPL-3.0-or-later | Apache-2.0 (+ NOTICE) | MIT |
| **Latest version** | 4.13.4 (2026-09-07) | 1.15.1 (2026-10-31) | Pi 1.0 (docs "latest", 2026) |
| **Repo activity** | 16.8k commits, 167 tags, 40 branches | 770 commits, 36 tags, 1 branch | npm + GitHub monorepo, packages |
| **Platform** | Fedora / RHEL (RPM) | Linux + AMD GPU (ROCm 10.1/7.2) or CPU | macOS / Linux / Windows / Termux; Node ≥22.19 |
| **Install** | `dnf` + `ipa-server-install` | Docker image or `./build.sh` | `install.sh`, npm, Nix |
| **Hardware floor** | ~1.2 GB RAM (2 GB rec.) | 32 GB VRAM per card recommended; CPU fallback | Any laptop |
| **Config surface** | CLI, Web UI, JSON-RPC/XML-RPC, Python SDK | flags + env + compose; plugins (.so) | `settings.json`, `models.json`, extensions, `AGENTS.md` |
| **Auth model** | Kerberos, LDAP, X.509, OTP, RBAC | one shared bearer key (or none, loopback-only) | provider keys/OAuth, `auth.json`, `!command` |
| **Extensibility** | Python plugins, 389-ds plugins, ACIs | kernel/architecture/quantiser plugins, C ABI | TypeScript extensions, skills, packages, MCP, providers |
| **Ops burden** | High (DNS/Kerberos/CA/replication) | Medium (GPU drivers, VRAM, TLS proxy) | Low |
| **Upgrade risk** | High (ACIs/permissions rewrite in 4.13.4) | Medium-high (fast minors) | Low-medium (1.0 churn) |
| **Docs quality** | Reference-grade, distro docs authoritative | Very high (spec, GUIDE, TOOLS, PLUGIN) | Very high, task-oriented |
| **Best role here** | Host/user identity, certs, DNS, policy | Model serving on AMD | The agent users actually run |

---

## 8. Licensing and compliance

### 8.1 Component licenses

| Component | License | Obligations / notes |
|---|---|---|
| FreeIPA | **GPL-3.0-or-later** (`COPYING`, plus `COPYING.openssl` exception) | Distribution of binaries/source derivatives triggers GPL; source availability; no relicensing |
| radiance | **Apache-2.0** (`LICENSE`, `NOTICE`) | Keep NOTICE; state changes; patent grant; compatible with GPLv3 (one-way) |
| Pi | **MIT** | Attribution + license text; compatible with GPLv3 |
| This repo | GPLv3 text at root (version 3, 29 June 2007) | Ambiguous "only vs or-later"; no per-file notices yet |

Apache-2.0 and MIT are compatible with GPLv3, so a GPLv3 umbrella project can include or invoke all three. But the umbrella license **cannot relicense** the permissively licensed components; keep their notices, and be explicit about what the root license covers (your code) versus bundled dependencies.

If the project's own code is meant to be permissive, the current root GPLv3 text is a decision that should be revisited now, before code lands. If it is meant to be copyleft, say so in `README.md` and add SPDX headers.

### 8.2 Model weights are separately licensed

radiance's own README warns: *"The model weights are not covered: each keeps the license of the model it was converted from."* Concrete examples called out in the README:

| Model family | License note |
|---|---|
| Qwen-Image 2.1 | Qwen research license — **non-commercial** |
| MiniMax-H3 / FastH3 | License **does not cover the EU, UK, Republic of Korea, or USA** |
| Breeze-TTS-2 | Research / non-commercial only |
| Fish Audio drama-3 | Fish Audio Community License; hosted generation for others needs a Fish Audio licence; voice imitation needs consent |
| Gemma, Qwen and other upstream families | Each upstream license + acceptable-use terms |

A model-license inventory is a **pre-launch gate** if the service is offered to others, even internally across legal entities.

### 8.3 Contribution policy

Codeberg's Terms of Use, as displayed at the time of research, restrict **LLM-generated content** (banner links to a Terms diff and a blog post). Both upstreams are on Codeberg. If the plan includes contributing patches upstream, read the current policy before sending AI-assisted changes; keep commits attributable and follow each project's DCO/commit-template rules (`freeipa` has a `.git-commit-template` and `CONTRIBUTING.md`).

### 8.4 Trademarks and naming

"FreeIPA" is a Red Hat project name; "Pi" and "Radius" are Earendil names. Avoid implying endorsement in the README/product name.

---

## 9. Risks and open questions

| # | Risk / question | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | **GPU mismatch.** radiance's kernels target RDNA4; the team's hardware may be another AMD family, NVIDIA, or none. | High | High | Confirm hardware first; use `--no-hip` host backend for functional work; budget for kernel-library work or different hardware |
| R2 | **radiance API/behaviour churn.** 1.x, frequent minors, single maintainer. | High | Medium | Pin a version + container digest; keep integration behind `models.json`; track release notes before upgrades |
| R3 | **Tool-calling reliability** varies by chat template/quantisation. | Medium | High | Test tool round-trips per container; prefer containers with verified templates; keep a fallback model |
| R4 | **Auth gap** (one shared key, no per-user identity). | Certain | Medium | Gateway (Keycloak/oauth2-proxy) + TLS proxy; rotate keys via `ipa vault` |
| R5 | **FreeIPA operational weight** and upgrade risk (ACI/permission rewrites). | Medium | High | Pin ≥4.13.4; stage upgrades; snapshot/backup; rehearse on a replica |
| R6 | **Pi 1.0 churn** and experimental harness adapters. | Medium | Medium | Pin the npm version; avoid depending on experimental adapters in production; wrap Pi behind print/JSON/RPC modes rather than internal APIs |
| R7 | **Prompt-injection → shell** via Pi tools. | Medium | High | Run Pi in a container/sandbox as a low-privilege IPA user; HBAC restrict hosts; no long-lived cloud creds in the environment |
| R8 | **Model license violations** (non-commercial, territory exclusions). | Medium | High | Inventory licenses per container; block restricted models at the gateway or by omitting them from `models.json` |
| R9 | **Secrets on disk** (`auth.json`, `.env`, `models.json` with literal keys). | Medium | High | `$ENV`/`!command` resolution; file modes; vault; avoid literals; document rotation |
| R10 | **Supply chain** (HF containers, quantised third-party weights, vendored libraries). | Medium | Medium | Prefer official/known uploaders; verify hashes; radiance's `vendor/SHA256SUMS` + `hfget.sh` hashing; pin Pi installer rather than loose npm |
| R11 | **Licensing ambiguity of the umbrella repo.** | Certain | Low-medium | Decide now; add SPDX headers; update README |
| R12 | **Codeberg LLM-content policy** if upstreaming. | Medium | Low | Read policy; human-review/attribute contributions; keep patches minimal |

### Open questions to answer before building

1. **Hardware**: which GPU family and how much VRAM? If not RDNA4, is CPU-only acceptable for phase 1?
2. **Scale**: single developer, small team, or multi-tenant service? This decides whether the gateway is optional.
3. **Identity**: is a FreeIPA realm already deployed? Is Keycloak present? Who owns DNS?
4. **Models**: which containers, and do their licenses permit the intended use?
5. **Contribution**: is the goal to build a product, contribute upstream, or both? (Policy + DCO implications.)
6. **Isolation**: are Pi's tools allowed to run directly on developer machines, or must everything be containerised?

---

## 10. Suggested next steps

Each experiment has an explicit pass condition so it can be closed.

| # | Experiment | Pass condition |
|---|---|---|
| E1 | **Build radiance host-only** (`./build.sh --no-hip`), serve a small container (e.g. MiniCPM5-2B), run the non-GPU test suite | Server answers `/health`, `/v1/models`, and a chat completion; test suite green |
| E2 | **Verify tool calling** on the target container with a scripted two-tool conversation | Model emits a valid tool call, accepts the result, and finishes; no refusals from the template analyser |
| E3 | **Wire Pi to radiance** via `models.json` (snippet in §6.2) and run a real repo task | Pi completes a read/edit/test loop using only the radiance model; usage appears in the footer |
| E4 | **Measure the operating point**: tokens/s, TTFT, context limit, VRAM headroom under 1/2/4 concurrent Pi sessions | Numbers recorded in this repo; a documented max-concurrency recommendation |
| E5 | **FreeIPA test realm** (`ipa.test`), enroll a host, create a service user, add HBAC + sudo rules, issue a TLS cert with `ipa-getcert` | Host enrolled; `kinit` works; HBAC denies/allows as configured; cert auto-renews |
| E6 | **Gateway spike**: Keycloak federated with FreeIPA + `oauth2-proxy` in front of radiance | A Pi request authenticated by an IPA-backed OIDC token reaches radiance; unauthenticated request gets 401 |
| E7 | **Licence inventory** of chosen containers + a one-page policy | Every container has a recorded license and an allowed-use decision |

Sequencing: **E1 → E2 → E3** proves the core value with no identity work. **E5/E6** are parallel and independent. **E4/E7** gate any shared or external use.

---

## 11. Fact provenance

| Claim | Source |
|---|---|
| FreeIPA components, multi-master LDAP, XML-RPC/JSON-RPC, Python SDK | freeipa.org home, `/page/About` |
| FreeIPA release dates, 4.13.4 CVEs | `/release-notes/4-13-4.html`, Codeberg tags |
| FreeIPA repo size, languages, commit/tag counts | Codeberg repo page |
| FreeIPA build/test/API.txt workflow | `BUILD.txt`, repo tree |
| FreeIPA platform + RAM + DNS requirements | `/page/Quick_Start_Guide` |
| radiance architecture, plugins, spec scope | `spec.md`, README |
| radiance APIs, flags, auth, build, Docker, tests | README, `spec.md` §14 |
| radiance version/date | commit `203064b4` ("radiance 1.15.1"), tags |
| Pi install, quickstart, sessions, tools | pi.dev quickstart, `/docs/latest/cli`, `/docs/latest/how-pi-works` |
| Pi `models.json` schema and defaults | `/docs/latest/models-configuration` |
| Pi config layout, trust, security | `/docs/latest/configuration`, `/docs/latest/how-pi-works` (trust and permissions), `/docs/latest` ("Work safely") |
| Pi provider list, local models | `/docs/latest/providers`, `/docs/latest/llama-cpp` |
| "Pi harness" adapter | ai-sdk.dev `/providers/ai-sdk-harnesses/pi` |
| Model license caveats | radiance README (License, model table notes) |

---

## 12. Verification status

**Verified by reading primary sources** (docs/repos, fetched 2026-10-31): all version numbers, dates, commands, configuration field names, license identifiers, API endpoint lists, and architecture descriptions above.

**Not verified by execution** (no clone/build/run was performed):

- That radiance builds on this machine (no AMD GPU assumed; ROCm not checked).
- That the sample `models.json` produces a working Pi session — the field names and semantics are from the reference, but the combination is untested. Treat §6.2 as a starting point and expect one or two compat flags to be needed.
- Tool-calling behaviour of any specific container.
- That FreeIPA installs cleanly on the target OS, and that `ipa-getcert`/HBAC commands match the target version's syntax (they are standard but version-sensitive).
- Gateway integration (Keycloak + FreeIPA + `oauth2-proxy`) — entirely design-stage.

**Time-sensitive**: FreeIPA and radiance both move quickly; re-check versions and release notes before implementing. Model tables and prices on Pi's side also change.

---

## 13. Sources

**FreeIPA**

- Repository: <https://codeberg.org/freeipa/freeipa>
- `BUILD.txt`: <https://codeberg.org/freeipa/freeipa/raw/branch/master/BUILD.txt>
- Tags/releases: <https://codeberg.org/freeipa/freeipa/tags>
- Home: <https://www.freeipa.org/>
- About: <https://www.freeipa.org/page/About.html>
- Documentation index: <https://www.freeipa.org/page/Documentation.html>
- Quick Start Guide: <https://www.freeipa.org/page/Quick_Start_Guide>
- Release notes 4.13.4: <https://www.freeipa.org/release-notes/4-13-4.html>

**radiance**

- Repository: <https://codeberg.org/StillDeadcode/radiance>
- README (raw): <https://codeberg.org/StillDeadcode/radiance/raw/branch/main/README.md>
- Design spec: <https://codeberg.org/StillDeadcode/radiance/raw/branch/main/spec.md>
- Docker image: <https://hub.docker.com/r/stilldeadcode/radiance>

**Pi**

- Docs home: <https://pi.dev/docs/latest>
- Quickstart: <https://pi.dev/docs/latest/quickstart>
- How Pi works: <https://pi.dev/docs/latest/how-pi-works>
- CLI: <https://pi.dev/docs/latest/cli>
- Models: <https://pi.dev/docs/latest/models>
- Models configuration: <https://pi.dev/docs/latest/models-configuration>
- Configuration: <https://pi.dev/docs/latest/configuration>
- Providers: <https://pi.dev/docs/latest/providers>
- Local models (llama.cpp): <https://pi.dev/docs/latest/llama-cpp>
- Custom providers: <https://pi.dev/docs/latest/custom-provider>
- Package: <https://www.npmjs.com/package/@earendil-works/pi-coding-agent>
- AI SDK harness adapter: <https://ai-sdk.dev/providers/ai-sdk-harnesses/pi>

**Context**

- Pi 1.0 announcement: <https://earendil.com/posts/pi-1-0/>
- Radius (disambiguation): <https://radius.earendil.com/>

**Implementation addendum sources**

- FreeIPA containers: <https://github.com/freeipa/freeipa-container> (README: systemd, `/data`, `ipa-server-install-options`, cgroup caveats)
- FreeIPA web-app auth: <https://www.freeipa.org/page/Web_App_Authentication>; group authz draft: <https://www.freeipa.org/page/Apache_Group_Based_Authorization>
- Apache LDAP authz: <https://httpd.apache.org/docs/2.4/mod/mod_authnz_ldap.html>
- `mod_auth_gssapi`: <https://github.com/gssapi/mod_auth_gssapi> (README: `GssapiLocalName`, `GSS_NAME`, `GssapiPublishMech`, `GssapiSSLonly`, `GssapiUseSessions`)
- MIT `kinit`: <https://web.mit.edu/kerberos/krb5-1.21/doc/user/user_commands/kinit.html>
- radiance server/auth docs: `docs/GUIDE.md` §4.4, §4.4.1, §6.6; `docs/TOOLS.md`; `deploy/compose/common.yaml`, `deploy/compose/qwen3.8-27b-mxfp4.yaml`, `.env.example`
- Pi source: `packages/coding-agent/src/core/resolve-config-value.ts`, `provider-composer.ts`; `packages/ai/src/api/openai-completions.ts` (uncached header commands, Bearer construction)

---

## 14. Addendum: verified implementation details (2026-10-31)

This addendum records facts checked *after* the main report, by reading the upstream container docs, the radiance guide and compose files, FreeIPA CLI sources, Apache/mod_auth_gssapi docs, and Pi's source. It supersedes the corresponding generalizations above and feeds [PLAN.md](PLAN.md).

### 14.1 radiance

| Topic | Verified detail |
|---|---|
| API key | `--api-key KEY` **or `--api-key-env NAME`**; the latter reads the key from the environment and refuses startup if unset/empty. The shipped compose files use `--api-key-env RADIANCE_API_KEY`. |
| Exemptions | `/health`, `/v1/health`, `/ping`, and the dashboard page are exempt from the key; everything else, including `/tokenize` and `/server_info`, requires it. |
| No TLS | The guide is explicit: *"There is no TLS, and without `--api-key` there is no authentication."* A TLS-terminating proxy is the documented deployment pattern. |
| CORS | CORS is on by default; `--no-cors` turns it off. |
| Bind | `--host ADDR` (default `0.0.0.0`); `--host 127.0.0.1` is the documented proxy pattern. |
| Model name | `--served-model-name NAME` sets the id `/v1/models` lists and responses use. |
| Vision | `--mm-max-patches 0` serves text only and keeps the vision tower off the card. |
| Seccomp / user | Docker's default seccomp blocks `io_uring` and NUMA calls; upstream ships `seccomp-radiance.json`. Compose runs as `user: RADIANCE_UID:RADIANCE_GID`, `init: true`, `ulimits.memlock: -1`, and host networking. |
| Streaming KV | `--kv-resident` **does not support** Qwen3.5/3.6/3.8 dense (`qwen35_*`); it is ignored with a warning. It applies to Flash-Next (`qwen4exp_fp8`) and GLM-5.3-Flash (`glm5next`). |
| Narrow KV caches | `fp8_v4` (K E4M3, V int4) and `k6_v4` (K int6) are supported for Qwen3.8-27B attention (head_dim 256, gqa 6), adding 28% and 46% pool versus `fp8` in the published measurement. |
| Measured pool | Two R9700s, MXFP4, `--tp 2`, 12 GiB/card reserved: `fp8` 518,800 tokens; `fp8_v4` 664,400; `k6_v4` 755,184. One card must be measured. |
| Prefill | `--attn-prefill-fp8 qk`, `pv`, or `both` is lossy and speeds 200K-token prefill (~15–20% with `both`); it does **not** add KV capacity. |
| State | `--state-cache-dtype f16` halves hybrid recurrent state (lossy) for `qwen35` plugins. |
| Route risk | LoRA load/unload, `/admin/control-vector`, `/diagnostics`, and media routes sit behind the same API key; an authenticating proxy must expose an explicit allowlist, not all of `/v1`. |

### 14.2 FreeIPA

- The server container **runs systemd** and is explicitly **not** privileged; rootless/cgroup setups may need `cgroupns: host`, `/sys/fs/cgroup` mounted rw, and the SELinux boolean `container_manage_cgroup`.
- It stores all state in the volume mounted at `/data` and, on first start, runs `ipa-server-install` using arguments from `IPA_SERVER_INSTALL_OPTS` or the file `/data/ipa-server-install-options`. That file can carry `--admin-password`/`--ds-password`, keeping secrets out of the image environment.
- `PASSWORD` sets both Directory Manager and admin passwords; the options file is the more controllable path.
- Integrated DNS is optional; unattended installs default to no DNS. Explicit `krb5.conf` KDC entries plus Compose aliases avoid BIND/Docker DNS conflicts.
- Container-level setup is fiddly enough that upstream recommends debugging plain `podman`/`docker` before Compose. Bootstrap from the host with `docker compose exec` avoids CA-trust and admin-secret containers.

CLI details verified in source:

| Command | Verified options / behavior |
|---|---|
| `ipa cert-request` | `--principal`, `--add`, `--chain`; CSR positional; used for `HTTP/radiance.ipa.test` |
| `ipa cert-show` | `SERIAL --out FILE --chain` |
| `ipa-getkeytab` | `-s`, `-p`, `-k`, `-e`, `-r` (retrieve current keys); default generates a **new** key (new kvno) |
| `ipa sysaccount-add` | `--password` or `--random`; system account DN is `cn=sysaccounts,cn=etc`, not `cn=users` |
| `ipa krbtpolicy-mod` | `--maxlife`, `--maxrenew` (realm or per-user) |
| `kinit` | No `--password-file` in MIT krb5; pipe the password on stdin. `-F` requests non-forwardable, `-l`/`-r` lifetime/renewal. |

### 14.3 Apache / Kerberos

- `mod_auth_gssapi` directives verified: `GssapiCredStore keytab:…`, `GssapiAcceptorName HTTP@host`, `GssapiSSLonly On`, `GssapiUseSessions Off` (default), `GssapiBasicAuth Off`, `GssapiLocalName On`, `GssapiPublishMech On`.
- With `GssapiLocalName On`, `REMOTE_USER` is the mapped uid and **`GSS_NAME` is the full client principal**; `GssapiPublishMech` exposes `GSS_MECH` (e.g. `Negotiate/krb5`). Both are useful for authorization logs and negative tests.
- `Require ldap-group` combined with `AuthType GSSAPI` works when `GssapiLocalName On` maps the principal to the LDAP `uid` attribute (`AuthLDAPURL …?uid…`) and `AuthLDAPGroupAttribute member` is set; a known-working configuration and upstream discussion confirm the pattern.
- `AuthLDAPGroupAttributeIsDN` defaults to **on**, which matches FreeIPA's DN-valued `member` attribute.
- `mod_authnz_ldap` caches authn/authz results; `LDAPCacheTTL` bounds how long a removed group member remains authorized.
- Radiance's engine is plain HTTP on loopback; the edge must terminate TLS 1.3, pin the IPA CA for LDAPS, and keep the keytab at 0400 on tmpfs.

### 14.4 Pi

- `models.json` values support literal, `$ENV`, `${ENV}`, and `!command`. Source shows two resolution paths: `resolveConfigValue` (process-lifetime cache, used for `auth.json`) and `resolveConfigValueUncached` (used for provider/model configuration, including headers and `apiKey`). **Model config commands run per request.**
- Provider `headers` are resolved like `apiKey`, but Pi's OpenAI-completions client passes `apiKey` into the OpenAI SDK, which emits `Authorization: Bearer …`. A custom `Authorization` header from `models.json` can therefore be overwritten. A local loopback shim that translates a Pi bearer token into Negotiate is the robust path; a direct-header mode is an experiment.
- `authHeader` defaults to `false`; with a configured `apiKey` and `authHeader: false`, Pi's composer does not add Bearer itself, but the API client still receives the key. Test before relying on header-only auth.
- For a custom provider, `models.json` needs `baseUrl` and `api`; `apiKey` commands make the provider count as configured without executing at startup.

### 14.5 What this means for the plan

The plan in [PLAN.md](PLAN.md) reflects these corrections: edge enforcement with an endpoint allowlist, host-side IPA bootstrap via `docker compose exec`, shim-first Pi integration, `--api-key-env`/`--no-cors`/`--served-model-name`/`--mm-max-patches 0`, and a measured 200k capacity gate with `fp8_v4`/`k6_v4` rather than streaming KV.

