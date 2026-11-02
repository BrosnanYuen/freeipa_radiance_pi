SHELL := /bin/bash
ENV_FILE ?= $(if $(wildcard .env),.env,.env.example)
COMPOSE := docker compose --env-file $(ENV_FILE)
PYTHON ?= python3

.PHONY: help unit config lint gateway-check edge-check test-fast test-sec test-slow test-rotation \
	up up-gpu smoke host-pi down test-host reset env license-check backup-ipa clean

help:
	@echo "make unit        - fast unit tests (no Docker)"
	@echo "make config      - validate compose.yaml against .env.example"
	@echo "make lint        - Python compile + shell syntax checks"
	@echo "make gateway-check - build the gateway image and run its module check"
	@echo "make env         - create .env with this host's UID/GIDs"
	@echo "make license-check - enforce a licence decision for every .rad container"
	@echo "make up          - bring up IPA + gateway + mock radiance + shim"
	@echo "make up-gpu      - bring up IPA + gateway + real radiance, then smoke-test it"
	@echo "make smoke       - assert the running engine lists and serves the model"
	@echo "make host-pi     - run a 10-turn Pi session from the host through a loopback shim"
	@echo "make test-fast   - run integration + security tests against the stack (mock profile)"
	@echo "make test-slow   - T4b revocation and T10 expiry (~4 min)"
	@echo "make test-rotation - destructive credential/certificate rotation checks"
	@echo "make test-host   - host-side container/mount/secret inspections"
	@echo "make reset       - delete run/ipa-data after an explicit confirmation"
	@echo "make backup-ipa  - back up the realm to run/backups (online data backup)"
	@echo "make down        - stop the stack"

unit:
	$(PYTHON) -m pytest -q tests/unit

config:
	$(COMPOSE) config -q
	@echo "compose config OK"

lint:
	$(PYTHON) -m compileall -q deploy scripts tests
	@find scripts deploy -name '*.sh' -print0 | xargs -0 -r -n1 bash -n
	@echo "lint OK"

gateway-check:
	set -a; . ./$(ENV_FILE); set +a; \
	docker build --build-arg GATEWAY_BASE_IMAGE="$$GATEWAY_BASE_IMAGE" -t radiance-gateway:check deploy/gateway && \
	docker run --rm radiance-gateway:check --check

edge-check: gateway-check

test-fast:
	$(COMPOSE) --profile test run --rm test-runner pytest -q integration security

test-sec:
	$(COMPOSE) --profile test run --rm test-runner pytest -q security

test-host:
	$(PYTHON) -m pytest -q tests/host

test-slow:
	RUN_SLOW=1 $(PYTHON) -m pytest -q tests/host/test_advanced.py

test-rotation:
	RUN_DESTRUCTIVE=1 $(PYTHON) -m pytest -q tests/host/test_rotation.py

env:
	$(PYTHON) scripts/render_env.py --source .env.example --out .env

backup-ipa:
	./scripts/backup-ipa.sh

license-check:
	set -a; . ./$(ENV_FILE); set +a; \
	$(PYTHON) scripts/check_model_licenses.py --models-dir "$${RADIANCE_MODELS:-/srv/models/rad}"

smoke:
	./scripts/smoke-engine.sh --mock

host-pi:
	./scripts/host-pi-smoke.sh --turns 10

reset:
	./scripts/reset.sh

up:
	./scripts/up.sh

up-gpu:
	./scripts/up.sh --gpu
	./scripts/smoke-engine.sh --gpu

down:
	./scripts/down.sh

clean:
	rm -rf run secrets work .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
