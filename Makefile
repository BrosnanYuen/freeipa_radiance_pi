SHELL := /bin/bash
ENV_FILE ?= $(if $(wildcard .env),.env,.env.example)
COMPOSE := docker compose --env-file $(ENV_FILE)
PYTHON ?= python3

.PHONY: help unit config lint edge-check test-fast test-sec up up-gpu down test-host clean

help:
	@echo "make unit        - fast unit tests (no Docker)"
	@echo "make config      - validate compose.yaml against .env.example"
	@echo "make lint        - Python compile + shell syntax checks"
	@echo "make edge-check  - build the edge image and run apachectl -t on the rendered vhost"
	@echo "make up          - bring up IPA + edge + mock radiance + shim"
	@echo "make up-gpu      - bring up IPA + edge + real radiance (needs model + GPU)"
	@echo "make test-fast   - run integration + security tests against the stack (mock profile)"
	@echo "make test-host   - host-side container/mount/secret inspections"
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

edge-check:
	set -a; . ./$(ENV_FILE); set +a; \
	docker build --build-arg EDGE_BASE_IMAGE="$$EDGE_BASE_IMAGE" -t radiance-edge:check deploy/edge && \
	docker run --rm radiance-edge:check --check

test-fast:
	$(COMPOSE) --profile test run --rm test-runner pytest -q integration security

test-sec:
	$(COMPOSE) --profile test run --rm test-runner pytest -q security

test-host:
	$(PYTHON) -m pytest -q tests/host

up:
	./scripts/up.sh

up-gpu:
	./scripts/up.sh --gpu

down:
	./scripts/down.sh

clean:
	rm -rf run secrets work .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
