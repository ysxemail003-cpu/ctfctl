# Prefer the local venv when present; otherwise fall back to PATH tools
# (GitHub Actions installs dev deps into the system interpreter).
PY ?= $(or $(wildcard .venv/bin/python),python3)
PYTEST ?= $(or $(wildcard .venv/bin/pytest),pytest)
RUFF ?= $(or $(wildcard .venv/bin/ruff),ruff)
MYPY ?= $(or $(wildcard .venv/bin/mypy),mypy)
COVERAGE ?= $(or $(wildcard .venv/bin/coverage),coverage)

.PHONY: install dev test lint typecheck coverage build check bench demo scan-secrets doctor clean

install:
	test -d .venv || python3 -m venv --system-site-packages .venv
	$(PY) -m pip install -e .

dev:
	test -d .venv || python3 -m venv --system-site-packages .venv
	$(PY) -m pip install -e ".[dev]"

test:
	if test -x $(PYTEST); then $(PYTEST); else python3 -m pytest; fi

lint:
	$(RUFF) check src tests

typecheck:
	$(MYPY) src/ctf_agent

coverage:
	$(COVERAGE) run -m pytest
	$(COVERAGE) report

build:
	$(PY) -m build

check: test lint typecheck coverage

bench:
	./tools/ctfctl bench

demo:
	examples/demo.sh

scan-secrets:
	tools/scan_secrets.sh

doctor:
	./tools/ctfctl doctor

clean:
	rm -rf build dist src/*.egg-info .pytest_cache .coverage
