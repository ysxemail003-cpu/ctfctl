PY ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
RUFF ?= .venv/bin/ruff
MYPY ?= .venv/bin/mypy
COVERAGE ?= .venv/bin/coverage

.PHONY: install dev test lint typecheck coverage build check bench doctor clean

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

doctor:
	./tools/ctfctl doctor

clean:
	rm -rf build dist src/*.egg-info .pytest_cache .coverage
