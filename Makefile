.PHONY: test validate lint install

install:
	pip install -e ".[ad,dev]"

# Fast unit + CLI suite (excludes the heavier validation harness).
test:
	pytest -q -m "not validation" tests

# Score-ranking validation harness (Task 8). Compiles a small corpus and reports
# where known-vulnerable services rank; set BT_VALIDATION_CORPUS to also run
# against a real service corpus (e.g. compiled FAUST binaries).
validate:
	pytest -m validation -v tests

lint:
	flake8 src tests || true
