all: fmt

.PHONY: fmt
fmt:
	uv run ruff format
	uv run ruff check --fix

.PHONY: test
test:
	uv run pytest

.PHONY: mypy
mypy:
	uv run mypy
