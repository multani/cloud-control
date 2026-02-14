all: check


check: fmt typing test

.PHONY: fmt
fmt:
	uv run ruff format
	uv run ruff check --fix

.PHONY: test
test:
	uv run pytest

.PHONY: typing
typing:
	uv run ty check
