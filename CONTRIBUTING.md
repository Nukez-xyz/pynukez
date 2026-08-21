# Contributing

## Setup

```bash
git clone https://github.com/Nukez-xyz/pynukez.git
cd pynukez
pip install -e ".[dev]"
```

The `[dev]` extra pulls testing and lint tooling (pytest, pytest-asyncio, pytest-mock, black, isort, mypy, python-dotenv). The runtime dependencies — httpx, pynacl, base58, eth-account — install with the base package.

## Tests

```bash
pytest
```

Async tests run automatically via `pytest-asyncio` (configured in `pyproject.toml`).

## Code Style

The target style is black/isort with a line length of 100 (both configured
in `pyproject.toml`), but the codebase has never been bulk-formatted and
`black --check` currently fails repo-wide, including on files untouched for
many releases. Until that changes, treat the formatters as advisory: match
the style of the file you are editing, do not reformat files you are not
otherwise changing, and never fold repo-wide reformatting into a feature or
release commit, because it buries the real diff. If enforcement is ever
adopted, it happens as a dedicated style-only commit plus a CI check, and
that is the owner's decision.

## Pull Requests

1. Fork the repo and create a feature branch
2. Make your changes — keep them small and focused
3. Add or update tests
4. Run `pytest`, `black`, `isort`, and `mypy` before pushing
5. Open a PR against `main` on https://github.com/Nukez-xyz/pynukez

## Release Process

Releases are tagged on `main` and published to PyPI by the
`.github/workflows/publish.yml` workflow (PyPI trusted publishing, no API
tokens required). The workflow runs when a GitHub Release is published, so
pushing the tag alone does not publish. The version has been single-sourced
since 4.0.22; the sequence is:

1. Bump `__version__` in `pynukez/_version.py` and `version` in
   `pyproject.toml`, keeping the two identical. `pynukez.__version__` and
   the HTTP User-Agent header derive from `_version.py` automatically — do
   not edit them by hand.
2. Run `pytest`; the full suite must pass.
3. Commit with explicit file paths — never `git add -A`. In particular,
   `tests/e2e_30_file_batch.py` is a local-only file containing live
   credentials, excluded via `.git/info/exclude`, and must never be
   committed.
4. Tag `vX.Y.Z`, push `main` and the tag, then create and publish the
   GitHub Release for the tag; publishing the Release is what triggers the
   PyPI upload.
5. Verify the distribution, not just the behavior: confirm the new version
   on PyPI's JSON API, then install it into a fresh venv and smoke-test the
   public surface (imports, new methods, dependencies resolving).

Never re-cut a changed SDK under an existing version number: pip caches and
installed venvs make same-version-different-bytes undetectable. If anything
changed after a version was published, the fix ships as a new version.
