# Changelog

Notable changes to pynukez. Versions are single-sourced from
`pynukez/_version.py` and `pyproject.toml` (see CONTRIBUTING.md).

## 4.0.26 — 2026-10-22

- Security: require certifi >= 2026.10.19 (eMudhra/emSign compromised
  intermediate CAs). Users must also upgrade their installer: pip >= 26.2.2
  (`python -m pip install -U pip`), uv >= 0.13.4 (`uv self update`),
  pipx >= 1.18.4; older pip/uv trust the compromised chain even when the OS
  does not.
- CI: `actions/setup-python` uses `check-latest`, the publish job installs a
  hash-pinned pip 26.2.2 before any package install, and
  `pypa/gh-action-pypi-publish` is pinned to v1.14.3.
- Added `.github/dependabot.yml` (weekly pip and github-actions updates).
