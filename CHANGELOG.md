# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.4] - 2026-03-17

### Added
- Usage API contract aligned with Stage0 runtime (`plan`, `monthly_remaining`, `daily_remaining`, `minute_remaining`)
- `raw_response` field preserved for debugging and forward compatibility
- CHANGELOG.md for version tracking
- GitHub issue templates (bug report, feature request, question)
- Version-pinned installation instructions in README

### Changed
- Client tolerates additive fields in API responses without breaking

## [1.2.1] - 2026-02-16

### Fixed
- Cloudflare 403 error by adding `User-Agent` header to all HTTP requests

## [1.2.0] - 2026-02-16

### Added
- `.env` file auto-loading support via `python-dotenv` (optional dependency)
- `[dotenv]` extra for users who want automatic environment loading

## [1.1.0] - 2026-02-16

### Added
- Pro plan handling with `pro=True` flag in `ExecutionIntent`
- Local enforcement rules: `risk_threshold`, `deny_on_issues`, `deny_on_high_severity`
- English README documentation

### Changed
- Improved error messages for quota exceeded and authorization failures

## [1.0.0] - 2026-02-16

### Added
- Initial release
- `ExecutionGuard` class for execution authorization
- `ExecutionIntent` dataclass for intent specification
- `must_allow()` convenience function
- `Stage0Client` for direct API interaction
- Support for `ALLOW`, `DENY`, `DEFER` verdicts
- Fail-closed behavior: execution blocked on missing/invalid API key, unreachable API, unknown verdict

---

## Installation

### From Git Tag (Recommended)

```bash
pip install "stage0-execution-guard @ git+https://github.com/Starlight143/stage0-execution-guard-skill.git@v1.2.4"
pip install "stage0-execution-guard[dotenv] @ git+https://github.com/Starlight143/stage0-execution-guard-skill.git@v1.2.4"
```

### From Local Clone

```bash
git clone https://github.com/Starlight143/stage0-execution-guard-skill.git
cd stage0-execution-guard-skill
pip install .
pip install ".[dotenv]"
```

---

## Known Limitations

- Not published on PyPI. Installation requires Git or local clone.
- Requires a valid Stage0 API key from [signalpulse.org](https://signalpulse.org).
- API rate limits apply based on your plan tier.

---

## Breaking Changes Policy

This project follows semantic versioning:

- **Major version (X.0.0)**: Breaking changes to public API
- **Minor version (0.X.0)**: New features, backward compatible
- **Patch version (0.0.X)**: Bug fixes, backward compatible

Breaking changes include:
- Removal of public functions, classes, or methods
- Changes to function signatures that require caller updates
- Changes to default behavior that affect existing integrations

Non-breaking additions (new optional parameters, new functions, new response fields) are allowed in minor versions.