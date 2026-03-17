# Stage0 Execution Guard Skill

Stage0 Execution Guard Skill is a fail-closed execution gate for AI agents. Before an agent performs real work, it submits an execution intent to Stage0 and receives an authorization verdict. If the verdict is not `ALLOW`, execution must stop.

This package is meant to enforce the execution boundary in code. Prompts can influence model behavior, but they cannot reliably prevent execution.

## Verdict Model

Stage0 returns one of three verdicts:

- `ALLOW`: execution may proceed
- `DENY`: execution is blocked
- `DEFER`: execution is blocked until clarifying questions are answered

The package also supports local enforcement rules on top of the API response:

- `risk_threshold`: auto-deny if `risk_score >= threshold`
- `deny_on_issues`: auto-deny if any issues are present
- `deny_on_high_severity`: auto-deny if any HIGH severity issue is present

## Installation

This package is not currently published on PyPI. Do not use `pip install stage0-execution-guard`.

### From Git Tag (Recommended)

Pin to a specific version for reproducible builds:

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

**Do not install from `main` branch directly in production.** Always pin to a tag or commit hash.

## Setup

1. Visit `https://signalpulse.org`
2. Create an account and obtain an API key
3. Configure the package with one of these options

### Option A: `.env` file

```bash
STAGE0_API_KEY=your-api-key-here
```

If `python-dotenv` is installed, the package auto-loads `.env` on import.

### Option B: environment variable

```bash
export STAGE0_API_KEY=your-api-key-here
```

### Option C: direct configuration

```python
from stage0_execution_guard import ExecutionGuard, Stage0Client

client = Stage0Client(api_key="your-api-key-here")
guard = ExecutionGuard(client=client)
```

### Optional local runtime override

Production defaults to `https://api.signalpulse.org`. For local runtime development, point the client at a local Stage0 API:

```bash
STAGE0_API_BASE=http://127.0.0.1:8000
```

## Minimal Example

```python
from stage0_execution_guard import ExecutionIntent, must_allow

intent = ExecutionIntent(
    goal="Summarize a risky deployment request",
    success_criteria=["Return a safe recommendation"],
    constraints=["dry-run", "approval"],
    tools=["shell"],
    side_effects=["deploy"],
    pro=True,
)

must_allow(intent)

# If execution reaches here, Stage0 allowed it.
```

## Detailed Response Example

```python
from stage0_execution_guard import ExecutionGuard, ExecutionIntent

guard = ExecutionGuard(
    risk_threshold=50,
    deny_on_issues=False,
    deny_on_high_severity=True,
)

intent = ExecutionIntent(
    goal="Review an internal-tools permission change",
    success_criteria=["Confirm whether execution should proceed"],
    constraints=["approval", "require_mfa", "rollback_plan_required"],
    tools=["identity"],
    side_effects=["permission_change"],
    context={"run_id": "abc-123", "approval_status": "approved"},
    pro=True,
)

result = guard.check(intent)
print(result.allowed)
print(result.verdict)
print(result.risk_score)
print(result.high_risk)
print(result.issues)
print(result.clarifying_questions)
print(result.guardrail_checks)
```

## Usage API Example

```python
from stage0_execution_guard import Stage0Client

client = Stage0Client(api_key="your-api-key-here")
usage = client.get_usage()

print(usage.plan)
print(usage.monthly_remaining)
print(usage.daily_remaining)
print(usage.minute_remaining)
```

## Response Fields

The Stage0 `/check` response consumed by this package includes:

- `verdict`
- `risk_score`
- `high_risk`
- `issues`
- `clarifying_questions`
- `constraints_applied`
- `guardrail_checks`
- `request_id`

The Stage0 `/usage` response consumed by this package includes:

- `plan`
- `month_key`
- `monthly_used`
- `monthly_quota`
- `monthly_remaining`
- `day_key`
- `daily_used`
- `daily_quota`
- `daily_remaining`
- `per_minute_limit`
- `minute_used`
- `minute_remaining`
- `request_id`

The client tolerates additive fields in API responses and preserves the raw payload in `raw_response`.

## Operational Notes

- No API key configured: execution is blocked
- Invalid API key: execution is blocked
- Monthly quota exceeded: execution is blocked and surfaced as `QuotaExceededError`
- Stage0 unreachable: execution is blocked
- Unknown verdict: execution is blocked

This is intentional. The package is designed to fail closed.

## Project Links

- Homepage: `https://signalpulse.org`
- Docs: `https://signalpulse.org/docs`
- Default API base: `https://api.signalpulse.org`

Removing this guard removes the execution boundary. Treat it as mandatory infrastructure, not optional middleware.
