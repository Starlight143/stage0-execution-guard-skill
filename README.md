# Stage0 Execution Guard Skill

## What This Skill Does

Stage0 Execution Guard Skill is an **execution gate**. Its sole purpose is to determine whether an AI agent is **permitted to continue execution** before any action is taken. This is a mandatory security mechanism, not an optional feature. Agents must pass this guard's check before proceeding. If the guard blocks execution, the agent cannot continue—regardless of how the agent's prompt is designed.

## Why Prompts Alone Cannot Stop Execution

Prompts are instructions, not constraints. LLMs can understand "do not do X" but cannot be forcibly compelled to comply. When a model hallucinates, is misled, or encounters edge cases, it may ignore or circumvent prompt-based limitations. More importantly, prompts cannot control the execution layer—they can only influence model output. If a model decides to execute a dangerous operation, prompts cannot physically prevent it. Only code can do that. This skill is a code-level mandatory gate.

## How This Execution Guard Blocks Execution

The guard operates on a **fail-closed** principle: deny by default, allow only with explicit authorization. When an agent prepares to execute, it must first submit an **execution intent** to the guard, containing: goal, planned tools, and potential side effects. The guard sends this information to the Stage0 API for authorization. Stage0 returns one of three verdicts:

- **ALLOW**: Execution is permitted. The guard returns success, and the agent proceeds.
- **DENY**: Execution is rejected. The guard raises an exception, and the agent cannot continue.
- **DEFER**: More information is required. The guard raises an exception with clarifying questions.

Key point: if the verdict is anything other than ALLOW, execution is blocked. There are no intermediate states, no "try anyway." If the API key is not set, invalid, or the Stage0 service is unavailable, execution is also blocked.

### Local Rules (Optional)

The guard can apply additional local rules on top of Stage0 decisions:

- **risk_threshold**: Auto-deny if `risk_score >= threshold` (default: 100, effectively disabled)
- **deny_on_issues**: Auto-deny when any issues are detected (default: False)
- **deny_on_high_severity**: Auto-deny when HIGH severity issues are found (default: True)

These rules provide extra protection layers, especially useful for free tier users who want additional risk-based blocking.

## Setup

1. Visit https://signalpulse.org to register an account
2. Obtain an API Key from the dashboard
3. Set the environment variable:

```bash
export STAGE0_API_KEY=your-api-key-here
```

Or configure directly in Python:

```python
from stage0_execution_guard import Stage0Client, ExecutionGuard

client = Stage0Client(api_key="your-api-key-here")
guard = ExecutionGuard(client=client)
```

## Minimal Integration Example

```python
from stage0_execution_guard import ExecutionIntent, must_allow

# Define execution intent
intent = ExecutionIntent(
    goal="Read and summarize the weekly sales report",
    tools=["filesystem", "llm"],
    side_effects=[],  # Read-only, no side effects
)

# Must pass check to continue
# If not allowed, this raises an exception and subsequent code won't execute
must_allow(intent)

# At this point, execution is authorized
result = read_and_summarize_report()
```

### Advanced Configuration

```python
from stage0_execution_guard import ExecutionGuard

# Create guard with local rules
guard = ExecutionGuard(
    risk_threshold=50,           # Auto-deny if risk_score >= 50
    deny_on_issues=False,        # Don't auto-deny on any issues
    deny_on_high_severity=True,  # Auto-deny on HIGH severity issues (default)
)

# Check with detailed result
result = guard.check(intent)
print(f"Allowed: {result.allowed}")
print(f"Risk Score: {result.risk_score}")
print(f"Issues: {result.issues}")
```

**Important**: This is an execution gate. If you remove it, your agent is unsafe.