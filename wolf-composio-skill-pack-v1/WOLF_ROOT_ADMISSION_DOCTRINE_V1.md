# WOLF ROOT ADMISSION DOCTRINE V1

## Rule-mãe

**ZERO COST × ZERO TOUCH × MÁXIMA EFICIÊNCIA**

This is a mandatory admission invariant for Project Wolf, not a preference.

## ZERO COST

- EUR spend must remain 0 for the admitted path.
- PAID_FALLBACK = DENY.
- TRIAL_CREDIT_DEPENDENCY = DENY.
- COST_UNKNOWN = DENY.
- PAYMENT_METHOD_REQUIRED = DENY for the admitted path.
- Premium credits, temporary grants, promotional credits, or expiring allowances must not be architectural dependencies.
- Any proposed tool or action with unknown or non-zero recurring cost is denied until a permanent-EUR0 proof exists.

## ZERO TOUCH

- Founder stays out of the hot path.
- No avoidable clicks, prompts, manual retries, `Continua`, terminal work, reauthentication, copy/paste of secrets, maintenance, or routine supervision.
- Human action is admitted only at a physically unavoidable authorization boundary or when explicitly requested by the Founder.
- Systems should reconcile durable state and continue autonomously where safe.

## MÁXIMA EFICIÊNCIA

- Prefer, in order: ADOPT OSS → CONFIGURE → THIN WRAPPER → HARVEST → BUILD LAST.
- Reuse admitted existing capabilities before adding components.
- Minimize components, tool calls, orchestration layers, state duplication, and operational steps.
- Efficiency must not weaken evidence, security, correctness, economic controls, independent verification, or authority boundaries.

## Admission rule

A proposed solution is WOLF-ADMITTED only when all three dimensions pass:

`ZERO_COST = PASS`

`ZERO_TOUCH = PASS`

`MAXIMUM_EFFICIENCY = PASS`

If any dimension fails, the solution is **DENY / NOT WOLF-ADMITTED** while an alternative exists that can satisfy all three.

## Tool and skill gate

Every tool, skill, provider, integration, runtime, workflow, and infrastructure proposal must pass this doctrine before execution.

For skills such as Superpowers:

`SKILL = ADMITTED` does not imply unrestricted tool authority.

Every proposed external action still passes:

`SKILL → PROPOSED ACTION → WOLF ROOT ADMISSION GATE → AUTHORITY GATE → EXECUTE`

If a proposed action is premium, paid, trial-dependent, cost-unknown, manually dependent, or unnecessarily complex:

`DENY → SUBSTITUTE WITH AN ADMITTED EUR0 / ZERO-TOUCH / LOWER-COMPLEXITY CAPABILITY`

## Authority

This doctrine does not grant merge, deployment, scheduler, queue, verification, NEXT_READY, checkpoint-promotion, economic, or infrastructure authority.

**WOLF DECIDES. COMPOSIO ACTS. WOLF VERIFIES.**

**BUILD WOLF, NOT INFRASTRUCTURE.**
