# D-01: No automatic extraction for the Max pilot

Status: **founder decision**, decided November 5, 2026 and recorded November 6, 2026.

## Decision

Founder decision: Automatic extraction is disabled for Max's initial EngramPort pilot.

No automatic extraction is authorized for the Max pilot.

## Founding principle

In the founder's words:

> "EngramPort should never confuse something an AI inferred with something the organization authorized as knowledge."

Institutional memory is written first through explicit, authorized actions, with
provenance, and with human approval where D-03 and D-04 require it.

## Implementation sequence

1. Secure legacy access through a PR and independent review.
2. Qualify memory governance and verify PR #65's server-side write protections.
3. Execute Max's synthetic pilot using explicit writes, retrieval, supersession, and erasure tests.
4. Reconsider automatic extraction only after demonstrating measurable precision, safety, and customer value.

## What this means for the code

- No extraction provider is chosen, and no extraction job, worker or schedule is
  run for the Max pilot. The extraction code (`src/store/extract.ts`) stays
  unused there.
- Graph rows are written only when an agent calls `link` explicitly, under the
  same never-store checks as every other write (D-07).
- Changing this needs a new, separately scoped proposal and a new founder decision.

This decision does not change D-02 through D-07, and it does not enable customer writes.
