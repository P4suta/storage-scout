## What this changes

## Checklist

- [ ] `mise run check` and `mise run cross` are green.
- [ ] A new rule is a new `Gate` or `PairGate` variant, with a test that fails without it.
- [ ] A JSON change only adds fields, and `tests/schema/v2.json` is re-blessed.
- [ ] `mise run mutants:branch` leaves no survivor without a test or a claim in `.rust-mutants.toml`.
