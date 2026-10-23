## What this changes

## Checklist

- [ ] `mise run check` and `mise run cross` are green.
- [ ] A new rule is a new `Gate` or `PairGate` variant, with a test that fails without it.
- [ ] A JSON change only adds fields, and `tests/schema/v3.json` is re-blessed.
- [ ] `just check` passes on this candidate.
- [ ] Mutation or other heavy results describe their actual scope and source; release verification requires the complete catalog.
