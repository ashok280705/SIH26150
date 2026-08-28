# profiles/

Versioned `OEM_Profile` **data artifacts** (TOML), loaded at runtime. This directory — not
Rust source — is where every OEM signature, offset, structure layout, range, validation
rule, applicability scope, and confidence weight lives (Req 6.1, 11).

Rules the loader enforces (fail-closed):

- Every signature, offset, magic value, structure, range, and validation rule carries an
  `evidence_status` of `validated`, `provisional`, `model_specific`, `firmware_specific`, or
  `unvalidated`. A rule missing it is rejected with `ProfileInvalid`.
- Malformed, unparseable, or schema-invalid profiles are rejected outright — never partially
  loaded.
- `profile_version` and `profile_hash` are recorded into every result so a report can cite
  exactly which profile produced a claim.
- A non-`validated` rule may only be used within its stated applicability and can never
  alone establish `confirmed` attribution.

## Currently supported OEMs

| Directory | OEM / storage family | Notes |
|---|---|---|
| `dahua/` | Dahua | |
| `hikvision/` | Hikvision | |
| `honeywell/` | Honeywell | |
| `cpplus/` | CP Plus / UBS storage | Stays a **compatible candidate**; OEM exclusivity is not established |
| `uniview/` | Uniview | First-class supported OEM, full parity with the others (Req 25.1) |

Profile data for these five is authored by the Phase 2 profile tasks. Until then the
directories are empty by design.

## Future OEMs — present as directories only, NOT implemented

`tplink/`, `godrej/`, `matrix/`

These are placeholders for possible future work. They contain no profile data, are **not
implemented**, and must never be advertised or reported as supported. Each carries a
`NOT_IMPLEMENTED.md` marker stating so.
