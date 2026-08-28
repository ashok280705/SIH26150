# config/

Versioned **platform configuration data** (TOML), loaded at runtime. This directory holds
uniform, non-OEM engineering and policy values. Its sibling `profiles/` holds OEM-specific
knowledge. The split mirrors the design's separation of concerns:

| Directory | Holds | Example |
|---|---|---|
| `profiles/` | OEM-specific knowledge: signatures, offsets, structures, per-signature confidence weights | `profiles/cpplus/ubs-v1.toml` |
| `config/` | Uniform platform values applied identically across OEMs | `config/reader.toml` |

Rules for everything in this directory:

- **No value here is a validated forensic constant.** Values are provisional engineering
  configuration unless a decision note or validation record says otherwise (Req 10.7, 13.9).
- **No value here may also exist as a Rust source constant.** Source reads configuration;
  it does not restate it.
- Each file carries a `config_id`, a `config_version`, a `status`, and a link to the
  decision note that justifies its values.
- Each file states the allowed range for its tunable keys so the loader can reject
  out-of-range configuration instead of silently clamping.

## Contents

| File | Decision | Status |
|---|---|---|
| `reader.toml` | OPEN-2 — maximum read-window / bounded-buffer size (`docs/decisions/OPEN-2-max-read-window.md`) | Decided, provisional |

Classification policy (`ConfidenceConfig`: threshold, minimum margin, minimum evidence
quality) and recovery bounds (`RecoveryBounds`) belong in this directory as separate
versioned files. Their values are **OPEN-4** and are not decided here.

Note on layout: `design.md` → "Workspace Layout" predates this directory. It should be read
as extended by `docs/decisions/OPEN-2-max-read-window.md`, which records `config/` as the
home for versioned non-OEM configuration data.
