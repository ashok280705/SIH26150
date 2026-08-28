# apps/frontend

Placeholder for the React + TypeScript frontend (Vite, Tailwind, shadcn/ui).

This directory is intentionally unscaffolded. The UI shell and navigation (Case, Evidence,
Acquisition, Detection, Parsing, Recovery, Timeline, Evidence/Provenance, Reports) plus the
Hex Viewer are built by the Phase 1/Phase 2 UI tasks. `P1-001` only establishes the layout.

Notes that govern this app when it is built:

- There is **no Node.js backend**. The frontend talks to `apps/api` (Rust/Axum) over
  HTTP/JSON only.
- All raw-byte access goes through the API's read-only `EvidenceReader` addressing
  (evidence id + offset + length). The frontend never opens arbitrary filesystem paths.
- `Capability_Stage` (implementation maturity) and `Validation_State` (per-operation result)
  are rendered as two separate axes, never merged. The UI never shows only "Supported".
