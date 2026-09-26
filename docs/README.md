# docs/

Project documentation and decision notes.

Expected contents as the project progresses:

- Open-item decision notes in `decisions/`: `OPEN-1` (E01/EWF dependency go/no-go), `OPEN-2`
  (maximum read-window default — see `decisions/OPEN-2-max-read-window.md`), `OPEN-3`
  (FFmpeg runtime dependency), `OPEN-4` (confidence and recovery-bound configuration values).
- The `Capability_Stage` matrix per OEM across the five dimensions (detection, profiling,
  parsing, reconstruction, validation), reported separately from `Validation_State`.
- Examiner-facing operating notes, including stated limitations: software read-only handles
  are not a hardware write blocker, and the platform supports forensic defensibility rather
  than guaranteeing legal admissibility.

OEM format notes:

- `uniview.md` — Uniview SUPER / UI / UI-DATA / DI / DATA layout, per-field confidence, FLOW,
  disktool `.h3crd` exports, and known limitations.

The authoritative spec lives in `.kiro/specs/dvr-nvr-forensic-platform/`
(`requirements.md`, `design.md`, `tasks.md`).
