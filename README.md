# DVR/NVR Forensic Analysis Platform

A forensic toolchain for recovering and analysing surveillance video from seized DVR/NVR
disks. It detects the storage manufacturer, parses the vendor-specific on-disk format,
recovers recordings (including deleted/lost footage), normalizes timestamps across
cameras, and produces a documented, reproducible forensic report.

Evidence is treated as read-only, every derived artifact carries cryptographic
provenance, and results are deterministic: the same image + profile + config always
produces the same output.

## Pipeline

```
RAW IMAGE → OEM DETECTION → CONFIDENCE/ATTRIBUTION → VENDOR PARSER
          → RECOVERY (L1/L2/L3) → TIMESTAMP NORMALIZATION → TIMELINE → REPORT
```

- **Detection** — all vendor detectors run in parallel; profile-driven signature matching.
- **Confidence** — a decision tree assigns an attribution status (Confirmed …​ Unknown); no unearned PASS.
- **Parsing** — one adapter per OEM behind a common `Parser` trait; all OEM facts live in versioned TOML profiles, never in code.
- **Recovery** — bounded, multi-level: L1 indexed, L2 orphan/slack, L3 raw carving. Gaps are marked, never synthesized.
- **Timeline** — per-camera sessions with in-recording gaps, plus a unified cross-camera view (physical / recorder-native / normalized ordering).
- **Reporting** — JSON / CSV / Markdown, with chain of custody and stated limitations. Never claims legal admissibility.

## Repository layout

```
crates/                 pure, deterministic forensic core (no network/DB)
  forensic-core/        identifiers, hashing, provenance, validation, time model
  evidence-reader/      read-only, bounded evidence access
  detection/            OEM detection orchestrator + detectors
  confidence/           scoring + attribution decision tree
  parsers/<oem>/        per-OEM parsers (dahua, hikvision, honeywell, cpplus-ubs, uniview, tplink)
  parsing/              parsing orchestrator
  recovery/             recovery engine + video reconstructor (FFmpeg)
  timeline/             sessions, gaps, cross-camera correlation
  reporting/            report model + JSON/CSV/Markdown exporters
  pipeline/             end-to-end run orchestration
apps/
  api/                  Axum/Tokio REST API — the only crate touching network + DB
  frontend/             React 18 + TypeScript + Vite workstation UI
  ai-service/           optional Python/FastAPI analytics (operates on derived clips only)
profiles/               versioned OEM profile data (TOML)
tests/                  cross-crate tests + fixture generators
```

## OEM support

| OEM | Storage format | Status |
|:--|:--|:--|
| **Dahua** | DHFS 4.1 (partition table, block chains, DHII index, DHAV, packed timestamps) | Parser implemented |
| Hikvision / Honeywell / CP Plus (UBS) / Uniview | vendor profiles | In development |
| TP-Link VIGI | provisional profile | Research |

Detection uses signatures; codec identity never proves OEM identity. Unsupported or
ambiguous images resolve to a generic Annex-B carving fallback.

## Getting started

Prerequisites: Rust (1.82+), Node.js 18+, FFmpeg on `PATH`; Python 3.10+ for the optional AI service.

Backend API (run from repo root; SQLite migrations run on startup):
```bash
cargo run -p forensic-api        # http://127.0.0.1:3000
```

Frontend (separate terminal):
```bash
cd apps/frontend
npm install
npm run dev                      # http://localhost:5173  (proxies /api → :3000)
```

Optional — offline assistant (bundled Ollama) and AI analytics:
```bash
cd apps/frontend && npm run assistant:setup && npm run assistant:serve   # :11434
cd apps/ai-service && pip install -r requirements.txt && python main.py  # :8000
```

## Test fixtures

Sample DVR images are generated locally (they are git-ignored, never committed):
```bash
python3 generate_dahua_raw.py        # dahua_dhfs_sample.raw   (DHFS 4.1)
python3 generate_evidence_3day.py    # dvr_3day_sample.raw     (3 days × 2 cameras, real footage, lost+recoverable segments)
python3 generate_tplink_raw.py       # tplink_vigi_nvr_sample.raw
```
`generate_evidence_3day.py` can build from real clips dropped in `footage/` (or a Pexels
video id via `--pexels-ch1/--pexels-ch2`); otherwise it falls back to a synthetic pattern.

## Build & test

```bash
cargo build
cargo test
cd apps/frontend && npx tsc --noEmit && npm run build
```

## Principles

- **Read-only evidence** — no crate exposes a write path to evidence; write guards deny and log attempts.
- **OEM facts in data** — signatures, offsets, structures live in `profiles/`, never as source constants.
- **Provenance & custody** — SHA-256 over evidence and every artifact; append-only custody log.
- **Deterministic & defensible** — reproducible output; unrun checks are `UNKNOWN`, not `PASS`.

> This is an active development / research project. Fixtures are synthetic; agreement
> between the generators and parsers is a cross-check of documented structures, not
> evidence of compatibility with any specific firmware.
