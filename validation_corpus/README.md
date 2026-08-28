# validation_corpus/

Deterministic validation corpus. Each case is a directory containing a manifest that states
the expected outcome, so regressions in detection, parsing, recovery, or reconstruction are
caught mechanically.

Manifest fields (design.md → Validation Corpus):

- `source_hash`, `source_type`
- `expected_detection`, `expected_detection_status`
- `expected_classification`, `expected_attribution_status`
- `expected_regions`
- `expected_parser_stage`, `expected_reconstruction_stage`
- `expected_validation_state`
- `expected_warnings`
- `provenance`

Rules:

- Corpus cases are deterministic: the same case plus the same profile and config versions
  always produces the same result.
- Real evidence is **never** committed. Fixtures are produced by the synthetic fixture
  generator and are explicitly labeled `synthetic`.
- A synthetic fixture is never described, reported, or used as real OEM forensic evidence. A
  random image containing a lone magic value must not pass OEM detection.

Empty at skeleton stage — corpus cases and the fixture generator land in later Phase 1 and
Phase 2 tasks.
