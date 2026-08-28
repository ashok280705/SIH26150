# Requirements Document

## Introduction

The Multi-Vendor DVR/NVR Forensic Analysis Platform (SIH 2026) is a forensic workstation
application for analyzing storage media (HDD images) recovered from digital and network
video recorders manufactured by multiple OEMs. The current supported target OEMs are
Dahua, Hikvision, Honeywell, CP Plus/UBS, and Uniview. Future/extensible vendors (not yet
implemented) include TP-Link, Godrej, Matrix, and additional OEMs.

The platform ingests read-only disk images, identifies which proprietary storage system is
present, parses the vendor-specific filesystem and recording structures, recovers deleted,
orphaned, corrupted, and carved video data, reconstructs playable video, builds a unified
cross-camera timeline, optionally applies AI analytics to validated evidence, and produces
forensically defensible reports with documented provenance, integrity, limitations, and
chain of custody. The Platform provides technical safeguards and forensic provenance; it
does not and cannot guarantee legal admissibility, which depends on jurisdiction,
acquisition procedure, examiner qualifications, and other external factors.

The system is governed by a set of non-negotiable forensic principles: evidence is handled
read-only and never modified; detection is explainable and never fabricated; detection and
parsing are separate concerns; recovery honestly distinguishes recoverable from unrecoverable
data; original timestamps are always preserved alongside normalized ones; all evidence and
exports are hashed and tracked through a complete chain of custody; and the architecture is
extensible so new OEMs can be added without rewriting the core. These principles apply across
every functional area and are captured both as cross-cutting requirements and reflected within
each functional requirement.

Development is phased: Phase 1 core (case/evidence/reader/hashing), Phase 2 detection,
Phase 3 parsers, Phase 4 recovery, Phase 5 timeline, Phase 6 reporting, Phase 7 AI analytics.
Requirements are tagged with their phase to support prioritization.

## Glossary

- **Platform**: The complete Multi-Vendor DVR/NVR Forensic Analysis Platform (all subsystems).
- **Case_Manager**: The subsystem that creates and manages forensic cases and their metadata.
- **Evidence_Reader**: The abstraction that provides read-only, streaming access to evidence images and physical disks.
- **Hashing_Service**: The subsystem that computes and records SHA-256 hashes of evidence and exports.
- **Detection_Orchestrator**: The subsystem that coordinates parallel execution of OEM detectors over a single read-only reader.
- **Detector**: An OEM-specific component that inspects storage structures and produces a Detector_Output. Detectors answer "what storage system is this".
- **Detector_Output**: The structured output of a Detector, containing the OEM candidate, storage family, Detection_Status, evidence list (Evidence_Items), candidate regions, warnings, and OEM_Profile version. A Detector_Output does NOT contain a final Attribution_Status, confidence, or Classification.
- **Classified_Detection_Result**: The Confidence_Engine's output for a Detector_Output, containing the Detector_Output plus the confidence, the Classification, the Attribution_Status, the top candidate, the second candidate, the margin, the evidence quality, and the validation state. The Confidence_Engine is the sole producer of Attribution_Status, Classification, and confidence.
- **Evidence_Item**: A single observation supporting a Detector_Output, containing type, offset, length, observed value, expected value, validation status, score contribution, and explanation.
- **Confidence_Engine**: The subsystem that scores and classifies Detector_Outputs using threshold, margin, and evidence quality, producing a Classified_Detection_Result.
- **OEM_Profile**: A versioned data artifact describing an OEM storage system: signatures, offset constraints, endianness, expected ranges, validation rules, confidence weights, and model/firmware applicability.
- **Parser**: An OEM-specific component implementing a common interface. The Parser owns filesystem/storage interpretation, metadata interpretation, recording/index interpretation, timestamp extraction, OEM-specific structural validation, OEM-specific candidate recognition, and OEM-specific recovery knowledge. The Parser answers "how to interpret these structures"; it does NOT own the recovery state machine (that is the Recovery_Engine) and does NOT make or override final OEM attribution.
- **Recording**: A stored video segment with a camera channel, timestamps, source location, and integrity status.
- **Recovery_Engine**: The subsystem that recovers deleted, orphaned, corrupted, and carved data across three levels.
- **Video_Reconstructor**: The subsystem that validates, orders, and reconstructs recovered frames into playable video.
- **Timeline_Engine**: The subsystem that builds the unified cross-camera timeline and correlates events.
- **AI_Analytics**: The optional downstream subsystem producing face, object, motion, and event findings from validated evidence.
- **Chain_Of_Custody**: The subsystem that logs significant actions and records provenance and hashes for exports.
- **Reporting_Service**: The subsystem that generates PDF, JSON, and CSV forensic reports.
- **UI**: The forensic workstation user interface.
- **Hex_Viewer**: The UI component that displays raw bytes and supports clickable evidence-to-offset inspection.
- **Examiner**: The forensic investigator operating the Platform.
- **Raw_Timestamp**: A timestamp exactly as stored in the source evidence, unmodified.
- **Normalized_Timestamp**: An investigative timestamp derived from a Raw_Timestamp (e.g., converted to UTC) that never replaces the Raw_Timestamp.
- **OEM_Exclusive_Evidence**: Evidence that can only be produced by one specific OEM storage system.
- **Provenance**: The recorded origin and processing lineage of an artifact (source image, offsets, parser/version, hashes).
- **Attribution_Status**: What the Platform is willing to claim about OEM identity, one of `confirmed`, `compatible_candidate`, `unsupported`, or `unknown`. Set by the Confidence_Engine; `confirmed` requires OEM_Exclusive_Evidence.
- **Classification**: The deterministic Confidence_Engine decision for a candidate, one of `confirmed`, `compatible_candidate`, `ambiguous`, `insufficient`, or `unknown`. (`candidate` is not a Classification value.)
- **Detection_Status**: The state of a single Detector's output, one of `confirmed`, `ambiguous`, `insufficient`, or `not_detected`. Distinct from Attribution_Status and Classification.
- **Evidence_Status**: The evidence basis of an OEM_Profile signature/rule, one of `validated`, `provisional`, `model_specific`, `firmware_specific`, or `unvalidated`.
- **Data_State**: What happened to an item's data on the medium, one of `active`, `deleted`, `orphaned`, `corrupted`, or `overwritten`. Independent of Recovery_Status.
- **Recovery_Status**: Whether an item's required content can still be reconstructed, one of `recoverable`, `partially_recoverable`, or `unrecoverable`. Independent of Data_State.
- **Forensic_Result**: The reproducible analytical output (detection result, confidence/classification, parser result, recovery result), excluding environment-dependent runtime metadata such as timestamps, database identifiers, temporary paths, and processing durations.
- **Capability_Stage**: The independently tracked *implementation maturity* of an OEM capability, one of `NOT_IMPLEMENTED`, `PARTIAL`, or `IMPLEMENTED`, tracked separately for each of the five dimensions Detection, Profiling, Parsing, Reconstruction, and Validation. Capability_Stage describes maturity, NOT a validation outcome, and is never advertised higher than actually implemented. (Distinct from Validation_State.)
- **Validation_State**: The *outcome* of a major forensic operation, one of `PASS`, `REVIEW`, `FAIL`, or `UNKNOWN`, always accompanied by an explanation. Validation_State describes an operation's result, NOT implementation maturity. (Distinct from Capability_Stage.)
- **Source_State**: The observed writability of an evidence source, one of `read_only`, `read_write`, or `unknown`.
- **Storage_Topology**: The partition/region structure of a source (e.g. MBR, GPT, partitions, unpartitioned/raw regions, filesystem signatures, candidate OEM regions). A partition is a candidate region only, not proof of an OEM.
- **Native_Artifact**: Bytes recovered/extracted directly from source evidence, as opposed to a derived artifact.
- **Derived_Artifact**: An artifact produced by transforming a native artifact (e.g. extracted elementary stream, remuxed video, decoded review copy, AI-derived output); it carries its own provenance and never replaces the native artifact.
- **Acquisition_Status**: The completeness state of an evidence acquisition, one of `complete`, `partial`, `failed`, or `unknown`.
- **Recorder_Native_Time**: A timestamp as recorded by the DVR/NVR device clock.
- **Reference_Time**: A corrected/reference time derived from Recorder_Native_Time via a documented correction (anchor, offset, drift, residual); it never overwrites the recorder-native or raw timestamp.
- **Uniview**: A supported target OEM (fifth), with research covering `disktool`, `super`/`super-data`, super-block validation, storage-region vocabulary (`super`, `ui-ctl`, `ui-data`, `di`, `flow`, `data`), `EcPortId`, timestamp metadata, `MP_MAIN_IDX_S`-style index, and timestamp-to-block mapping.

## Requirements

### Requirement 1: Read-Only Evidence Handling (Cross-Cutting, Phase 1)

**User Story:** As an Examiner, I want the Platform to guarantee original evidence is never modified, so that findings remain forensically sound and defensible with documented provenance, integrity, limitations, and chain of custody.

#### Acceptance Criteria

1. THE Platform SHALL open all evidence images and physical disks in read-only mode.
2. WHEN a physical disk is used as evidence, THE Evidence_Reader SHALL open the disk read-only and SHALL reject any write operation to the disk.
3. THE Platform SHALL store all derived artifacts and exports in a location separate from the original evidence.
4. IF any component requests a write operation against original evidence, THEN THE Evidence_Reader SHALL deny the operation and record the denied attempt in the Chain_Of_Custody.
5. THE Platform SHALL enforce application-level immutability for the configured evidence directory for the duration of a case and SHALL reject Platform-initiated writes to that directory; THE Platform SHALL NOT imply that it can prevent every privileged operating-system process from modifying the directory.
6. THE Evidence_Reader SHALL enforce read-only access primarily through read-only operating-system handles (Linux `O_RDONLY`; Windows `GENERIC_READ` with `FILE_SHARE_READ`; read-only memory mapping only; physical disks opened with read access and never a writable handle), and SHALL treat the application-level write guard as a secondary safeguard.
7. THE Platform SHALL NOT claim that software read-only access replaces a hardware write blocker, and SHALL document that hardware write blocking is outside the software's scope.
8. THE Platform SHALL determine and record the Source_State (`read_only`, `read_write`, or `unknown`) of each evidence source before analysis.
9. WHEN a physical block device is used as evidence, THE Platform SHALL inspect the source state before analysis and SHALL reject by default a mounted or write-enabled source.
10. IF a source is detected as write-enabled (`read_write`), THEN THE Platform SHALL produce a visible failure and SHALL NOT silently proceed with analysis.
11. THE Platform SHALL record the source safety decision and its reason in the Chain_Of_Custody.
12. WHERE the Source_State cannot be determined, THE Platform SHALL record it as `unknown` and SHALL NOT assert that the source is read-only.

### Requirement 2: Explainable and Non-Fabricated Detection (Cross-Cutting, Phase 2)

**User Story:** As an Examiner, I want every detection to be explainable and grounded in observed evidence, so that I can defend conclusions and avoid false attribution.

#### Acceptance Criteria

1. THE Platform SHALL support only OEM signatures and validation rules that are defined in an OEM_Profile.
2. THE Detector SHALL include, for every Detector_Output, an evidence list where each Evidence_Item records its offset, length, observed value, expected value, validation status, and explanation.
3. IF only a single magic value matches for an OEM, THEN THE Confidence_Engine SHALL classify the result as insufficient for confirmed identification.
4. WHERE OEM_Exclusive_Evidence is absent for CP Plus, THE Detection_Orchestrator SHALL report the result as "UBS storage / CP Plus-compatible candidate" rather than "CP Plus confirmed".
5. THE Detector SHALL NOT attribute an OEM using signatures or rules that are absent from any OEM_Profile.
6. THE Confidence_Engine SHALL set Attribution_Status to `confirmed` only WHERE OEM_Exclusive_Evidence is present; otherwise THE Platform SHALL use `compatible_candidate` or `unknown`, and THE Platform SHALL prefer `unknown` over an incorrect OEM attribution. THE Detector SHALL NOT set the final Attribution_Status.
7. THE Detector SHALL produce a Detection_Status of `confirmed`, `ambiguous`, `insufficient`, or `not_detected`; THE Confidence_Engine SHALL produce the Classification (`confirmed`, `compatible_candidate`, `ambiguous`, `insufficient`, or `unknown`) and the Attribution_Status (`confirmed`, `compatible_candidate`, `unsupported`, or `unknown`). THE Platform SHALL keep Detection_Status, Classification, and Attribution_Status as distinct concepts and SHALL NOT treat them as interchangeable.
8. THE Detector SHALL include, for every Evidence_Item, the source evidence identifier, offset, length, observed value, expected value, validation status, Evidence_Status, score contribution, and explanation.

### Requirement 3: Separation of Detection and Parsing (Cross-Cutting, Phase 2–3)

**User Story:** As a system architect, I want detection and parsing to be separate modules, so that each concern can evolve independently and remain testable.

#### Acceptance Criteria

1. THE Detector SHALL determine which storage system is present without interpreting recording content.
2. THE Parser SHALL interpret storage structures for a storage system identified by detection.
3. THE Platform SHALL expose detection and parsing as separate modules with distinct interfaces.
4. WHEN detection completes, THE Platform SHALL pass the identified storage family and OEM_Profile version to the Parser as input.
5. THE Platform SHALL make final OEM attribution through the Detection_Orchestrator and the Confidence_Engine (the Detector produces evidence and Detection_Status; the Confidence_Engine sets Classification and Attribution_Status); THE Parser SHALL NOT make or override the final OEM attribution decision.
6. THE Platform SHALL track capability maturity independently per OEM across the stages `detection_stage`, `profiling_stage`, `parsing_stage`, `reconstruction_stage`, and `validation_stage`, and SHALL NOT collapse them into a single "supported" boolean.
7. THE Platform SHALL set each Capability_Stage value from actually implemented capabilities and SHALL NOT advertise a stage higher than what is implemented.

### Requirement 4: Timestamp Preservation (Cross-Cutting, Phase 3+)

**User Story:** As an Examiner, I want raw and normalized timestamps preserved together, so that I can trust temporal evidence without losing the source values.

#### Acceptance Criteria

1. WHEN the Parser reads a timestamp from evidence, THE Parser SHALL retain the Raw_Timestamp exactly as stored.
2. WHEN a Normalized_Timestamp is produced, THE Parser SHALL store the Normalized_Timestamp alongside the Raw_Timestamp.
3. THE Platform SHALL retain the Raw_Timestamp for every artifact that carries a Normalized_Timestamp.
4. THE Platform SHALL record the normalization method used to derive each Normalized_Timestamp.
5. THE Platform SHALL keep Raw_Timestamp, Recorder_Native_Time, Normalized_Timestamp, and Reference_Time as separate evidence classes and SHALL NOT overwrite any one with another.
6. WHERE the source timezone is unknown, THE Platform SHALL record the timezone as `unknown` and SHALL NOT silently assume UTC.
7. WHERE clock correction is performed, THE Platform SHALL store the correction anchor evidence, the correction offset, the drift where applicable, and the residual/error, while preserving the original timestamp.

### Requirement 5: Hashing and Chain of Custody (Cross-Cutting, Phase 1 & 6)

**User Story:** As an Examiner, I want all evidence and exports hashed and every action logged, so that I can prove integrity and provenance.

#### Acceptance Criteria

1. WHEN evidence is added to a case, THE Hashing_Service SHALL compute a SHA-256 hash of the evidence and record it.
2. WHEN an export is produced, THE Hashing_Service SHALL compute a SHA-256 hash of the export and record it with the export Provenance.
3. WHEN a significant action is performed, THE Chain_Of_Custody SHALL log the action with a timestamp, the acting Examiner, and the affected artifact.
4. THE Chain_Of_Custody SHALL record source image and source offsets as part of the Provenance for every derived artifact.
5. THE Chain_Of_Custody SHALL retain all logged actions for the lifetime of the case.
6. WHEN a hash is computed, THE Hashing_Service SHALL record the algorithm, hash value, hash status, bytes hashed, and hashing duration.
7. THE Hashing_Service SHALL compute hashes using streaming reads and SHALL NOT require loading the complete image into memory.
8. THE Provenance SHALL include source hash, source region, producing component, component version, OEM_Profile version, parser version, recovery level, output hash, and transformation history.
9. THE Platform SHALL maintain separate provenance for Native_Artifacts and Derived_Artifacts, and SHALL NOT silently replace a native artifact with a derived copy.

### Requirement 6: Extensible OEM Architecture (Cross-Cutting, All Phases)

**User Story:** As a system architect, I want new OEMs added without rewriting the core, so that the Platform stays maintainable as coverage grows.

#### Acceptance Criteria

1. THE Platform SHALL load OEM_Profiles as versioned data artifacts separate from Detector and Parser source code.
2. WHERE a new OEM_Profile is added, THE Detection_Orchestrator SHALL include the new OEM in detection without changes to core orchestration logic.
3. THE Parser SHALL implement a common interface shared across all OEMs.
4. THE Detector SHALL implement a common interface shared across all OEMs.
5. THE Platform SHALL support model-specific, firmware-specific, and storage-variant OEM_Profiles, and SHALL NOT assume that one OEM maps to a single universal filesystem.
6. THE Platform SHALL select the applicable OEM_Profile based on the combination of OEM, model, firmware, and storage variant where such distinctions are established.

### Requirement 7: Case and Evidence Model (Phase 1)

**User Story:** As an Examiner, I want to create cases and register evidence with acquisition details, so that investigations are organized and documented.

#### Acceptance Criteria

1. WHEN an Examiner creates a case, THE Case_Manager SHALL create a case record with a unique identifier and the creating Examiner.
2. WHEN an Examiner adds an HDD image to a case, THE Case_Manager SHALL record the source device, acquisition time, capacity, and image format, and SHALL record the acquisition tool and acquisition tool version WHERE provided.
3. THE Case_Manager SHALL associate each piece of evidence with exactly one case.
4. IF any of the required acquisition fields — `source_device`, `acquisition_time`, `capacity`, `image_format` — is missing when adding evidence, THEN THE Case_Manager SHALL reject the addition and report which required field is missing. (Acquisition tool and acquisition tool version are optional per 7.6.)
5. THE Case_Manager SHALL record the Examiner responsible for each evidence item.
6. THE Case_Manager SHALL allow evidence registration to succeed WHERE the acquisition tool or acquisition tool version is genuinely unknown, treating those fields as optional.
7. WHERE acquisition information is available, THE Case_Manager SHALL record the Acquisition_Status, acquisition completeness, bad-sector information, unresolved ranges, an acquisition map/reference, and the acquisition verification status.
8. WHERE acquisition information is unavailable, THE Case_Manager SHALL mark it `unknown` and SHALL NOT fabricate completeness.
9. THE Case_Manager SHALL NOT label an incomplete acquisition as complete.

### Requirement 8: Evidence Reader Abstraction (Phase 1)

**User Story:** As an Examiner, I want to read large images and physical disks efficiently and safely, so that I can analyze multi-terabyte evidence without exhausting memory.

#### Acceptance Criteria

1. THE Evidence_Reader SHALL support reading `.raw`, `.dd`, and `.img` raw image formats.
2. WHEN reading an image, THE Evidence_Reader SHALL stream reads using bounded buffers rather than loading the entire image into memory.
3. WHERE an image exceeds available memory, THE Evidence_Reader SHALL read requested regions without allocating memory proportional to the total image size.
4. WHERE memory mapping is available for a source, THE Evidence_Reader SHALL support read-only memory-mapped reads for that source.
5. WHILE a long-running operation is in progress (sequential read, region scan, hashing, recovery scan, or other long-running bounded operation), THE Evidence_Reader SHALL report progress to the caller; a random-access `read_at` MAY complete immediately without progress reporting.
6. WHEN a caller requests cancellation of a long-running operation, THE Evidence_Reader SHALL stop the operation and report cancellation.
7. WHEN a physical disk is opened, THE Evidence_Reader SHALL open the disk read-only.
8. THE Evidence_Reader SHALL treat `.E01` (EWF) support as a planned integration; THE Platform SHALL NOT claim `.E01` support until an EWF/E01 dependency has been selected, license-verified, and tested for read-only, segmented, and compressed E01 handling, and SHALL NOT implement a custom E01 reader merely to satisfy this requirement.
9. THE Evidence_Reader SHALL support random-access reading, sequential streaming, and bounded region scanning over the same read-only source.
10. THE Evidence_Reader SHALL be sparse-image aware and SHALL preserve logical offsets, distinguishing sparse/unallocated logical regions from actual source truncation/end-of-source; it SHALL NOT silently treat sparse holes as truncation, and SHALL report actual truncation separately without crashing.
11. WHEN a requested read falls outside the source bounds, THE Evidence_Reader SHALL reject it as an out-of-bounds error.

### Requirement 9: Multi-OEM Parallel Detection (Phase 2)

**User Story:** As an Examiner, I want all OEM detectors run in parallel over the same read-only reader, so that identification is unbiased by execution order.

#### Acceptance Criteria

1. WHEN detection is requested, THE Detection_Orchestrator SHALL run the Dahua, Hikvision, Honeywell, CP Plus/UBS, and Uniview Detectors in parallel over the same read-only Evidence_Reader.
2. THE Detection_Orchestrator SHALL produce one Detector_Output per Detector.
3. THE Detector_Output SHALL include the OEM candidate, storage family, Detection_Status, evidence list, candidate regions, warnings, and OEM_Profile version; THE Detector_Output SHALL NOT include a final Attribution_Status, confidence score, or Classification.
4. THE Evidence_Item SHALL include type, offset, length, observed value, expected value, validation status, score contribution, and explanation.
5. THE Detection_Orchestrator SHALL NOT allow one Detector's result to change another Detector's independent evidence collection.
6. THE Confidence_Engine SHALL combine each Detector_Output into a Classified_Detection_Result that includes the Detector_Output, the confidence, the Classification, the Attribution_Status, the top candidate, the second candidate, the margin, the evidence quality, and the validation state; THE Confidence_Engine SHALL be the sole producer of the Attribution_Status, Classification, and confidence, and THE Detector SHALL NOT set any of them.

### Requirement 10: Confidence Scoring and Classification (Phase 2)

**User Story:** As an Examiner, I want confidence based on threshold, margin, and evidence quality, so that ambiguous results are flagged rather than forced into a single answer.

#### Acceptance Criteria

1. WHEN classifying a Detector_Output, THE Confidence_Engine SHALL evaluate the confidence threshold, the margin between the top candidates, and the evidence quality.
2. IF the margin between the two highest-scoring Detector_Outputs is below the configured margin, THEN THE Confidence_Engine SHALL flag the result as ambiguous and mark it for deeper validation.
3. THE Confidence_Engine SHALL NOT select an OEM based solely on the marginally-highest score when the margin is below the configured margin.
4. WHERE a Detector_Output meets the configured threshold, margin, and evidence-quality criteria AND OEM_Exclusive_Evidence is present, THE Confidence_Engine SHALL classify the result as `confirmed`; otherwise THE Confidence_Engine SHALL classify the result according to the `compatible_candidate`, `ambiguous`, `insufficient`, or `unknown` rules.
5. THE Confidence_Engine SHALL compute a deterministic weighted-evidence score per OEM, normalize it to a confidence in the range 0..1, and derive a classification that is distinct from the score and the confidence.
6. THE Confidence_Engine SHALL classify each result as one of `confirmed`, `compatible_candidate`, `ambiguous`, `insufficient`, or `unknown`, requiring OEM_Exclusive_Evidence for `confirmed`.
7. THE Confidence_Engine SHALL read all OEM-specific evidence/signature weights from versioned OEM_Profile data and all classification-policy values (threshold, minimum margin, minimum evidence quality) from versioned classification configuration, rather than from source-code constants; all such numeric values are provisional engineering configuration unless validated.
8. THE Confidence_Engine SHALL preserve the Evidence_Status of every contributing Evidence_Item and SHALL NOT treat a non-validated OEM_Profile rule as validated forensic evidence solely because its numerical score is high.
9. THE Confidence_Engine SHALL expose the top candidate, the second candidate, the margin, the evidence quality, the validation state, applicability, and the Evidence_Status of the contributing evidence.
10. THE Confidence_Engine SHALL preserve ambiguity and SHALL NOT select a winner solely because it has the highest score WHERE the margin is below the configured minimum.
11. THE Confidence_Engine SHALL apply the classification decision order: (1) if the evidence is structurally insufficient OR the result rests only on a lone magic value → `insufficient`; (2) else if no candidate reaches the configured threshold → `unknown`; (3) else if the top-two margin is below the configured minimum → `ambiguous`; (4) else if the threshold, margin, and quality requirements are satisfied AND OEM_Exclusive_Evidence exists → `confirmed`; (5) otherwise → `compatible_candidate`. This ordering makes evidence insufficiency and the lone-magic-value case (Req 2.3) take precedence over the threshold check, so a lone magic value is classified `insufficient` and never `unknown`. All thresholds, margins, weights, and quality factors are versioned configuration/profile values and are provisional engineering configuration unless validated.

### Requirement 11: Versioned OEM Profiles (Phase 2)

**User Story:** As a system architect, I want OEM knowledge stored as versioned profiles, so that detection rules are auditable and updatable without code changes.

#### Acceptance Criteria

1. THE OEM_Profile SHALL contain signatures, offset constraints, endianness, expected ranges, validation rules, confidence weights, and model/firmware applicability.
2. THE OEM_Profile SHALL carry a version identifier.
3. WHEN a Detector uses an OEM_Profile, THE Detector SHALL record the OEM_Profile version used in the Detector_Output.
4. THE Platform SHALL store OEM_Profiles as data artifacts separate from Detector source code.
5. THE OEM_Profile SHALL assign every signature, offset, magic value, structure, and range an Evidence_Status of `validated`, `provisional`, `model_specific`, `firmware_specific`, or `unvalidated`, and THE profile loader SHALL reject a signature or rule that lacks an Evidence_Status.
6. THE Platform SHALL NOT treat a `provisional`, `model_specific`, `firmware_specific`, or `unvalidated` signature as a universal forensic fact, and SHALL NOT raise Attribution_Status to `confirmed` on the basis of such signatures alone.
7. THE OEM_Profile SHALL record model, firmware, hardware/storage variant, evidence source/reference, and validation state for its applicability.
8. THE Platform SHALL NOT admit an undocumented factual signature into an OEM_Profile; every rule SHALL carry one of `validated`, `provisional`, `model_specific`, `firmware_specific`, or `unvalidated`.

### Requirement 12: OEM Parsers and Active Recording Parsing (Phase 3)

**User Story:** As an Examiner, I want parsers that interpret filesystem, metadata, recordings, timeline, and deleted data through a common interface, so that all OEMs are analyzed consistently.

#### Acceptance Criteria

1. THE Parser SHALL expose, through a common interface shared across the Dahua, Hikvision, Honeywell, CP Plus/UBS, and Uniview parsers, operations for filesystem/storage interpretation, metadata interpretation, recording/index interpretation, timestamp extraction, OEM-specific structural validation, and OEM-specific candidate recognition used by recovery; THE Recovery_Engine SHALL own recovery-level orchestration, recovery-state classification, and candidate recovery orchestration, invoking Parser knowledge as needed.
2. WHEN the Parser parses an active Recording, THE Parser SHALL record the camera channel, Raw_Timestamp, Normalized_Timestamp, source image, source offsets, parser identifier, parser version, status, and integrity; THE Parser SHALL NOT be required to record an exported video path, which is associated later by the Video_Reconstructor or export step and never by the Parser.
3. WHEN the Parser reads filesystem structures, THE Parser SHALL interpret them according to the OEM_Profile identified during detection.
4. IF the Parser encounters a structure inconsistent with the OEM_Profile, THEN THE Parser SHALL record the inconsistency in the Recording integrity status.
5. WHEN the Parser validates or interprets a candidate structure, THE Parser SHALL NOT independently make or override the final OEM attribution decision.

### Requirement 13: Multi-Level Recovery (Phase 4)

**User Story:** As an Examiner, I want recovery that distinguishes recovery levels, what happened to the data (Data_State), and whether it can be reconstructed (Recovery_Status), so that I understand what was recovered and what is unrecoverable.

#### Acceptance Criteria

1. THE Recovery_Engine SHALL support Level 1 indexed recovery, Level 2 orphan and slack recovery, and Level 3 raw carving.
2. WHEN recovering data, THE Recovery_Engine SHALL classify each item along two independent dimensions: a Data_State (one of `active`, `deleted`, `orphaned`, `corrupted`, `overwritten`) describing what happened to the data on the medium, and a Recovery_Status (one of `recoverable`, `partially_recoverable`, `unrecoverable`) describing whether the required content can still be reconstructed.
3. IF data has been physically overwritten, THEN THE Recovery_Engine SHALL set the Data_State to `overwritten` and SHALL NOT reconstruct or fabricate the replaced content.
4. WHEN validating a candidate frame, THE Recovery_Engine SHALL validate the frame against OEM signatures, structure, timestamps, channel, and continuity.
5. THE Recovery_Engine SHALL record the recovery level, Data_State, and Recovery_Status for each item.
6. THE Recovery_Engine SHALL apply the Data_State definitions: `active` (valid indexed/recognized recording represented by valid storage structures); `deleted` (metadata indicates deletion but recoverable content may remain); `orphaned` (content remains but normal index linkage is missing); `corrupted` (evidence exists but required structures/content are damaged or inconsistent); `overwritten` (evidence indicates previous content has been replaced by newer content).
7. THE Recovery_Engine SHALL apply the Recovery_Status definitions: `recoverable` (required content can be reconstructed from available evidence); `partially_recoverable` (some required content can be reconstructed and gaps remain); `unrecoverable` (required content cannot be reconstructed from available evidence, including confirmed overwrite or insufficient remaining data). THE Recovery_Engine SHALL NOT treat a `corrupted` Data_State as automatically `unrecoverable`.
8. WHERE data has an `overwritten` Data_State and its required previous content cannot be reconstructed, THE Recovery_Engine SHALL set Recovery_Status to `unrecoverable` while retaining the `overwritten` Data_State, and SHALL NOT collapse the two dimensions into a single value.
9. THE Recovery_Engine SHALL bound every recovery algorithm with a maximum scan region, a maximum candidate count, and a maximum hypothesis count, and SHALL support cancellation, progress reporting, and a truncation status.
10. IF a recovery search is deliberately bounded and the full search space was not explored, THEN THE Recovery_Engine SHALL report the result as `REVIEW` and SHALL NOT claim a global optimum.
11. THE Recovery_Engine SHALL set Data_State to `overwritten` ONLY WHERE physical evidence supports an actual overwrite; the mere absence of data or missing index linkage SHALL NOT be treated as proof of overwrite, and such cases SHALL instead be classified as `deleted`, `orphaned`, `corrupted`, or `unrecoverable` as the evidence supports.

### Requirement 14: Video Reconstruction (Phase 4)

**User Story:** As an Examiner, I want recovered frames validated and reconstructed into playable video without fabricated continuity, so that reconstructed video is trustworthy.

#### Acceptance Criteria

1. WHEN reconstructing video, THE Video_Reconstructor SHALL validate frame headers, frame sizes, timestamps, channels, and sequence.
2. THE Video_Reconstructor SHALL use I-frame and GOP relationships to order and reconstruct frames.
3. WHEN a gap in frames is detected, THE Video_Reconstructor SHALL mark the gap and SHALL NOT synthesize content to fill the gap.
4. WHEN producing output video, THE Video_Reconstructor SHALL prefer remux/transmux over re-encoding.
5. WHEN reconstruction is complete, THE Video_Reconstructor SHALL perform a decode test on the reconstructed output and record the decode result.
6. THE Video_Reconstructor SHALL keep native extraction separate from derived review video, and SHALL identify codecs from evidence rather than assuming an OEM from a codec.
7. THE Video_Reconstructor SHALL NOT treat an elementary stream as implying recorder identity, and SHALL NOT treat physical order as automatically chronological.
8. THE Video_Reconstructor SHALL handle circular/wrap storage explicitly and record decode/QC results.
9. THE Video_Reconstructor SHALL assign each reconstruction a Validation_State of `PASS`, `REVIEW`, `FAIL`, or `UNKNOWN`, where `PASS` means required validation executed successfully, `REVIEW` means a candidate exists but ambiguity or missing evidence remains, `FAIL` means a strong structural/decode/integrity contradiction, and `UNKNOWN` means required validation has not run.
10. THE Video_Reconstructor SHALL NOT assign `PASS` on the basis of duration or successful extraction alone.

### Requirement 15: Timeline and Cross-Camera Correlation (Phase 5)

**User Story:** As an Examiner, I want a unified cross-camera timeline linked to source evidence, so that I can correlate events across cameras with provenance.

#### Acceptance Criteria

1. THE Timeline_Engine SHALL build the unified timeline spanning all cameras in a case from the TimelineEvent candidates extracted by the Parser.
2. WHEN adding an event to the timeline, THE Timeline_Engine SHALL link the event to its camera, timestamp, recording identifier, and source offsets.
3. THE Timeline_Engine SHALL order timeline events by their Normalized_Timestamp while retaining each event's Raw_Timestamp.
4. THE Timeline_Engine SHALL support correlating events that occur across multiple cameras.
5. THE Parser SHALL perform OEM-specific extraction of timestamped recording/event information into TimelineEvent candidates; THE Parser SHALL NOT construct the final unified timeline, which is owned by the Timeline_Engine.
6. THE Timeline_Engine SHALL keep physical order, recorder-native chronological order, and normalized chronological order distinguishable, and SHALL NOT automatically equate physical disk order with chronological order.

### Requirement 16: AI Analytics (Optional, Phase 7)

**User Story:** As an Examiner, I want optional AI analytics on validated evidence with full traceability, so that AI findings are useful but clearly labeled as assistive.

#### Acceptance Criteria

1. THE AI_Analytics SHALL operate only on evidence that has been validated by parsing.
2. WHEN AI_Analytics produces a finding, THE AI_Analytics SHALL link the finding to its clip, recording identifier, camera, timestamp, source offset, parser version, and hash.
3. THE AI_Analytics SHALL label every finding as AI-assisted.
4. THE AI_Analytics SHALL NOT present findings as absolute truth.
5. WHERE AI_Analytics is disabled, THE Platform SHALL complete parsing, recovery, timeline, and reporting without AI findings.
6. THE AI_Analytics SHALL NOT alter forensic source evidence, and its outputs SHALL remain Derived_Artifacts labeled AI-assisted.

### Requirement 17: Reporting (Phase 6)

**User Story:** As an Examiner, I want reports in PDF, JSON, and CSV that include full case detail and limitations, so that I can deliver defensible findings.

#### Acceptance Criteria

1. WHEN an Examiner requests a report, THE Reporting_Service SHALL generate the report in the requested format among PDF, JSON, and CSV.
2. THE Reporting_Service SHALL include case information, evidence information, acquisition details, hashes, OEM detection, filesystem analysis, recordings, recovered and deleted data, timeline, cross-camera events, AI findings, source offsets, parser version, chain of custody, and limitations in the report.
3. WHEN a report is generated, THE Hashing_Service SHALL compute a SHA-256 hash of the report and THE Chain_Of_Custody SHALL record the report Provenance.
4. THE Reporting_Service SHALL state the limitations of the analysis in every report.
5. THE Reporting_Service SHALL include the capabilities actually executed, the unsupported capabilities, ambiguous results, `REVIEW` results, `UNKNOWN` results, source hash, OEM_Profile versions, parser versions, recovery level, validation status, and provenance.
6. THE Reporting_Service SHALL NOT present a profile-only capability as reconstruction support.

### Requirement 18: Forensic Workstation UI (All Phases)

**User Story:** As an Examiner, I want a professional forensic workstation interface with evidence-backed detection and a hex viewer, so that I can inspect findings down to raw bytes.

#### Acceptance Criteria

1. THE UI SHALL provide navigation to Case, Evidence, Acquisition, Detection, Parsing, Recovery, Timeline, Evidence/Provenance, and Reports screens.
2. WHEN displaying a Classified_Detection_Result, THE UI SHALL show the supporting evidence list and SHALL NOT display only a confidence percentage.
3. THE UI SHALL provide a Hex_Viewer that displays raw bytes of evidence.
4. WHEN an Examiner selects an Evidence_Item, THE Hex_Viewer SHALL resolve the evidence identifier, offset, and length and navigate to that offset, displaying offset, hexadecimal bytes, ASCII, the selected range, and interpretation.
5. THE UI SHALL present a light, neutral visual style with charcoal text, compact tables, and restrained blue accents.
6. WHERE the original evidence is available, THE Hex_Viewer SHALL read directly from the original evidence through the Evidence_Reader and SHALL NOT read from an exported or copied version.
7. THE UI overview SHALL display case, evidence name, hash, evidence size, analysis status, OEM/storage candidates, confidence, the evidence supporting detection, OEM_Profile version, and warnings.
8. THE UI SHALL present a capability matrix, detection evidence view, profile applicability (including model/firmware applicability), PASS/REVIEW/FAIL/UNKNOWN validation status, source provenance, acquisition status, parser status, and reconstruction status.
9. THE UI SHALL NOT display only "Supported"; it SHALL show the separate Capability_Stage values per OEM (for example: Detection: IMPLEMENTED, Profiling: IMPLEMENTED, Parsing: PARTIAL, Reconstruction: NOT_IMPLEMENTED, Validation: PARTIAL). THE UI SHALL present Capability_Stage (implementation maturity) separately from Validation_State (PASS/REVIEW/FAIL/UNKNOWN operation outcome) and SHALL NOT render a Validation_State value as a Capability_Stage.

### Requirement 19: Testing and Quality Benchmarks (All Phases)

**User Story:** As a quality engineer, I want per-OEM test corpora and measured benchmarks, so that detection, parsing, and recovery quality are verifiable.

#### Acceptance Criteria

1. THE Platform SHALL include, for each supported OEM, known-good, known-negative, corrupted, partial, and false-positive test cases.
2. THE Platform SHALL measure detection accuracy, false-positive rate, and false-negative rate.
3. THE Platform SHALL measure parsing success rate, recovery rate, and false recovery rate.
4. THE Platform SHALL measure timestamp accuracy, throughput, and memory use.
5. WHEN a benchmark is executed, THE Platform SHALL record the measured values for review.
6. THE Platform SHALL include adversarial tests for: lone magic value, magic value at an incorrect offset, valid signature with corrupted surrounding structure, overlapping OEM signatures, ambiguous confidence, unknown filesystem, truncated image, sparse image, out-of-bounds read, cancellation, write attempt, profile-version change, repeated deterministic analysis, overwritten recovery candidate, fragmented recording, and missing video frames.
7. THE Platform SHALL provide a synthetic fixture generator so that tests run without real forensic evidence.
8. THE adversarial tests SHALL specifically verify that the Platform does not produce false OEM attribution or false recovery.
9. THE Platform SHALL include, for each supported OEM, test cases covering: known-good, known-negative, corrupted, partial, false-positive, truncated, sparse, overlapping-signature, wrong-offset, lone-magic, fragmented, missing-frame, overwritten, deleted, orphaned, unknown-model, and unknown-firmware.
10. THE Platform SHALL provide a machine-readable validation corpus in which each case records a case ID, source hash, expected detection, expected confidence/classification, expected regions, expected parser state, expected recovery state, expected validation state, and provenance.
11. THE Platform SHALL clearly label synthetic fixtures as `synthetic` and SHALL NOT describe them as real forensic evidence.

### Requirement 20: Deterministic Forensic Results (Cross-Cutting, All Phases)

**User Story:** As an Examiner, I want reproducible forensic results, so that an analysis can be independently repeated and defended.

#### Acceptance Criteria

1. WHERE evidence bytes, OEM_Profile versions, configuration (including the ConfidenceConfig version and recovery configuration), and the relevant analysis-component versions (Detector, Parser, Confidence_Engine, and Recovery_Engine versions) are identical, THE Platform SHALL produce identical Forensic_Results, comprising the detection result, confidence and classification, parser result, and recovery result.
2. THE Platform SHALL NOT require reproducibility of runtime metadata that is inherently environment-dependent, including database identifiers, execution timestamps, temporary paths, and processing durations.
3. THE Platform SHALL ensure detector order independence, parser order independence where applicable, stable evidence ordering, stable candidate ordering, and stable confidence calculation.
4. WHERE detection or recovery is executed in parallel, THE Platform SHALL produce a final Forensic_Result that is independent of execution order and thread scheduling.

### Requirement 21: Capability Maturity (Cross-Cutting, All Phases)

**User Story:** As an Examiner, I want each OEM's capabilities represented at their true maturity, so that I am never misled that a capability exists when it does not.

#### Acceptance Criteria

1. THE Platform SHALL represent capability maturity independently for Detection, Profiling, Parsing, Reconstruction, and Validation.
2. THE Platform SHALL express each Capability_Stage using an explicit maturity set (`NOT_IMPLEMENTED`, `PARTIAL`, `IMPLEMENTED`) applied independently to each of the five dimensions (Detection, Profiling, Parsing, Reconstruction, Validation); the exact enum may be adjusted in implementation but the five independent dimensions SHALL remain, and Capability_Stage SHALL remain distinct from Validation_State (PASS/REVIEW/FAIL/UNKNOWN).
3. THE Platform SHALL NOT advertise a capability at a higher stage than is actually implemented.
4. THE Platform SHALL derive Capability_Stage values from implemented capabilities rather than from marketing or intent.

### Requirement 22: Validation States (Cross-Cutting, All Phases)

**User Story:** As an Examiner, I want every major forensic operation to carry an explicit validation outcome with a reason, so that I can distinguish verified results from unverified ones.

#### Acceptance Criteria

1. THE Platform SHALL assign every major forensic operation a Validation_State of `PASS`, `REVIEW`, `FAIL`, or `UNKNOWN`.
2. THE Platform SHALL record an explanation/reason for each Validation_State.
3. THE Platform SHALL NOT record `PASS` for a stage that has not been executed or verified.

### Requirement 23: Acquisition Verification (Phase 1+)

**User Story:** As an Examiner, I want acquisition maps and completeness preserved and verified, so that I never treat an incomplete acquisition as complete.

#### Acceptance Criteria

1. WHERE acquisition metadata or maps are available, THE Platform SHALL preserve them and compute and record their hashes.
2. THE Platform SHALL record unresolved regions, bad-sector regions, and the completion status of the acquisition.
3. THE Platform SHALL represent Acquisition_Status as one of `complete`, `partial`, `failed`, or `unknown`.
4. THE Platform SHALL NOT label an incomplete acquisition as complete.

### Requirement 24: Adversarial Parsing and Recovery (Cross-Cutting, All Phases)

**User Story:** As a security-conscious Examiner, I want all parsers and recovery modules to treat evidence as hostile input, so that malformed evidence never crashes or misleads the Platform.

#### Acceptance Criteria

1. THE Parsers and Recovery_Engine SHALL treat all evidence as hostile input and SHALL NOT panic on malformed evidence.
2. THE Platform SHALL safely handle invalid lengths, integer/offset/length overflow, negative or invalid offsets, out-of-range offsets, truncated structures, corrupted metadata, malformed strings, impossible timestamps, cyclic references, excessive candidate counts, and pathological fragmentation.
3. THE Platform SHALL safely handle cancellation during parsing and interrupted reads, returning a defined result rather than crashing.
4. THE Platform SHALL use checked arithmetic for offset and size computations and SHALL reject out-of-bounds access.

### Requirement 25: Uniview OEM Support (Phases 2–4)

**User Story:** As an Examiner, I want Uniview treated as a first-class supported OEM with profile-controlled evidence, so that Uniview storage is detected and parsed with the same forensic rigor and honesty as the other target OEMs.

#### Acceptance Criteria

1. THE Platform SHALL treat Uniview as a current supported target OEM (not future work), with a Uniview Detector and Uniview Parser sharing the common Detector/Parser interfaces.
2. THE Uniview Detector SHALL operate over the read-only Evidence_Reader using a bounded initial scan whose range, alignment, and expected structures are controlled by the Uniview OEM_Profile; a 16 KiB initial scan MAY be used as a profile-controlled strategy but SHALL NOT be treated as a universal Uniview rule.
3. THE Uniview OEM_Profile SHALL supply, with an Evidence_Status, the Uniview storage-region vocabulary (`super`, `super-data`, `ui-ctl`, `ui-data`, `di`, `flow`, `data`), magic/version candidates (including `0x1367` and `0x1587`), the `EcPortId` form, timestamp encoding, and the `MP_MAIN_IDX_S`-style index and timestamp-to-block mapping; THE Platform SHALL NOT treat any of these as universal facts unless their Evidence_Status is `validated`.
4. THE Uniview Detector SHALL treat `EcPortId` (e.g. the illustrative form `00000#EC1001`) and timestamp evidence as corroborating evidence validated by profile rules, and SHALL NOT treat either alone as proof of Uniview.
5. THE Uniview Parser SHALL interpret Uniview storage via detection → super metadata → region identification → DI/index → timestamp-to-block mapping → DATA region → video payload → frame validation → Recording, and SHALL NOT construct the unified timeline or make final OEM attribution.
6. THE Recovery_Engine SHALL apply L1/L2/L3 recovery to Uniview evidence using Uniview Parser recovery knowledge, preserving Data_State/Recovery_Status independence and bounded-search semantics.
7. THE Platform SHALL handle Uniview edge cases (missing superblock, wrong magic location, lone magic, corrupted super metadata, invalid timestamp, missing/invalid EcPortId, model/firmware mismatch, region inconsistency, missing DI, orphan DATA, fragmented recording, missing/corrupted frames, overwrite, truncated image, out-of-bounds block, multiple/conflicting candidates, unknown variant) without panic and via checked arithmetic.
