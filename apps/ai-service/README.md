# DVR/NVR Forensic Platform — AI Analytics Microservice

Optional Python/FastAPI visual analytics microservice (Req 16).

## Forensic Isolation Architecture
- Strictly downstream of parser validation (Req 16.1).
- Operates ONLY on derived clip bytes streamed in memory.
- NEVER accepts filesystem paths to raw evidence disk images.
- All outputs are labeled `AI-assisted` with non-admissibility disclaimers.
- Findings are registered as `DerivedArtifact`s and never modify original evidence.

## Security Notice
This is an unauthenticated local service for prototype/demonstration use. In production deployments, mutual TLS (mTLS) or JWT bearer token authentication MUST be configured before exposing across any network boundary.
