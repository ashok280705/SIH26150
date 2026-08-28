# services/ai

Placeholder for the **optional** Python FastAPI AI analytics service (OpenCV + PyTorch).

Not scaffolded yet — the service is built in Phase 7. `P1-001` only establishes the layout.

Constraints that govern this service when it is built:

- AI is **optional**. The full pipeline completes end to end with the service absent or
  disabled (Req 16.1).
- It operates only on parser-validated evidence and rejects non-validated input.
- Every finding is a **Derived_Artifact** labeled AI-assisted, never absolute truth, and
  carries full provenance: clip, recording id, camera, timestamp, source offset, parser
  version, and hash.
- It never replaces a native artifact with a derived copy.
