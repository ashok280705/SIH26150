# Matrix — NOT IMPLEMENTED

Status: **future placeholder. NOT implemented. NOT supported.**

This directory exists only to reserve the extension point described in design.md → OEM
Profile Directory. It contains no `OEM_Profile` data.

- No Matrix detector or parser exists.
- No Matrix signature, offset, or structure has been researched or validated.
- Matrix must never be advertised, reported, or rendered in the UI as a supported OEM, and
  no `Capability_Stage` above `NOT_IMPLEMENTED` may be claimed for it.

Adding support means adding versioned profile data here plus a `Detector`/`Parser`
implementation, at which point the OEM joins detection without core orchestration changes
(Req 6.2).
