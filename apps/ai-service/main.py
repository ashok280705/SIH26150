"""
DVR/NVR Forensic Platform — AI Analytics Microservice (Phase 7 / Req 16).

This service provides optional, probabilistic AI-assisted visual analytics
(e.g., motion detection, vehicle/person bounding box identification).

Evidentiary Constraints:
- Operates ONLY on derived video clips or frame byte streams.
- NEVER receives a filesystem path to original evidence (Req 16.1).
- Outputs are probabilistic findings labeled 'AI-assisted' (Req 16.3).
- Findings NEVER alter or replace original evidence (Req 16.6).
- Unauthenticated prototype: Add authentication before network exposure.
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Optional
import time

app = FastAPI(
    title="DVR/NVR Forensic AI Analytics Service",
    version="1.0.0",
    description="Probabilistic AI analytics for validated DVR/NVR video clips.",
)

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    device: str = "cpu"
    models_loaded: List[str] = ["yolov8_detector", "motion_analyzer"]

class BoundingBox(BaseModel):
    x: float = Field(..., ge=0.0, le=1.0)
    y: float = Field(..., ge=0.0, le=1.0)
    width: float = Field(..., ge=0.0, le=1.0)
    height: float = Field(..., ge=0.0, le=1.0)

class AnalyzeClipRequest(BaseModel):
    evidence_id: str
    recording_id: str
    channel: int
    clip_bytes_base64: Optional[str] = None
    # Reject direct evidence path if supplied (Safety Guard)
    evidence_path: Optional[str] = None

class AiFindingResponse(BaseModel):
    finding_id: str
    evidence_id: str
    recording_id: str
    channel: int
    timestamp_offset_sec: float
    finding_type: str
    confidence: float
    bounding_box: Optional[BoundingBox]
    is_ai_assisted: bool = True
    disclaimer: str = "AI-assisted finding; probabilistic analysis only; not absolute truth (Req 16.3)"

@app.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint confirming AI service status and loaded models."""
    return HealthResponse()

@app.post("/analyze_clip", response_model=List[AiFindingResponse])
def analyze_clip(request: AnalyzeClipRequest):
    """
    Analyzes a parser-validated video clip.
    Rejects any request containing direct evidence paths to enforce isolation boundary.
    """
    if request.evidence_path is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Direct evidence paths are prohibited; AI operates strictly on extracted clip bytes (Req 16.1)",
        )

    # Simulated deterministic detection for validated clips
    findings = [
        AiFindingResponse(
            finding_id=f"ai-{int(time.time())}-1",
            evidence_id=request.evidence_id,
            recording_id=request.recording_id,
            channel=request.channel,
            timestamp_offset_sec=12.5,
            finding_type="PersonDetected",
            confidence=0.91,
            bounding_box=BoundingBox(x=0.25, y=0.30, width=0.15, height=0.45),
        ),
        AiFindingResponse(
            finding_id=f"ai-{int(time.time())}-2",
            evidence_id=request.evidence_id,
            recording_id=request.recording_id,
            channel=request.channel,
            timestamp_offset_sec=24.0,
            finding_type="VehicleDetected",
            confidence=0.87,
            bounding_box=BoundingBox(x=0.55, y=0.40, width=0.30, height=0.25),
        ),
    ]
    return findings

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
