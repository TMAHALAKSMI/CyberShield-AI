"""
routers/scan.py  –  URL scan + history endpoints
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from typing import List

from database.db import get_db
from database.models import ScanHistory

router = APIRouter(prefix="/scan", tags=["scan"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    user_id: int
    url: str


class ScanResult(BaseModel):
    id: int
    user_id: int
    url: str
    is_phishing: bool
    prediction: str
    confidence: float
    scanned_at: datetime

    class Config:
        from_attributes = True


# ── routes ────────────────────────────────────────────────────────────────────
@router.post("/check", response_model=ScanResult)
def scan_url(payload: ScanRequest, db: Session = Depends(get_db)):
    """
    Run phishing model on URL and persist result to scan_history.
    Replace the stub below with your actual model call.
    """
    # ── call your ML model here ───────────────────────────────────────────────
    from model import predict_url          # your existing model module
    is_phishing, confidence = predict_url(payload.url)
    prediction = "phishing" if is_phishing else "legitimate"
    # ─────────────────────────────────────────────────────────────────────────

    record = ScanHistory(
        user_id=payload.user_id,
        url=payload.url,
        is_phishing=is_phishing,
        prediction=prediction,
        confidence=round(confidence, 4),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("/history/{user_id}", response_model=List[ScanResult])
def get_history(user_id: int, limit: int = 50, db: Session = Depends(get_db)):
    """Return latest scan history for a user (most recent first)."""
    records = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user_id)
        .order_by(ScanHistory.scanned_at.desc())
        .limit(limit)
        .all()
    )
    return records


@router.delete("/history/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a single scan record."""
    record = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    db.delete(record)
    db.commit()
    return {"detail": "deleted"}