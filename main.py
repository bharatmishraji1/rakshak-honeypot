from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, List
import os

app = FastAPI()

API_KEY = os.getenv("API_KEY", "RAKSHAK_SECRET_123")


# Request schema (flexible but structured)
class HoneypotRequest(BaseModel):
    message: Optional[str] = None
    content: Optional[str] = None
    text: Optional[str] = None
    conversation_id: Optional[str] = None


@app.post("/honeypot")
async def honeypot(payload: HoneypotRequest, x_api_key: str = Header(None)):
    # API key check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Extract text safely
    raw_text = payload.message or payload.content or payload.text or ""
    text = raw_text.lower()

    # Detection logic
    financial_keywords = [
        "upi", "payment", "transfer", "wallet", "bank", "transaction"
    ]

    urgency_keywords = [
        "urgent", "immediately", "last warning", "final notice", "freeze"
    ]

    credential_keywords = [
        "otp", "pin", "cvv", "card", "password", "login"
    ]

    refund_keywords = ["refund", "cashback", "reward"]
    job_keywords = ["job", "registration fee", "processing fee"]
    lottery_keywords = ["lottery", "winner", "prize"]
    kyc_keywords = ["kyc", "update", "verify", "blocked"]

    score = 0.0

    if any(k in text for k in financial_keywords):
        score += 0.3
    if any(k in text for k in urgency_keywords):
        score += 0.2
    if any(k in text for k in credential_keywords):
        score += 0.4
    if any(k in text for k in refund_keywords + job_keywords + lottery_keywords + kyc_keywords):
        score += 0.3

    confidence = min(score, 1.0)
    is_scam = confidence > 0.4

    # Scam type
    if any(k in text for k in kyc_keywords):
        scam_type = "kyc_scam"
    elif any(k in text for k in refund_keywords):
        scam_type = "refund_scam"
    elif any(k in text for k in job_keywords):
        scam_type = "job_scam"
    elif any(k in text for k in lottery_keywords):
        scam_type = "lottery_scam"
    else:
        scam_type = "generic_scam" if is_scam else "none"

    # Final response
    return {
        "scam_detected": is_scam,
        "scam_type": scam_type,
        "confidence_score": confidence,
        "extracted_entities": {
            "upi_ids": [],
            "bank_accounts": [],
            "phone_numbers": [],
            "urls": []
        },
        "conversation_summary": "Basic honeypot detection active."
    }
