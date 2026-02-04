from fastapi import FastAPI, Header, HTTPException, Request
import os

app = FastAPI()

API_KEY = os.getenv("API_KEY", "RAKSHAK_SECRET_123")

@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):
    # API key check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Accept ANY JSON body
    try:
        payload = await request.json()
    except:
        payload = {}

    # Extract text from any possible field
    raw_text = ""
    if isinstance(payload, dict):
        raw_text = (
            payload.get("message")
            or payload.get("text")
            or payload.get("input")
            or payload.get("content")
            or ""
        )

    text = str(raw_text).lower()

    scam_keywords = ["upi", "account", "blocked", "verify", "refund", "payment", "bank", "otp"]
    is_scam = any(k in text for k in scam_keywords)

    return {
        "scam_detected": is_scam,
        "scam_type": "generic_scam" if is_scam else "none",
        "confidence_score": 0.9 if is_scam else 0.2,
        "extracted_entities": {},
        "brief_conversation_summary": "Basic honeypot detection active."
    }
