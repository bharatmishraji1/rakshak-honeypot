from fastapi import FastAPI, Header, HTTPException, Request
import os

app = FastAPI()

# API key from environment
API_KEY = os.getenv("API_KEY", "RAKSHAK_SECRET_123")


@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):
    # API key check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Try reading JSON safely
    try:
        payload = await request.json()
    except:
        payload = {}

    # Universal text extractor (handles nested JSON)
    def extract_text(data):
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            for value in data.values():
                result = extract_text(value)
                if result:
                    return result
        if isinstance(data, list):
            for item in data:
                result = extract_text(item)
                if result:
                    return result
        return ""

    raw_text = extract_text(payload)
    text = raw_text.lower()

    # Basic scam detection
    scam_keywords = [
        "upi",
        "account",
        "blocked",
        "verify",
        "refund",
        "payment",
        "bank",
        "otp",
        "kyc",
        "link"
    ]

    is_scam = any(k in text for k in scam_keywords)

    # Required JSON response schema
    return {
        "scam_detected": bool(is_scam),
        "scam_type": "generic_scam" if is_scam else "none",
        "confidence_score": float(0.9 if is_scam else 0.2),
        "extracted_entities": {
            "upi_ids": [],
            "bank_accounts": [],
            "phone_numbers": [],
            "urls": []
        },
        "conversation_summary": "Basic honeypot detection active."
    }
