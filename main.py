from fastapi import FastAPI, Header, HTTPException, Request
import os
import re

app = FastAPI()

API_KEY = os.getenv("API_KEY", "RAKSHAK_SECRET_123")


@app.post("/honeypot")
async def honeypot(request: Request, x_api_key: str = Header(None)):
    # API key check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Raw JSON accept
    try:
        data = await request.json()
    except:
        data = {}

    # Extract text from possible fields
    text = ""
    if isinstance(data, dict):
        text = (
            str(data.get("message", "")) +
            str(data.get("content", "")) +
            str(data.get("text", ""))
        ).lower()

    # ----------------------------
    # SCAM DETECTION LOGIC
    # ----------------------------

    scam_categories = {
        "bank_kyc": [
            "kyc", "blocked", "account", "verify", "bank",
            "update", "suspend", "freeze"
        ],
        "payment_scam": [
            "upi", "payment", "transfer", "send money",
            "processing fee", "charge"
        ],
        "otp_scam": [
            "otp", "one time password", "code", "verification code"
        ],
        "job_scam": [
            "job", "work from home", "salary", "registration fee",
            "apply now", "seat", "task"
        ],
        "lottery_scam": [
            "lottery", "prize", "winner", "reward", "claim now"
        ],
        "refund_scam": [
            "refund", "cashback", "return", "amount credited"
        ],
        "phishing_link": [
            "link", "click", "http", "www", ".com", ".net"
        ]
    }

    scam_score = 0
    detected_types = []

    for scam_type, keywords in scam_categories.items():
        for kw in keywords:
            if kw in text:
                scam_score += 1
                detected_types.append(scam_type)
                break

    # Final decision
    is_scam = scam_score >= 2

    if detected_types:
        scam_type = max(set(detected_types), key=detected_types.count)
    else:
        scam_type = "none"

    # Confidence calculation
    confidence = min(0.4 + (scam_score * 0.1), 0.95) if is_scam else 0.2

    # ----------------------------
    # ENTITY EXTRACTION
    # ----------------------------

    upi_pattern = r"\b[\w\.-]+@[\w]+\b"
    phone_pattern = r"\b\d{10}\b"
    url_pattern = r"(https?://[^\s]+)"
    bank_pattern = r"\b\d{9,18}\b"

    upi_ids = re.findall(upi_pattern, text)
    phone_numbers = re.findall(phone_pattern, text)
    urls = re.findall(url_pattern, text)
    bank_accounts = re.findall(bank_pattern, text)

    return {
        "scam_detected": is_scam,
        "scam_type": scam_type,
        "confidence_score": round(confidence, 2),
        "extracted_entities": {
            "upi_ids": list(set(upi_ids)),
            "bank_accounts": list(set(bank_accounts)),
            "phone_numbers": list(set(phone_numbers)),
            "urls": list(set(urls))
        },
        "conversation_summary": "Scam analysis completed using rule-based engine."
    }
