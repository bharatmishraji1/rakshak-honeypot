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
        
    # Safe JSON read
    try:
        data = await request.json()
        if not isinstance(data, dict):
            data = {}
    except:
        data = {}

    # Extract text safely
    text = (
        str(data.get("message", "")) +
        str(data.get("content", "")) +
        str(data.get("text", ""))
    ).lower()

     # ----------------------------
    # ENTITY EXTRACTION
    # ----------------------------

    # UPI ID pattern
    upi_ids = re.findall(r"\b[\w\.-]+@[\w]+\b", text)

    # Bank account numbers (9–18 digits)
    bank_accounts = re.findall(r"\b\d{9,18}\b", text)

    # Phone numbers (10 digits)
    phone_numbers = re.findall(r"\b\d{10}\b", text)

    # URLs
    urls = re.findall(r"https?://[^\s]+", text)

    # ----------------------------
    # SCAM TYPE DETECTION
    # ----------------------------

    scam_type = "none"
    confidence = 0.2

    if any(k in text for k in ["kyc", "blocked", "verify", "suspend"]):
        scam_type = "kyc_scam"
        confidence = 0.9

    elif any(k in text for k in ["refund", "return", "cashback"]):
        scam_type = "refund_scam"
        confidence = 0.9

    elif any(k in text for k in ["job", "salary", "offer", "seat", "registration"]):
        scam_type = "job_scam"
        confidence = 0.88

    elif any(k in text for k in ["lottery", "prize", "winner", "reward"]):
        scam_type = "lottery_scam"
        confidence = 0.85

    elif any(k in text for k in ["upi", "payment", "account", "bank", "otp", "link"]):
        scam_type = "generic_scam"
        confidence = 0.8

    is_scam = scam_type != "none"

    # ----------------------------
    # DYNAMIC SUMMARY
    # ----------------------------

    summary_parts = []

    if is_scam:
        summary_parts.append(f"Detected {scam_type} attempt.")

    if upi_ids:
        summary_parts.append(f"Extracted {len(upi_ids)} UPI ID(s).")

    if bank_accounts:
        summary_parts.append(f"Extracted {len(bank_accounts)} bank account number(s).")

    if phone_numbers:
        summary_parts.append(f"Extracted {len(phone_numbers)} phone number(s).")

    if urls:
        summary_parts.append(f"Extracted {len(urls)} phishing URL(s).")

    if not summary_parts:
        summary_parts.append("No significant scam indicators detected.")

    conversation_summary = " ".join(summary_parts)

    # ----------------------------
    # FINAL RESPONSE
    # ----------------------------

    return {
        "scam_detected": is_scam,
        "scam_type": scam_type,
        "confidence_score": confidence,
        "extracted_entities": {
            "upi_ids": upi_ids,
            "bank_accounts": bank_accounts,
            "phone_numbers": phone_numbers,
            "urls": urls
        },
        "conversation_summary": conversation_summary
    }
