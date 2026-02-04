from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Optional
import os, time

app = FastAPI(title = 'Rakshak-H Honeypot API')

API_KEY = os.getenv('API_KEY', 'CHANGE_ME')

class HoneypotRequest(BaseModel):
    message : str
    conversation_id : Optional[str] = None
    
class HoneypotResponse(BaseModel):
    
    scam_detected: bool
    agent_activated: bool
    message: str

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot(payload: HoneypotRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    time.sleep(1)

    text = payload.message.lower()
    scam_keywords = ["upi","account","blocked","verify","refund","payment","bank","otp"]
    is_scam = any(k in text for k in scam_keywords)
    
    return {
        "scam_detected": is_scam,
        "agent_activated": is_scam,
        "message": "Honeypot active and ready." if not is_scam
                   else "Scam intent detected. Autonomous agent engaged."
    }