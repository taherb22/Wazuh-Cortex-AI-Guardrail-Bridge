import os
import uvicorn
import requests
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from cortex4py.api import Api
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

# --- Configuration ---
CORTEX_URL = os.getenv("CORTEX_URL", "http://cortex:9001")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "changeme")
GUARDRAIL_URL = os.getenv("GUARDRAIL_URL", "http://guardrail-agent:8080/validate")
PORT = int(os.getenv("PORT", 6000))

app = FastAPI()

# Initialize Cortex
cortex_api = None
try:
    if CORTEX_URL and "http" in CORTEX_URL:
        cortex_api = Api(CORTEX_URL, CORTEX_API_KEY)
        print(f"[*] Cortex initialized at {CORTEX_URL}")
    else:
        print("[!] Cortex URL not configured.")
except Exception as e:
    print(f"[!] Warning: Cortex connection failed: {e}")

# --- Models ---
class HostInfo(BaseModel):
    id: str
    hostname: str
    ip: str
    os: Optional[str] = None

class Artifact(BaseModel):
    type: str
    sha256: Optional[str] = None
    path: Optional[str] = None
    url: Optional[str] = None

class SuggestedAction(BaseModel):
    id: str
    label: str

class AlertEvent(BaseModel):
    rule_id: Any 
    timestamp: Optional[str] = None
    process_name: Optional[str] = None
    command_line: str 
    parent_process: Optional[str] = None
    indicators: Optional[List[Dict[str, Any]]] = []

class AlertInput(BaseModel):
    alert_id: str
    received_at: str
    source: str
    type: str
    severity: str
    summary: str
    risk_score: Optional[int] = 0
    confidence: Optional[float] = 0.0
    host: HostInfo
    actor: Dict[str, Any]
    event: AlertEvent
    artifacts: List[Artifact] = []
    suggested_actions: List[SuggestedAction] = []

class GuardrailPayload(BaseModel):
    input: str
    task: str = "validate_action"
    context: Dict[str, Any]
    candidates: List[Dict[str, str]]

# --- Logic ---

def process_alert(alert: AlertInput):
    print(f"[*] Processing {alert.alert_id}...")
    cortex_context = []
    
    # 1. Cortex Analysis
    if cortex_api:
        # Check IP
        try:
            job = cortex_api.analyzers.run_by_name("VirusTotal_GetReport_3_0", alert.host.ip, "ip", tlp=2)
            cortex_context.append({"type": "ip", "value": alert.host.ip, "job_id": job.id})
        except Exception as e:
            # Only print error if it's NOT just a connection error (keep logs clean)
            pass 
        
        # Check Hash
        for art in alert.artifacts:
            if art.sha256:
                try:
                    job = cortex_api.analyzers.run_by_name("VirusTotal_GetReport_3_0", art.sha256, "hash", tlp=2)
                    cortex_context.append({"type": "hash", "value": art.sha256, "job_id": job.id})
                except Exception:
                    pass

    # 2. Extract Actions (Fixed .dict() -> .model_dump())
    actions_for_ai = [
        {"action_id": act.id, "description": act.label} 
        for act in alert.suggested_actions
    ]

    # 3. Prepare Payload
    payload = GuardrailPayload(
        input=alert.event.command_line, 
        context={
            "alert_summary": alert.summary,
            "severity": alert.severity,
            "user": alert.actor.get("user", "unknown"),
            "host": alert.host.hostname,
            "cortex_jobs": cortex_context
        },
        candidates=actions_for_ai
    )

    # 4. Send to Guardrail
    try:
        # Fixed warning: using model_dump() instead of dict()
        json_data = payload.model_dump()
        print(f"[*] Forwarding to Guardrail at {GUARDRAIL_URL}...")
        
        # ACTUAL SENDING IS ENABLED NOW
        response = requests.post(GUARDRAIL_URL, json=json_data, timeout=5)
        print(f"[*] Guardrail Response: {response.status_code}")
        
    except Exception as e:
        print(f"[!] Failed to contact Guardrail: {e}")

@app.post("/webhook/alert")
async def ingest(alert: AlertInput, background_tasks: BackgroundTasks):
    background_tasks.add_task(process_alert, alert)
    return {"status": "processing", "message": "Alert accepted"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)