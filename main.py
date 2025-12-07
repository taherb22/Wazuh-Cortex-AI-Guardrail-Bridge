import os
import logging
import uvicorn
import requests
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel, ValidationError
from cortex4py.api import Api
from cortex4py.exceptions import CortexException
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load .env variables
load_dotenv()

# --- Configuration ---
CORTEX_URL = os.getenv("CORTEX_URL", "http://cortex:9001")
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "changeme")
GUARDRAIL_URL = os.getenv("GUARDRAIL_URL", "http://guardrail-agent:8080/validate")
PORT = int(os.getenv("PORT", 6000))

# Timeouts
CORTEX_TIMEOUT = int(os.getenv("CORTEX_TIMEOUT", 10))
GUARDRAIL_TIMEOUT = int(os.getenv("GUARDRAIL_TIMEOUT", 5))

app = FastAPI()

# Initialize Cortex
cortex_api = None
try:
    if CORTEX_URL and "http" in CORTEX_URL:
        cortex_api = Api(CORTEX_URL, CORTEX_API_KEY)
        logger.info(f"Cortex initialized successfully at {CORTEX_URL}")
    else:
        logger.warning("Cortex URL not configured - enrichment will be skipped")
except Exception as e:
    logger.error(f"Failed to initialize Cortex API: {e}", exc_info=True)
    cortex_api = None

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

# --- Cortex Enrichment Functions ---

def enrich_ip_with_virustotal(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Submit IP to VirusTotal via Cortex analyzer.
    Returns job info on success, None on failure.
    """
    if not cortex_api:
        logger.debug("Cortex API not available, skipping IP enrichment")
        return None
    
    try:
        job = cortex_api.analyzers.run_by_name(
            "VirusTotal_GetReport_3_0", 
            ip_address, 
            "ip", 
            tlp=2
        )
        logger.info(f"Submitted IP {ip_address} to VirusTotal (job_id: {job.id})")
        return {"type": "ip", "value": ip_address, "job_id": job.id}
    
    except CortexException as e:
        logger.error(f"Cortex API error for IP {ip_address}: {e}")
        return None
    except ConnectionError as e:
        logger.warning(f"Connection failed for IP {ip_address} enrichment: {e}")
        return None
    except ValueError as e:
        logger.error(f"Invalid IP address format '{ip_address}': {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error submitting IP {ip_address} to VirusTotal: {e}", exc_info=True)
        return None


def enrich_hash_with_virustotal(file_hash: str) -> Optional[Dict[str, Any]]:
    """
    Submit file hash to VirusTotal via Cortex analyzer.
    Returns job info on success, None on failure.
    """
    if not cortex_api:
        logger.debug("Cortex API not available, skipping hash enrichment")
        return None
    
    try:
        job = cortex_api.analyzers.run_by_name(
            "VirusTotal_GetReport_3_0", 
            file_hash, 
            "hash", 
            tlp=2
        )
        logger.info(f"Submitted hash {file_hash[:16]}... to VirusTotal (job_id: {job.id})")
        return {"type": "hash", "value": file_hash, "job_id": job.id}
    
    except CortexException as e:
        logger.error(f"Cortex API error for hash {file_hash[:16]}...: {e}")
        return None
    except ConnectionError as e:
        logger.warning(f"Connection failed for hash {file_hash[:16]}... enrichment: {e}")
        return None
    except ValueError as e:
        logger.error(f"Invalid hash format '{file_hash[:16]}...': {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error submitting hash {file_hash[:16]}... to VirusTotal: {e}", exc_info=True)
        return None


def gather_cortex_enrichment(alert: AlertInput) -> List[Dict[str, Any]]:
    """
    Gather all Cortex enrichment data for an alert.
    Returns list of successful job submissions.
    """
    cortex_context = []
    
    # Enrich IP
    if alert.host and alert.host.ip:
        ip_result = enrich_ip_with_virustotal(alert.host.ip)
        if ip_result:
            cortex_context.append(ip_result)
    
    # Enrich file hashes
    for artifact in alert.artifacts:
        if artifact.sha256:
            hash_result = enrich_hash_with_virustotal(artifact.sha256)
            if hash_result:
                cortex_context.append(hash_result)
    
    logger.info(f"Cortex enrichment completed: {len(cortex_context)} successful submissions")
    return cortex_context


def send_to_guardrail(payload: GuardrailPayload, alert_id: str) -> bool:
    """
    Send validated payload to Guardrail service.
    Returns True on success, False on failure.
    """
    try:
        json_data = payload.model_dump()
        logger.info(f"Forwarding alert {alert_id} to Guardrail at {GUARDRAIL_URL}")
        
        response = requests.post(
            GUARDRAIL_URL, 
            json=json_data, 
            timeout=GUARDRAIL_TIMEOUT
        )
        
        response.raise_for_status()
        logger.info(f"Guardrail accepted alert {alert_id} (status: {response.status_code})")
        return True
    
    except requests.exceptions.Timeout:
        logger.error(f"Timeout sending alert {alert_id} to Guardrail after {GUARDRAIL_TIMEOUT}s")
        return False
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection failed to Guardrail for alert {alert_id}: {e}")
        return False
    except requests.exceptions.HTTPError as e:
        logger.error(f"Guardrail rejected alert {alert_id}: {e.response.status_code} - {e.response.text}")
        return False
    except ValidationError as e:
        logger.error(f"Invalid payload format for alert {alert_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending alert {alert_id} to Guardrail: {e}", exc_info=True)
        return False


# --- Main Processing Logic ---

def process_alert(alert: AlertInput):
    """
    Main alert processing pipeline:
    1. Enrich with Cortex analyzers
    2. Build payload for Guardrail
    3. Send to Guardrail for validation
    """
    try:
        logger.info(f"Processing alert {alert.alert_id} (severity: {alert.severity})")
        
        # Step 1: Cortex Enrichment
        cortex_context = gather_cortex_enrichment(alert)
        
        # Step 2: Extract suggested actions
        actions_for_ai = [
            {"action_id": act.id, "description": act.label} 
            for act in alert.suggested_actions
        ]
        logger.debug(f"Extracted {len(actions_for_ai)} suggested actions for alert {alert.alert_id}")
        
        # Step 3: Build Guardrail payload
        payload = GuardrailPayload(
            input=alert.event.command_line, 
            context={
                "alert_id": alert.alert_id,
                "alert_summary": alert.summary,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "user": alert.actor.get("user", "unknown"),
                "host": alert.host.hostname,
                "cortex_jobs": cortex_context
            },
            candidates=actions_for_ai
        )
        
        # Step 4: Send to Guardrail
        success = send_to_guardrail(payload, alert.alert_id)
        
        if success:
            logger.info(f"Successfully processed alert {alert.alert_id}")
        else:
            logger.warning(f"Alert {alert.alert_id} processed with errors (check logs above)")
    
    except ValidationError as e:
        logger.error(f"Invalid alert data for {alert.alert_id}: {e}")
    except Exception as e:
        logger.error(f"Failed to process alert {alert.alert_id}: {e}", exc_info=True)


# --- API Endpoints ---

@app.post("/webhook/alert")
async def ingest(alert: AlertInput, background_tasks: BackgroundTasks):
    """
    Webhook endpoint to receive and process security alerts.
    Processing happens asynchronously in the background.
    """
    try:
        logger.info(f"Received alert {alert.alert_id} from {alert.source}")
        background_tasks.add_task(process_alert, alert)
        return {
            "status": "accepted",
            "message": f"Alert {alert.alert_id} queued for processing",
            "alert_id": alert.alert_id
        }
    except ValidationError as e:
        logger.error(f"Invalid alert payload: {e}")
        raise HTTPException(status_code=422, detail=f"Invalid alert format: {e}")
    except Exception as e:
        logger.error(f"Failed to queue alert: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    cortex_status = "connected" if cortex_api else "unavailable"
    return {
        "status": "healthy",
        "cortex": cortex_status,
        "guardrail_url": GUARDRAIL_URL
    }


if __name__ == "__main__":
    logger.info(f"Starting Alert Processor on port {PORT}")
    logger.info(f"Cortex: {'enabled' if cortex_api else 'disabled'}")
    logger.info(f"Guardrail: {GUARDRAIL_URL}")
    
    uvicorn.run(app, host="0.0.0.0", port=PORT)