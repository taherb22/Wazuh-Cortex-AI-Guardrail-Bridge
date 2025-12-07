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
CORTEX_API_KEY = os.getenv("CORTEX_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GUARDRAIL_URL = os.getenv("GUARDRAIL_URL", "http://guardrail-agent:8080/validate")
PORT = int(os.getenv("PORT", 6000))

# Timeouts
CORTEX_TIMEOUT = int(os.getenv("CORTEX_TIMEOUT", 10))
GUARDRAIL_TIMEOUT = int(os.getenv("GUARDRAIL_TIMEOUT", 5))
VIRUSTOTAL_TIMEOUT = int(os.getenv("VIRUSTOTAL_TIMEOUT", 10))

app = FastAPI()

# Initialize Cortex (Optional)
cortex_api = None
cortex_enabled = False
if CORTEX_URL and CORTEX_API_KEY and "http" in CORTEX_URL:
    try:
        cortex_api = Api(CORTEX_URL, CORTEX_API_KEY)
        cortex_enabled = True
        logger.info(f"Cortex initialized successfully at {CORTEX_URL}")
    except Exception as e:
        logger.warning(f"Cortex initialization failed: {e}. Will use direct API calls only.")
else:
    logger.info("Cortex not configured - using direct API enrichment only")

# Check VirusTotal configuration
vt_enabled = bool(VIRUSTOTAL_API_KEY)
if vt_enabled:
    logger.info("VirusTotal direct API enabled")
else:
    logger.warning("VirusTotal API key not configured")

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

# --- VirusTotal Direct API Functions ---

def enrich_ip_with_virustotal_api(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Get IP reputation from VirusTotal API v3 directly.
    Returns enrichment data on success, None on failure.
    """
    if not vt_enabled:
        logger.debug("VirusTotal API key not configured, skipping IP enrichment")
        return None
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=VIRUSTOTAL_TIMEOUT)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract key reputation metrics
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        enrichment = {
            "source": "virustotal_api",
            "type": "ip",
            "value": ip_address,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation", 0),
            "country": attributes.get("country", "unknown"),
            "as_owner": attributes.get("as_owner", "unknown")
        }
        
        logger.info(f"VirusTotal API: IP {ip_address} - {stats.get('malicious', 0)} malicious detections")
        return enrichment
    
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.info(f"IP {ip_address} not found in VirusTotal")
        elif e.response.status_code == 429:
            logger.warning(f"VirusTotal API rate limit exceeded for IP {ip_address}")
        else:
            logger.error(f"VirusTotal API error for IP {ip_address}: {e.response.status_code}")
        return None
    except requests.exceptions.Timeout:
        logger.warning(f"VirusTotal API timeout for IP {ip_address}")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"Connection failed to VirusTotal for IP {ip_address}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error enriching IP {ip_address} with VirusTotal: {e}", exc_info=True)
        return None


def enrich_hash_with_virustotal_api(file_hash: str) -> Optional[Dict[str, Any]]:
    """
    Get file hash reputation from VirusTotal API v3 directly.
    Returns enrichment data on success, None on failure.
    """
    if not vt_enabled:
        logger.debug("VirusTotal API key not configured, skipping hash enrichment")
        return None
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=VIRUSTOTAL_TIMEOUT)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract key reputation metrics
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        enrichment = {
            "source": "virustotal_api",
            "type": "hash",
            "value": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "file_type": attributes.get("type_description", "unknown"),
            "size": attributes.get("size", 0),
            "names": attributes.get("names", [])[:3]  # First 3 known filenames
        }
        
        logger.info(f"VirusTotal API: Hash {file_hash[:16]}... - {stats.get('malicious', 0)} malicious detections")
        return enrichment
    
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.info(f"Hash {file_hash[:16]}... not found in VirusTotal")
        elif e.response.status_code == 429:
            logger.warning(f"VirusTotal API rate limit exceeded for hash {file_hash[:16]}...")
        else:
            logger.error(f"VirusTotal API error for hash {file_hash[:16]}...: {e.response.status_code}")
        return None
    except requests.exceptions.Timeout:
        logger.warning(f"VirusTotal API timeout for hash {file_hash[:16]}...")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"Connection failed to VirusTotal for hash {file_hash[:16]}...: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error enriching hash {file_hash[:16]}... with VirusTotal: {e}", exc_info=True)
        return None


# --- Cortex Analyzer Functions ---

def enrich_ip_with_cortex(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Submit IP to VirusTotal via Cortex analyzer.
    Returns job info on success, None on failure.
    """
    if not cortex_enabled:
        logger.debug("Cortex not available, skipping Cortex IP enrichment")
        return None
    
    try:
        # Cortex4py correct syntax: run_by_name(analyzer_name, observable_dict)
        job = cortex_api.analyzers.run_by_name(
            "VirusTotal_GetReport_3_0",
            {
                "data": ip_address,
                "dataType": "ip",
                "tlp": 2
            }
        )
        logger.info(f"Cortex: Submitted IP {ip_address} to VirusTotal (job_id: {job.id})")
        return {
            "source": "cortex",
            "type": "ip",
            "value": ip_address,
            "job_id": job.id,
            "analyzer": "VirusTotal_GetReport_3_0"
        }
    
    except CortexException as e:
        logger.error(f"Cortex API error for IP {ip_address}: {e}")
        return None
    except ConnectionError as e:
        logger.warning(f"Cortex connection failed for IP {ip_address}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected Cortex error for IP {ip_address}: {e}", exc_info=True)
        return None


def enrich_hash_with_cortex(file_hash: str) -> Optional[Dict[str, Any]]:
    """
    Submit file hash to VirusTotal via Cortex analyzer.
    Returns job info on success, None on failure.
    """
    if not cortex_enabled:
        logger.debug("Cortex not available, skipping Cortex hash enrichment")
        return None
    
    try:
        # Cortex4py correct syntax: run_by_name(analyzer_name, observable_dict)
        job = cortex_api.analyzers.run_by_name(
            "VirusTotal_GetReport_3_0",
            {
                "data": file_hash,
                "dataType": "hash",
                "tlp": 2
            }
        )
        logger.info(f"Cortex: Submitted hash {file_hash[:16]}... to VirusTotal (job_id: {job.id})")
        return {
            "source": "cortex",
            "type": "hash",
            "value": file_hash,
            "job_id": job.id,
            "analyzer": "VirusTotal_GetReport_3_0"
        }
    
    except CortexException as e:
        logger.error(f"Cortex API error for hash {file_hash[:16]}...: {e}")
        return None
    except ConnectionError as e:
        logger.warning(f"Cortex connection failed for hash {file_hash[:16]}...: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected Cortex error for hash {file_hash[:16]}...: {e}", exc_info=True)
        return None


# --- Combined Enrichment Orchestration ---

def gather_all_enrichment(alert: AlertInput) -> Dict[str, List[Dict[str, Any]]]:
    """
    Gather enrichment from BOTH VirusTotal API and Cortex independently.
    Returns dict with separate lists for each source.
    """
    enrichment = {
        "virustotal_api": [],
        "cortex": []
    }
    
    # Enrich IP with both sources
    if alert.host and alert.host.ip:
        # Try VirusTotal API
        vt_ip = enrich_ip_with_virustotal_api(alert.host.ip)
        if vt_ip:
            enrichment["virustotal_api"].append(vt_ip)
        
        # Try Cortex (independent)
        cortex_ip = enrich_ip_with_cortex(alert.host.ip)
        if cortex_ip:
            enrichment["cortex"].append(cortex_ip)
    
    # Enrich file hashes with both sources
    for artifact in alert.artifacts:
        if artifact.sha256:
            # Try VirusTotal API
            vt_hash = enrich_hash_with_virustotal_api(artifact.sha256)
            if vt_hash:
                enrichment["virustotal_api"].append(vt_hash)
            
            # Try Cortex (independent)
            cortex_hash = enrich_hash_with_cortex(artifact.sha256)
            if cortex_hash:
                enrichment["cortex"].append(cortex_hash)
    
    vt_count = len(enrichment["virustotal_api"])
    cortex_count = len(enrichment["cortex"])
    logger.info(f"Enrichment completed: {vt_count} from VirusTotal API, {cortex_count} from Cortex")
    
    return enrichment


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
    1. Enrich with BOTH VirusTotal API and Cortex (independent)
    2. Build payload for Guardrail
    3. Send to Guardrail for validation
    """
    try:
        logger.info(f"Processing alert {alert.alert_id} (severity: {alert.severity})")
        
        # Step 1: Gather enrichment from all sources
        enrichment = gather_all_enrichment(alert)
        
        # Step 2: Extract suggested actions
        actions_for_ai = [
            {"action_id": act.id, "description": act.label} 
            for act in alert.suggested_actions
        ]
        logger.debug(f"Extracted {len(actions_for_ai)} suggested actions for alert {alert.alert_id}")
        
        # Step 3: Build Guardrail payload with enrichment from both sources
        payload = GuardrailPayload(
            input=alert.event.command_line, 
            context={
                "alert_id": alert.alert_id,
                "alert_summary": alert.summary,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "user": alert.actor.get("user", "unknown"),
                "host": alert.host.hostname,
                "enrichment": enrichment  # Contains both VT API and Cortex data
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
    return {
        "status": "healthy",
        "enrichment": {
            "virustotal_api": "enabled" if vt_enabled else "disabled",
            "cortex": "enabled" if cortex_enabled else "disabled"
        },
        "guardrail_url": GUARDRAIL_URL
    }


if __name__ == "__main__":
    logger.info(f"Starting Alert Processor on port {PORT}")
    logger.info(f"VirusTotal Direct API: {'enabled' if vt_enabled else 'disabled'}")
    logger.info(f"Cortex: {'enabled' if cortex_enabled else 'disabled'}")
    logger.info(f"Guardrail: {GUARDRAIL_URL}")
    
    uvicorn.run(app, host="0.0.0.0", port=PORT)