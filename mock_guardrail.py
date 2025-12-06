import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List, Any

app = FastAPI()

# Matches the payload sent by main.py
class GuardrailPayload(BaseModel):
    input: str
    task: str
    context: Dict[str, Any]
    candidates: List[Dict[str, str]]

@app.post("/validate")
def validate(payload: GuardrailPayload):
    print(f"\n[MOCK GUARDRAIL] Received Alert!")
    print(f" > Command: {payload.input}")
    print(f" > Candidates: {payload.candidates}")
    print(f" > Cortex Context: {len(payload.context.get('cortex_jobs', []))} jobs found.")
    
    # Fake a successful response
    return {
        "status": "success", 
        "ai_decision": "valid", 
        "reason": "Mock Guardrail says this is fine."
    }

if __name__ == "__main__":
    # Listen on port 8080
    uvicorn.run(app, host="0.0.0.0", port=8080)