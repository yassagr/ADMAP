from fastapi import APIRouter, HTTPException, File, UploadFile, Form
from typing import Optional

router = APIRouter()

@router.post("/full")
async def execute_full_pipeline(
    m1_file: UploadFile = File(...),
    m2_pcap: UploadFile = File(...),
    enable_m3: bool = Form(False),
    m3_malware: list[UploadFile] = File(None),
    m3_benign: list[UploadFile] = File(None),
    top_k: int = Form(3)
):
    """
    Orchestrates the full pipeline.
    Due to the complexity of a truly async orchestrated pipeline which spans multiple 
    microservices and pollings, we return an initial job tracking ID, or simply
    instruct the frontend to orchestrate via step-by-step UI state.
    
    For now, this is a placeholder that returns dummy tracking IDs, and the
    frontend will actually orchestrate the calls step-by-step for better UX/progress tracking.
    """
    return {
        "status": "pipeline_started",
        "message": "Full pipeline orchestration is handled by the frontend for real-time progress.",
        "jobs": {}
    }
