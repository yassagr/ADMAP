from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import httpx
import asyncio
from settings import settings
import structlog

router = APIRouter()
logger = structlog.get_logger()

MODULE_URLS = {
    "m1": settings.m1_url,
    "m2": settings.m2_url,
    "m3": settings.m3_url,
    "m4": settings.m4_url,
    "m5": settings.m5_url,
}

@router.websocket("/jobs/{job_id}")
async def job_status_ws(websocket: WebSocket, job_id: str, module: str):
    await websocket.accept()
    
    if module not in MODULE_URLS:
        await websocket.send_json({"error": "Invalid module"})
        await websocket.close()
        return

    target_url = MODULE_URLS[module]
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            while True:
                # Poll the microservice
                try:
                    res = await client.get(f"{target_url}/api/v1/jobs/{job_id}")
                    if res.status_code == 200:
                        data = res.json()
                        await websocket.send_json(data)
                        
                        status = data.get("status")
                        if status in ["completed", "failed", "cancelled"]:
                            break
                    else:
                        await websocket.send_json({"error": f"Upstream error {res.status_code}"})
                except httpx.RequestError as e:
                    logger.error(f"Error polling {module} for job {job_id}: {e}")
                    # Send error but keep polling for a bit
                
                await asyncio.sleep(1)
    except WebSocketDisconnect:
        logger.info(f"Client disconnected from WS for job {job_id}")
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass # Already closed
