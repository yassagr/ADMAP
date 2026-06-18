from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import httpx
import asyncio
import structlog

from ..settings import get_settings

router = APIRouter()
logger = structlog.get_logger()


@router.websocket("/jobs/{job_id}")
async def job_status_ws(websocket: WebSocket, job_id: str, module: str):
    await websocket.accept()

    settings = get_settings()
    module_urls = {
        "m1": settings.m1_url,
        "m2": settings.m2_url,
        "m3": settings.m3_url,
        "m4": settings.m4_url,
        "m5": settings.m5_url,
    }

    if module not in module_urls:
        await websocket.send_json({"error": "Invalid module"})
        await websocket.close()
        return

    target_url = module_urls[module]

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
                        await websocket.send_json(
                            {"error": f"Upstream error {res.status_code}"}
                        )
                except httpx.RequestError as e:
                    logger.error(
                        "ws_poll_error", module=module, job_id=job_id, error=str(e)
                    )
                    # Send error but keep polling for a bit

                await asyncio.sleep(1)
    except WebSocketDisconnect:
        logger.info("ws_client_disconnected", job_id=job_id)
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass  # Already closed
