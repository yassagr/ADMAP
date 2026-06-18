import httpx
import asyncio
import time
from fastapi import APIRouter

from ..settings import get_settings

router = APIRouter()


async def fetch_health(client: httpx.AsyncClient, name: str, url: str) -> dict:
    try:
        response = await client.get(f"{url}/health", timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            return {
                "name": name,
                "status": "ok",
                "version": data.get("version", "unknown"),
                "queue_size": data.get("queue_size", 0),
                "last_checked": int(time.time() * 1000),
            }
        return {
            "name": name,
            "status": "error",
            "last_checked": int(time.time() * 1000),
        }
    except Exception:
        return {
            "name": name,
            "status": "unknown",
            "last_checked": int(time.time() * 1000),
        }


@router.get("/status")
async def get_all_status():
    settings = get_settings()
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            fetch_health(client, "m1", settings.m1_url),
            fetch_health(client, "m2", settings.m2_url),
            fetch_health(client, "m3", settings.m3_url),
            fetch_health(client, "m4", settings.m4_url),
            fetch_health(client, "m5", settings.m5_url),
        )
    return {res["name"]: res for res in results}
