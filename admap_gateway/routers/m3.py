from fastapi import APIRouter, Request
from settings import settings
from .proxy_utils import forward_request

router = APIRouter()

@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy_m3(request: Request, path: str):
    target_url = f"{settings.m3_url}/{path}"
    return await forward_request(request, target_url)
