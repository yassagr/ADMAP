import httpx
from fastapi import Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import structlog
from settings import settings

logger = structlog.get_logger()

async def forward_request(request: Request, target_url: str) -> Response:
    """Forwards an incoming FastAPI request to a target URL."""
    # We must construct the new URL manually from target_url and the path
    # But since we use a catch-all route, we pass the full constructed URL to httpx.
    
    headers = dict(request.headers)
    # Remove host header so httpx uses the target host
    headers.pop("host", None)
    # Remove content-length as httpx will recalculate it
    headers.pop("content-length", None)
    
    method = request.method
    
    try:
        body = await request.body()
        async with httpx.AsyncClient(timeout=settings.proxy_timeout) as client:
            req = client.build_request(
                method=method,
                url=target_url,
                headers=headers,
                content=body,
                params=request.query_params
            )
            response = await client.send(req, stream=True)
            
            # Read the entire response for simplicity, or stream it.
            # We'll stream it to support large files/exports.
            async def generate():
                async for chunk in response.aiter_bytes():
                    yield chunk
                    
            response_headers = dict(response.headers)
            # Remove encoding-related headers that might conflict
            response_headers.pop("content-encoding", None)
            response_headers.pop("transfer-encoding", None)
            response_headers.pop("content-length", None)
            
            return StreamingResponse(
                generate(),
                status_code=response.status_code,
                headers=response_headers
            )
            
    except httpx.RequestError as exc:
        logger.error(f"Proxy error to {target_url}: {exc}")
        raise HTTPException(status_code=502, detail="Bad Gateway: Target service is unreachable.")
