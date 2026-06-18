import httpx
from fastapi import Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import structlog

from ..settings import get_settings

logger = structlog.get_logger()


async def forward_request(request: Request, target_url: str) -> Response:
    """Forward an incoming FastAPI request to a target microservice URL.

    The httpx client and the streamed upstream response are kept open for the
    entire lifetime of the StreamingResponse: they are closed only once the
    response body generator is fully consumed (or the connection drops). Closing
    them eagerly via `async with` would break every proxied response, because
    the generator is iterated by Starlette *after* `forward_request` returns.
    """
    headers = dict(request.headers)
    # Remove host header so httpx uses the target host
    headers.pop("host", None)
    # Remove content-length as httpx will recalculate it
    headers.pop("content-length", None)

    body = await request.body()

    client = httpx.AsyncClient(timeout=get_settings().proxy_timeout)
    try:
        req = client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
            params=request.query_params,
        )
        upstream = await client.send(req, stream=True)
    except httpx.RequestError as exc:
        await client.aclose()
        logger.error("proxy_error", target_url=target_url, error=str(exc))
        raise HTTPException(
            status_code=502,
            detail="Bad Gateway: Target service is unreachable.",
        )

    async def stream_body():
        try:
            async for chunk in upstream.aiter_bytes():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()

    response_headers = dict(upstream.headers)
    # Remove encoding-related headers that might conflict with re-streaming
    response_headers.pop("content-encoding", None)
    response_headers.pop("transfer-encoding", None)
    response_headers.pop("content-length", None)

    return StreamingResponse(
        stream_body(),
        status_code=upstream.status_code,
        headers=response_headers,
    )
