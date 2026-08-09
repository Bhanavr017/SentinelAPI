import httpx

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.core.config import settings


router = APIRouter(
    prefix="/gateway",
    tags=["Security Gateway"],
)


HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


async def _gateway(
    path: str,
    request: Request,
):
    base = settings.UPSTREAM_BASE_URL.rstrip("/")
    target = f"{base}/{path}"

    if request.url.query:
        target += f"?{request.url.query}"

    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in HOP_BY_HOP
    }

    headers["X-Sentinel-Gateway"] = "SentinelAPI/2.0"

    try:
        body = await request.body()

        async with httpx.AsyncClient(
            timeout=settings.GATEWAY_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as client:
            upstream = await client.request(
                method=request.method,
                url=target,
                headers=headers,
                content=body,
            )

        response_headers = {
            key: value
            for key, value in upstream.headers.items()
            if key.lower() not in HOP_BY_HOP
        }

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=response_headers,
            media_type=upstream.headers.get("content-type"),
        )

    except httpx.TimeoutException:
        return JSONResponse(
            status_code=504,
            content={
                "detail": "Upstream API timeout",
                "upstream": settings.UPSTREAM_BASE_URL,
            },
        )

    except httpx.HTTPError as exc:
        return JSONResponse(
            status_code=502,
            content={
                "detail": "Upstream API unavailable",
                "error": str(exc),
            },
        )


@router.get(
    "/{path:path}",
    operation_id="gateway_get",
)
async def gateway_get(
    path: str,
    request: Request,
):
    return await _gateway(path, request)


@router.post(
    "/{path:path}",
    operation_id="gateway_post",
)
async def gateway_post(
    path: str,
    request: Request,
):
    return await _gateway(path, request)


@router.put(
    "/{path:path}",
    operation_id="gateway_put",
)
async def gateway_put(
    path: str,
    request: Request,
):
    return await _gateway(path, request)


@router.patch(
    "/{path:path}",
    operation_id="gateway_patch",
)
async def gateway_patch(
    path: str,
    request: Request,
):
    return await _gateway(path, request)


@router.delete(
    "/{path:path}",
    operation_id="gateway_delete",
)
async def gateway_delete(
    path: str,
    request: Request,
):
    return await _gateway(path, request)


@router.options(
    "/{path:path}",
    operation_id="gateway_options",
)
async def gateway_options(
    path: str,
    request: Request,
):
    return await _gateway(path, request)


@router.head(
    "/{path:path}",
    operation_id="gateway_head",
)
async def gateway_head(
    path: str,
    request: Request,
):
    return await _gateway(path, request)
