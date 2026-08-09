from fastapi import APIRouter, Request


router = APIRouter(
    prefix="/protected",
    tags=["Protected Demo API"],
)


async def _protected_echo(request: Request):
    body = await request.body()

    return {
        "status": "accepted",
        "message": "Request reached the protected API",
        "method": request.method,
        "path": request.url.path,
        "query": request.url.query,
        "body_length": len(body),
    }


@router.get(
    "/echo",
    operation_id="protected_echo_get",
)
async def protected_echo_get(
    request: Request,
):
    return await _protected_echo(request)


@router.post(
    "/echo",
    operation_id="protected_echo_post",
)
async def protected_echo_post(
    request: Request,
):
    return await _protected_echo(request)


@router.put(
    "/echo",
    operation_id="protected_echo_put",
)
async def protected_echo_put(
    request: Request,
):
    return await _protected_echo(request)


@router.patch(
    "/echo",
    operation_id="protected_echo_patch",
)
async def protected_echo_patch(
    request: Request,
):
    return await _protected_echo(request)


@router.delete(
    "/echo",
    operation_id="protected_echo_delete",
)
async def protected_echo_delete(
    request: Request,
):
    return await _protected_echo(request)
