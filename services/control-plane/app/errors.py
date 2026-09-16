"""One error shape for every service: {"error": <code>, "message": <sentence>, ...}.

`error` is a stable machine code a test can assert on. `message` is for the
person reading it - section 8, Day 18: every denial carries a human-readable
reason.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(self, status: int, error: str, message: str, **extra):
        super().__init__(message)
        self.status, self.error, self.message, self.extra = status, error, message, extra


def install(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, e: ApiError):
        return JSONResponse(
            status_code=e.status, content={"error": e.error, "message": e.message, **e.extra}
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, e: RequestValidationError):
        problems = [
            f"{'.'.join(str(p) for p in err['loc'][1:])}: {err['msg']}" for err in e.errors()
        ]
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "message": "; ".join(problems)},
        )
