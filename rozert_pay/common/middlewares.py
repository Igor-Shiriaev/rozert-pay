import logging
import time
from typing import Callable

from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)


class LogResponseMiddleware:
    def __init__(self, get_response: Callable) -> None:  # type: ignore[type-arg]
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        logfunc = logger.debug
        if 200 <= response.status_code < 300:
            logfunc = logger.debug
        elif 300 <= response.status_code < 400:
            logfunc = logger.debug
        elif 400 <= response.status_code < 500:
            logfunc = logger.warning
        elif 500 <= response.status_code:
            logfunc = logger.error

        if 400 <= response.status_code < 500:
            logfunc(
                f"4xx response on url {request.build_absolute_uri()} with status code {response.status_code}",
                extra={
                    "status_code": response.status_code,
                    "url": request.build_absolute_uri(),
                    "response": response.content,
                },
            )

        return response
