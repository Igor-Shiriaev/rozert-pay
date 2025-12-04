import logging
import time
import typing as ty
from typing import Any

import requests
from django.db import transaction
from rozert_pay.common import const
from rozert_pay.payment.models import PaymentTransactionEventLog
from rozert_pay.payment.services.context import current_context

logger = logging.getLogger(__name__)


class _OnRequest:
    def __call__(self, request: dict[str, ty.Any]) -> str:
        raise NotImplementedError


class _OnResponse:
    def __call__(
        self,
        *,
        request_id: str,
        response: requests.Response | None,
        error: Exception | None,
        duration: float,
        response_parsers: list[ty.Callable[[str], dict[str, ty.Any]]] | None = None,
    ) -> None:
        raise NotImplementedError


class PaymentTransactionEventLogOnRequest(_OnRequest):
    def __init__(self, trx_id: int) -> None:
        self.trx_id = trx_id

    def __call__(self, request: dict[str, ty.Any]) -> str:
        return str(
            PaymentTransactionEventLog.objects.create(
                transaction_id=self.trx_id,
                incoming_callback_id=current_context().get("incoming_callback_id"),
                event_type=const.EventType.EXTERNAL_API_REQUEST,
                description=f"{request['method']} {request['url']}",
                extra={
                    "request": request,
                },
            ).id
        )


def _parse_response(
    response: requests.Response | None,
    response_parsers: list[ty.Callable[[str], dict[str, ty.Any]]] | None = None,
) -> dict[str, Any] | None:
    json_response = None
    if response is not None:
        try:
            json_response = response.json()
        except Exception:
            for p in response_parsers or []:
                try:
                    json_response = p(response.text)
                    break
                except Exception:
                    pass
            else:
                if len(response.text) > 1000:
                    j = response.text[:1000] + "..."
                else:
                    j = response.text
                json_response = {"__non_json_response__": j}

    return json_response


class PaymentTransactionEventLogOnResponse(_OnResponse):
    def __init__(self, trx_id: int) -> None:
        self.trx_id = trx_id

    def __call__(
        self,
        *,
        request_id: str,
        response: requests.Response | None,
        error: Exception | None,
        duration: float,
        response_parsers: list[ty.Callable[[str], dict[str, ty.Any]]] | None = None,
    ) -> None:
        with transaction.atomic():
            log = PaymentTransactionEventLog.objects.select_for_update().get(
                id=request_id
            )
            json_response = _parse_response(response, response_parsers)

            log.extra = {
                **log.extra,
                "response": {
                    "status_code": response.status_code,
                    "text": json_response,
                }
                if response is not None
                else None,
                "error": {
                    "cls": error.__class__.__name__,
                    "message": str(error),
                    "data": str(error.__dict__),
                }
                if error
                else None,
                "duration": duration,
            }
            log.save(update_fields=["extra", "updated_at"])


class ExternalApiSession(requests.Session):
    response_parsers: list[ty.Callable[[str], dict[str, ty.Any]]]
    on_request_parser: ty.Callable[[str], dict[str, ty.Any]] | None

    def __init__(
        self,
        on_request: _OnRequest,
        on_response: _OnResponse,
        timeout: float = 10,
    ):
        super().__init__()
        self.timeout = timeout
        self.on_request = on_request
        self.on_response = on_response

        self.response_parsers = []
        self.on_request_parser = None

    if not ty.TYPE_CHECKING:

        def request(self, *args, **kwargs):
            kwargs.setdefault("timeout", self.timeout)

            if method := kwargs.get("method"):
                pass
            else:
                method = args[0]

            if url := kwargs.get("url"):
                pass
            else:
                url = args[1]

            logger.info(
                "sending request to external API",
                extra={
                    "method": method,
                    "url": url,
                },
            )
            start = time.time()

            request_data = None
            if r := kwargs.get("json"):
                request_data = r
            elif r := kwargs.get("data"):
                if self.on_request_parser:
                    try:
                        r = self.on_request_parser(r)
                    except Exception:
                        pass
                request_data = r

            request_id = self.on_request(
                dict(
                    method=method,
                    url=url,
                    headers=kwargs.get("headers"),
                    data=request_data,
                )
            )

            resp = error = None
            try:
                resp = super().request(*args, **kwargs)
            except Exception as e:
                error = e
                raise
            finally:
                self.on_response(
                    request_id=request_id,
                    response=resp,
                    error=error,
                    duration=time.time() - start,
                    response_parsers=self.response_parsers,
                )

            duration = time.time() - start

            json_response = _parse_response(
                resp, response_parsers=self.response_parsers
            )

            if not resp.ok:
                f = logger.warning
                msg = f"external API response is not ok: {resp.request.url} {resp.status_code}"
            else:
                msg = "external API response ok"
                f = logger.info

            f(
                msg,
                extra={
                    "status_code": resp.status_code,
                    "response": json_response,
                    "duration": duration,
                    "request": {
                        "method": method,
                        "url": url,
                        "headers": kwargs.get("headers"),
                        "data": kwargs.get("data") or kwargs.get("json"),
                    },
                },
            )
            return resp


def get_external_api_session(
    *,
    trx_id: int,
    timeout: float = 10,
) -> ExternalApiSession:
    return ExternalApiSession(
        on_request=PaymentTransactionEventLogOnRequest(trx_id),
        on_response=PaymentTransactionEventLogOnResponse(trx_id),
        timeout=timeout,
    )
