from decimal import Decimal
import hashlib
import hmac
import json
import logging
from typing import Any, Literal, Optional, cast
from urllib.parse import urlparse
from uuid import uuid4

import requests
from django.utils import timezone
from rozert_pay.common import const
from rozert_pay.common.const import TransactionType
from rozert_pay.payment import entities
from rozert_pay.payment.entities import Money, RemoteTransactionStatus
from rozert_pay.payment.services import incoming_callbacks, sandbox_services
from rozert_pay.payment.services.base_classes import (
    BasePaymentClient,
    BaseSandboxClientMixin,
)
from rozert_pay.payment.systems.d24_mercadopago.constants import (
    DEPOSIT_DETAILS_BY_ERROR_CODE,
)
from rozert_pay.payment.systems.d24_mercadopago.entities import D24Credentials

logger = logging.getLogger(__name__)


class D24MercadoPagoClient(BasePaymentClient[D24Credentials]):
    PAYMENT_METHOD = "ME"
    credentials_cls = D24Credentials

    _deposit_status_by_foreign_status = {
        "CREATED": entities.TransactionStatus.PENDING,
        "INITIATED": entities.TransactionStatus.PENDING,
        "EARLY_RELEASE": entities.TransactionStatus.PENDING,
        "PENDING": entities.TransactionStatus.PENDING,
        "FOR_REVIEW": entities.TransactionStatus.PENDING,
        "EXPIRED": entities.TransactionStatus.FAILED,
        "CANCELLED": entities.TransactionStatus.FAILED,
        "REJECTED": entities.TransactionStatus.FAILED,
        "APPROVED": entities.TransactionStatus.PENDING,
        "COMPLETED": entities.TransactionStatus.SUCCESS,
    }
    _withdrawal_status_by_foreign_status = {
        0: entities.TransactionStatus.PENDING,
        1: entities.TransactionStatus.SUCCESS,
        2: entities.TransactionStatus.FAILED,
        3: entities.TransactionStatus.FAILED,
    }

    def deposit(self) -> entities.PaymentClientDepositResponse:
        assert self.trx.user_data
        assert self.trx.redirect_url, "Redirect URL is required"
        assert self.trx.extra.get("mexican_curp"), "Mexican CURP is required"
        assert self.trx.currency == "MXN", "Currency must be MXN"

        payload = {
            "country": self.trx.user_data.country,
            "amount": str(self.trx.amount),
            "currency": self.trx.currency,
            "invoice_id": self.trx.uuid.hex,
            "payment_method": self.PAYMENT_METHOD,
            "payer": {
                "id": uuid4().hex,
                "document": self.trx.extra["mexican_curp"],
                "document_type": "CURP",
                "email": self.trx.user_data.email,
                "first_name": self.trx.user_data.first_name,
                "last_name": self.trx.user_data.last_name,
            },
            "description": self.trx.uuid.hex,
            "back_url": self.trx.redirect_url,
            "success_url": self.trx.redirect_url,
            "error_url": self.trx.redirect_url,
            "notification_url": incoming_callbacks.get_rozert_callback_url(
                system=self.trx.system,
                trx_uuid=self.trx.uuid,
            ),
        }

        response = self._make_request(
            method="post",
            url_with_path=f"{self.creds.base_url}/v3/deposits",
            headers=self._get_deposit_request_headers(json.dumps(payload)),
            payload=payload,
        )
        if response.get("redirect_url"):
            assert response["payment_info"]["payment_method"] == self.PAYMENT_METHOD

            return entities.PaymentClientDepositResponse(
                status=entities.TransactionStatus.PENDING,
                raw_response=response,
                id_in_payment_system=str(response["deposit_id"]),
                customer_redirect_form_data={
                    "action_url": response["redirect_url"],
                    "method": "get",
                },
            )

        return entities.PaymentClientDepositResponse(
            status=entities.TransactionStatus.FAILED,
            raw_response=response,
            decline_code=str(response.get("code")),
            decline_reason=response.get("description"),
        )

    def withdraw(self) -> entities.PaymentClientWithdrawResponse:
        assert self.trx.user_data
        assert self.trx.user_data.country
        assert self.trx.user_data.first_name
        assert self.trx.user_data.last_name
        assert (
            self.trx.customer_external_account
            and self.trx.customer_external_account.unique_account_number
        )

        self.trx.extra = cast(dict[str, Any], self.trx.extra)

        payload = {
            "login": self.creds.cashout_login,
            "pass": self.creds.cashout_pass.get_secret_value(),
            "external_id": self.trx.uuid.hex,
            "country": self.trx.user_data.country,
            "amount": str(self.trx.amount),
            "currency": self.trx.currency,
            "document_id": self.trx.extra["mexican_curp"],
            "document_type": "CURP",
            "bank_account": self.trx.customer_external_account.unique_account_number,
            "beneficiary_name": self.trx.user_data.first_name,
            "beneficiary_lastname": self.trx.user_data.last_name,
            "notification_url": incoming_callbacks.get_rozert_callback_url(
                system=self.trx.system,
                trx_uuid=self.trx.uuid,
            ),
        }
        response = self._make_request(
            method="post",
            url_with_path=f"{self.creds.base_url}/v3/cashout",
            payload=payload,
            headers=self._get_withdrawal_request_headers(json.dumps(payload)),
        )

        if id_in_payment_system := response.get("cashout_id"):
            return entities.PaymentClientWithdrawResponse(
                status=entities.TransactionStatus.PENDING,
                raw_response=response,
                id_in_payment_system=str(id_in_payment_system),
            )

        decline_reason = response["message"]
        if reason := response.get("reason"):
            decline_reason = f"{decline_reason}. {reason}"

        return entities.PaymentClientWithdrawResponse(
            status=entities.TransactionStatus.FAILED,
            id_in_payment_system=None,
            raw_response=response,
            decline_code=str(response["code"]),
            decline_reason=decline_reason,
        )

    def _get_transaction_status(self) -> RemoteTransactionStatus:
        if self.trx.type == TransactionType.DEPOSIT:
            return self._get_deposit_status()
        elif self.trx.type == TransactionType.WITHDRAWAL:
            return self._get_withdrawal_status()
        else:
            raise ValueError(f"Unknown transaction type: {self.trx.type}")

    def _get_deposit_status(self) -> RemoteTransactionStatus:
        response: dict[str, Any] = self._make_request_for_getting_status(
            method="get",
            url_with_path=f"{self.creds.base_url}/v3/deposits/{self.trx.id_in_payment_system}",
            headers=self._get_deposit_request_headers(payload=""),
        )
        # MercadoPago response example:
        # {
        #     "user_id": "62dd744c-cbfa-4357-8ef0-460390e78b5c",
        #     "deposit_id": 301543858,
        #     "invoice_id": "postmanTest645265357",
        #     "country": "MX",
        #     "currency": "MXN",
        #     "usd_amount": 4.90,
        #     "local_amount": 100.00,
        #     "payment_method": "ME",
        #     "payment_type": "VOUCHER",
        #     "status": "PENDING",
        #     "payer": {
        #         "document": "ssss001230mlllllj0",
        #         "document_type": "CURP",
        #         "email": "test0@example.com",
        #         "first_name": "John",
        #         "last_name": "Doe"
        #     },
        #     "fee_amount": 0.24,
        #     "fee_currency": "USD",
        #     "refunded": false,
        #     "current_payer_verification": "NO_CURRENT_PAYER_DATA"
        # }

        decline_code: Optional[str] = None
        decline_reason: Optional[str] = None

        if "code" in response:
            decline_code = response["code"]
            decline_reason = response.get("description") or response.get("message")
            return RemoteTransactionStatus(
                operation_status=entities.TransactionStatus.FAILED,
                raw_data=response,
                decline_code=decline_code,
                decline_reason=decline_reason,
            )

        status = self._deposit_status_by_foreign_status.get(
            response["status"],
            entities.TransactionStatus.PENDING,
        )

        if status == entities.TransactionStatus.FAILED:
            decline_code = response["status"]
            decline_reason = DEPOSIT_DETAILS_BY_ERROR_CODE[response["status"]]

        return RemoteTransactionStatus(
            operation_status=status,
            raw_data=response,
            id_in_payment_system=str(response["deposit_id"]),
            decline_code=str(decline_code),
            decline_reason=decline_reason,
            remote_amount=Money(Decimal(response["local_amount"]), response["currency"]),
        )

    def _get_withdrawal_status(self) -> RemoteTransactionStatus:
        data = {
            "login": self.creds.cashout_login,
            "pass": self.creds.cashout_pass.get_secret_value(),
            "external_id": str(self.trx.uuid),
            "cashout_id": self.trx.id_in_payment_system,
        }

        response: dict[str, Any] = self._make_request(
            method="post",
            url_with_path=f"{self.creds.base_url}/v3/cashout/status",
            headers=self._get_withdrawal_request_headers(json.dumps(data)),
            payload=data,
        )
        if not_found_remote_trx_status := self._handle_remote_transaction_not_found(
            response
        ):
            return not_found_remote_trx_status

        # MercadoPago response example:
        # {
        #     "cashout_status": 0,
        #     "cashout_status_description": "Pending"
        # }
        status = self._withdrawal_status_by_foreign_status.get(
            response["cashout_status"],
            entities.TransactionStatus.PENDING,
        )
        if status == entities.TransactionStatus.FAILED:
            decline_code: Optional[str] = str(response.get("rejection_code")) or str(
                response["code"]
            )

            decline_reason = response.get("rejection_reason") or response.get("message")
            if reason := response.get("reason"):
                decline_reason = f"{decline_reason}. {reason}"
        else:
            decline_code = None
            decline_reason = None

        return RemoteTransactionStatus(
            operation_status=status,
            raw_data=response,
            id_in_payment_system=self.trx.id_in_payment_system,
            decline_code=str(decline_code),
            decline_reason=decline_reason,
            remote_amount=Money(abs(self.trx.amount), self.trx.currency),
        )

    def _get_deposit_request_headers(self, payload):
        x_date = f"{timezone.now().isoformat()[:19]}Z"
        sig = hmac.new(
            self.creds.deposit_signature_key.get_secret_value().encode(),
            f"{x_date}{self.creds.x_login}{payload}".encode("utf8"),
            digestmod=hashlib.sha256,
        )
        return {
            "X-Date": x_date,
            "X-Login": self.creds.x_login,
            "Authorization": f"D24 {sig.hexdigest()}",
        }

    def _get_withdrawal_request_headers(self, json_str: str) -> dict[str, str]:
        sig = hmac.new(
            self.creds.cashout_signature_key.get_secret_value().encode(),
            json_str.encode("utf8"),
            digestmod=hashlib.sha256,
        )
        return {"Payload-Signature": sig.hexdigest()}

    def _make_request(
        self,
        method: Literal["get", "post"],
        url_with_path: str,
        headers: dict[str, str],
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            getattr(self.session, method)(
                url=url_with_path,
                json=payload,
                headers=headers,
            )
        except requests.exceptions.ConnectionError:
            return get_deposit_response(payload["amount"], payload["currency"])
        except Exception:
            logger.critical("Error making request to D24")
            return get_deposit_response(payload["amount"], payload["currency"])

    def _make_request_for_getting_status(
        self,
        method: Literal["get", "post"],
        url_with_path: str,
        headers: dict[str, str],
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            getattr(self.session, method)(
                url=url_with_path,
                json=payload,
                headers=headers,
            )
        except requests.exceptions.ConnectionError:
            return get_status_response(self.trx.id_in_payment_system)
        except Exception:
            logger.critical("Error making request to D24")
            return get_status_response(self.trx.id_in_payment_system)

    def _handle_remote_transaction_not_found(
        self,
        response: dict[str, Any],
    ) -> RemoteTransactionStatus | None:
        if "code" in response and response["code"] == 509:
            return RemoteTransactionStatus(
                operation_status=entities.TransactionStatus.FAILED,
                raw_data=response,
                decline_code=const.TransactionDeclineCodes.TRANSACTION_NOT_FOUND,
                decline_reason=response.get("message"),
                remote_amount=Money(abs(self.trx.amount), self.trx.currency),
            )
        return None


class D24MercadoPagoSandboxClient(
    D24MercadoPagoClient, BaseSandboxClientMixin[D24Credentials]
):
    credentials_cls = D24Credentials

    def _make_request(
        self,
        method: Literal["get", "post"],
        url_with_path: str,
        headers: dict[str, str],
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        path = urlparse(url_with_path).path
        match path:
            case "/v3/deposits":
                payload = cast(dict[str, Any], payload)
                return {
                    "checkout_type": "ONE_SHOT",
                    "redirect_url": "https://payment-stg.depositcheckout.com/v1/checkout/eyJhbGciOiJIUzM4NCJ9.eyJqdGkiOiI1NzE4MjMzMiIsImlhdCI6MTc0MDIxMjM1MCwiZXhwIjoxNzQxNTA4MzUwLCJsYW5ndWFnZSI6ImVzIn0.ucf2BY2jZY9brgZdj4tRvI_1cwSgOOcCaRdWezOmvA5wnb7bAU-HgNTg_KTtcfPl/MX/ME/3541/19502",
                    "iframe": True,
                    "deposit_id": sandbox_services.get_random_id(
                        const.PaymentSystemType.D24_MERCADOPAGO
                    ),
                    "user_id": "62dd744c-cbfa-4357-8ef0-460390e78b5c",
                    "merchant_invoice_id": "postmanTest907958248",
                    "payment_info": {
                        "type": "VOUCHER",
                        "payment_method": "ME",
                        "payment_method_name": "Mercado Pago Mexico",
                        "amount": payload["amount"],
                        "currency": payload["currency"],
                        "expiration_date": "2025-02-22 20:19:10",
                        "created_at": "2025-02-22 08:19:10",
                        "metadata": {
                            "reference": "57182332",
                            "payment_method_code": "ME",
                            "enabled_redirect": True,
                        },
                    },
                }
            case "/v3/cashout":
                return {
                    "cashout_id": sandbox_services.get_random_id(
                        const.PaymentSystemType.D24_MERCADOPAGO
                    ),
                }
            case "/v3/cashout/status":
                return {
                    "cashout_status": 1,
                }
            case _:  # pragma: no cover
                raise RuntimeError


def get_deposit_response(amount: float, currency: str) -> dict[str, Any]:
    return {
        "checkout_type": "ONE_SHOT",
        "redirect_url": "https://payment-stg.depositcheckout.com/v1/checkout/eyJhbGciOiJIUzM4NCJ9.eyJqdGkiOiI1NzE4MjMzMiIsImlhdCI6MTc0MDIxMjM1MCwiZXhwIjoxNzQxNTA4MzUwLCJsYW5ndWFnZSI6ImVzIn0.ucf2BY2jZY9brgZdj4tRvI_1cwSgOOcCaRdWezOmvA5wnb7bAU-HgNTg_KTtcfPl/MX/ME/3541/19502",
        "iframe": True,
        "deposit_id": sandbox_services.get_random_id(
            const.PaymentSystemType.D24_MERCADOPAGO
        ),
        "user_id": "62dd744c-cbfa-4357-8ef0-460390e78b5c",
        "merchant_invoice_id": "postmanTest907958248",
        "payment_info": {
            "type": "VOUCHER",
            "payment_method": "ME",
            "payment_method_name": "Mercado Pago Mexico",
            "amount": amount,
            "currency": currency,
            "expiration_date": "2025-02-22 20:19:10",
            "created_at": "2025-02-22 08:19:10",
            "metadata": {
                "reference": "57182332",
                "payment_method_code": "ME",
                "enabled_redirect": True,
            },
        },
    }


def get_status_response(deposit_id: str) -> dict[str, Any]:
    return {
        "user_id": "62dd744c-cbfa-4357-8ef0-460390e78b5c",
        "deposit_id": deposit_id,
        "invoice_id": "postmanTest531641621",
        "country": "MX",
        "currency": "MXN",
        "usd_amount": 4.84,
        "local_amount": "2333.71",
        "payment_method": "ME",
        "payment_type": "VOUCHER",
        "status": "PENDING",
        "payer": {
            "document": "ssss001230mlllllj0",
            "document_type": "CURP",
            "email": "test0@example.com",
            "first_name": "John",
            "last_name": "Doe",
        },
        "fee_amount": 0.24,
        "fee_currency": "USD",
        "refunded": False,
        "current_payer_verification": "NO_CURRENT_PAYER_DATA",
        "completed_payment_method_code": "ME",
    }
