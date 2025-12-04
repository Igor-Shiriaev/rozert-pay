import logging
import typing as ty
from typing import Any, final

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import connection
from django.utils.functional import cached_property
from rozert_pay.common.helpers import string_utils
from rozert_pay.common.helpers.log_utils import LogWriter
from rozert_pay.payment import entities, models
from rozert_pay.payment.entities import RemoteTransactionStatus
from rozert_pay.payment.models import PaymentTransaction
from rozert_pay.payment.services import db_services, errors
from rozert_pay.payment.services.external_api_services import (
    ExternalApiSession,
    PaymentTransactionEventLogOnRequest,
    PaymentTransactionEventLogOnResponse,
)
from rozert_pay.payment.tasks import sandbox_approve_transaction
from rozert_pay.payment.types import T_Credentials

logger = logging.getLogger(__name__)


class BasePaymentClient(ty.Generic[T_Credentials]):
    credentials_cls: ty.Type[T_Credentials]

    @classmethod
    def parse_and_validate_credentials(
        cls, credentials: dict[str, ty.Any]
    ) -> T_Credentials:
        try:
            return cls.credentials_cls(**credentials)
        except Exception as e:
            raise ValidationError(f"Error parsing credentials: {e}")

    @classmethod
    def get_credentials(cls, trx: PaymentTransaction) -> T_Credentials:
        return cls.get_credentials_from_dict(trx.wallet.wallet.credentials)

    @classmethod
    def get_credentials_from_dict(cls, data: dict[str, Any]) -> T_Credentials:
        return cls.parse_and_validate_credentials(data)

    @cached_property
    def trx(self) -> PaymentTransaction:
        return db_services.get_transaction(trx_id=self.trx_id, for_update=False)

    @cached_property
    def creds(self) -> T_Credentials:
        return self.parse_and_validate_credentials(self.trx.wallet.wallet.credentials)

    def __init__(self, trx_id: int, timeout: float = 10) -> None:
        self.trx_id = trx_id
        self.session = ExternalApiSession(
            on_request=PaymentTransactionEventLogOnRequest(trx_id),
            on_response=PaymentTransactionEventLogOnResponse(trx_id),
            timeout=timeout,
        )

        self._post_init()

    def _post_init(self) -> None:
        pass

    @final
    def get_transaction_status(self) -> RemoteTransactionStatus | errors.Error:
        if not settings.IS_UNITTESTS:
            assert not connection.in_atomic_block, "This method should not be called in transaction"

        try:
            return self._get_transaction_status()
        except Exception as e:
            logger.exception("Error getting transaction status")
            return errors.Error(f"Error getting transaction status: {e}")

    def _get_transaction_status(self) -> RemoteTransactionStatus:
        raise NotImplementedError

    def withdraw(self) -> entities.PaymentClientWithdrawResponse:
        """
        Ask payment system to withdraw money to user's bank account
        """
        raise NotImplementedError

    def deposit(self) -> entities.PaymentClientDepositResponse:  # pragma: no cover
        raise NotImplementedError

    def deposit_finalize(
        self,
    ) -> entities.PaymentClientDepositFinalizeResponse:  # pragma: no cover
        """
        Finalize deposit transaction.
        """
        raise NotImplementedError

    @classmethod
    def remove_webhooks(
        cls,
        urls_: ty.Union[str, ty.Pattern[str], list[str | ty.Pattern[str]]],
        creds: T_Credentials,
        log_writer: LogWriter,
    ) -> None:
        if not isinstance(urls_, list):
            urls = [urls_]
        else:
            urls = urls_

        for w in cls.get_webhooks(creds):
            if string_utils.string_matches(w.url, urls):
                cls._remove_webhook(w.id, creds)
                log_writer.write(f"Removed webhook {w.url}")

    @classmethod
    def create_webhooks(
        cls, urls: list[str], creds: T_Credentials, log_writer: LogWriter
    ) -> None:
        for url in urls:
            result = cls._create_webhook(url, creds)
            if result:
                log_writer.write(f"Created webhook {url} with id {result.id}")

    @classmethod
    def _remove_webhook(cls, webhook_id: str, creds: T_Credentials) -> None:
        raise NotImplementedError

    @classmethod
    def _create_webhook(cls, url: str, creds: T_Credentials) -> entities.Webhook | None:
        raise NotImplementedError

    @classmethod
    def get_webhooks(cls, creds: T_Credentials) -> list[entities.Webhook]:
        raise NotImplementedError


class BaseSandboxClientMixin(BasePaymentClient[T_Credentials]):
    def post_deposit_request(self) -> None:
        sandbox_approve_transaction.apply_async(
            args=(self.trx_id,),
            countdown=self.trx.wallet.wallet.sandbox_finalization_delay_seconds,
        )

    @classmethod
    def post_create_instruction(
        cls,
        customer_instruction: "models.CustomerDepositInstruction",
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    def post_withdraw_request(self) -> None:
        sandbox_approve_transaction.apply_async(
            args=(self.trx_id,),
            countdown=self.trx.wallet.wallet.sandbox_finalization_delay_seconds,
        )
