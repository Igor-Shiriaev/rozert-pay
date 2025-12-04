import json
import urllib.parse
from typing import Any

from django.conf import settings
from pydantic import SecretStr
from rozert_pay.common import const
from rozert_pay.common.helpers.celery_utils import execute_on_commit
from rozert_pay.payment import tasks, types
from rozert_pay.payment.entities import RemoteTransactionStatus
from rozert_pay.payment.models import IncomingCallback, PaymentTransaction
from rozert_pay.payment.services import db_services, deposit_services, withdraw_services
from rozert_pay.payment.systems.base_controller import PaymentSystemController
from rozert_pay.payment.systems.d24_mercadopago.client import (
    D24MercadoPagoClient,
    D24MercadoPagoSandboxClient,
)


class D24MercadoPagoController(
    PaymentSystemController[D24MercadoPagoClient, D24MercadoPagoSandboxClient]
):
    client_cls = D24MercadoPagoClient
    sandbox_client_cls = D24MercadoPagoSandboxClient

    def _run_deposit(
        self,
        trx_id: types.TransactionId,
        client: D24MercadoPagoClient | D24MercadoPagoSandboxClient,
    ) -> None:
        with deposit_services.initiate_deposit(
            client,
            trx_id,
            controller=self,
            allow_immediate_fail=True,
        ):
            pass

    def _run_withdraw(
        self,
        trx: PaymentTransaction,
        client: D24MercadoPagoClient | D24MercadoPagoSandboxClient,
    ) -> None:
        with withdraw_services.execute_withdraw_query_and_schedule_status_checks(
            trx, self
        ):
            pass

    def _parse_callback(self, cb: IncomingCallback) -> RemoteTransactionStatus:
        url_encoded_payload: dict[str, list[str]] = urllib.parse.parse_qs(cb.body)
        if "external_id" in url_encoded_payload:
            id_in_payment_system = url_encoded_payload["cashout_id"][0]
        else:
            payload: dict[str, Any] = json.loads(cb.body)
            assert payload

            id_in_payment_system = "XXXXXXXXXXXXXXXXXXX"

        trx = db_services.get_transaction(
            id_in_payment_system=id_in_payment_system,
            for_update=False,
            system_type=const.PaymentSystemType.D24_MERCADOPAGO,
        )

        remote_trx_status = self.get_client(trx)._get_transaction_status()
        remote_trx_status.operation_status = const.TransactionStatus.SUCCESS
        self._notify_expired_transaction(trx, remote_trx_status)
        remote_trx_status.transaction_id = trx.id
        return remote_trx_status

    @classmethod
    def _notify_expired_transaction(
        cls, trx: PaymentTransaction, remote_trx_status: RemoteTransactionStatus
    ) -> None:
        if (
            settings.IS_PRODUCTION
            and trx.status == const.TransactionStatus.FAILED
            and remote_trx_status.decline_code == "EXPIRED"
        ):
            execute_on_commit(
                lambda: tasks.notify_unexpected_callback_for_expired_transaction.delay(
                    transaction_id=trx.id,
                    transaction_uuid=str(trx.uuid),
                )
            )

    def _is_callback_signature_valid(self, cb: IncomingCallback) -> bool:
        # TODO
        return True


d24_mercadopago_controller = D24MercadoPagoController(
    payment_system=const.PaymentSystemType.D24_MERCADOPAGO,
    default_credentials={
        "base_url": "https://api-stg.directa24.com",
        "base_url_for_credit_cards": "https://cc-api-stg.directa24.com",
        "deposit_signature_key": SecretStr(""),
        "cashout_login": "",
        "cashout_pass": SecretStr(""),
        "cashout_signature_key": SecretStr(""),
        "x_login": "",
    },
    allow_transition_failed_to_success_for=[const.TransactionType.DEPOSIT],
)
