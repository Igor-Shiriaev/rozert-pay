import logging
import typing as ty
from typing import Any

from django import forms
from rozert_pay.account.models import User
from rozert_pay.common import const
from rozert_pay.payment import entities
from rozert_pay.payment.entities import RemoteTransactionStatus
from rozert_pay.payment.factories import get_payment_system_controller
from rozert_pay.payment.models import PaymentTransaction
from rozert_pay.payment.services import transaction_status_validation
from rozert_pay.payment.services.errors import Error, wrap_errors

logger = logging.getLogger(__name__)


class TransactionActualizationForm(forms.Form):
    transaction: PaymentTransaction

    remote_status = forms.JSONField()

    # Need to check this flag to perform transaction status synchronization
    actualize = forms.BooleanField(
        help_text="Check this flag to perform transaction status synchronization",
        initial=False,
        required=False,
    )

    def __init__(self, trx: PaymentTransaction, data: dict[str, ty.Any] | None = None):
        super().__init__(data=data)
        self.transaction = trx

        self.fields["remote_status"].widget.attrs["readonly"] = True


TForm = ty.TypeVar("TForm", bound=TransactionActualizationForm)


class BaseTransactionActualizer(ty.Generic[TForm]):
    form_cls: ty.Type[TForm]

    def __init__(self, transaction: PaymentTransaction, operation_user: User):
        self.transaction = transaction
        self.operation_user = operation_user

    def get_remote_status(
        self,
        transaction: PaymentTransaction,
        data: dict[str, ty.Any],
    ) -> Error | entities.RemoteTransactionStatus:
        controller = get_payment_system_controller(transaction.system)
        if not controller:
            return Error(
                f"Payment system controller not found for system {transaction.system}"
            )
        client = controller.get_client(transaction)
        return client.get_transaction_status()

    @wrap_errors
    def get_form(self, data: dict[str, Any]) -> TForm | Error:
        remote_status = self.get_remote_status(self.transaction, data)
        if isinstance(remote_status, Error):
            return remote_status

        remote_status_json = remote_status.model_dump_json(indent=2)
        return self.form_cls(
            trx=self.transaction,
            data={
                **data,
                "remote_status": remote_status_json,
            },
        )

    @wrap_errors
    def save_form(self, form: TForm, initiator: User) -> TForm | Error | None:
        if form.is_valid():
            if form.cleaned_data.get("actualize"):
                remote_status = RemoteTransactionStatus(
                    **form.cleaned_data["remote_status"]
                )
                controller = get_payment_system_controller(self.transaction.system)
                if not controller:
                    return Error(
                        f"Payment system controller not found for system {self.transaction.system}"
                    )

                controller.create_log(
                    trx_id=self.transaction.id,
                    event_type=const.EventType.TRANSACTION_ACTUALIZATION,
                    extra={
                        "initiator": initiator.email,
                        "initiator_id": initiator.id,
                        "remote_status": remote_status.model_dump(),
                    },
                    description=f"Transaction actualized by {initiator.email} with remote status {remote_status.operation_status}",
                )
                controller.sync_remote_status_with_transaction(
                    trx_id=self.transaction.id,
                    remote_status=transaction_status_validation.bypass_validation(
                        remote_status,
                    ),
                    allow_transition_from_final_statuses=True,
                )
                return None
        return form


class TransactionActualizer(BaseTransactionActualizer[TransactionActualizationForm]):
    form_cls = TransactionActualizationForm


DEFAULT_ACTUALIZER_CLS = TransactionActualizer
