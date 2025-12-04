from typing import Any, Generic, TypeVar

from django import forms
from rozert_pay.account.models import User
from rozert_pay.common import const
from rozert_pay.payment.entities import RemoteTransactionStatus
from rozert_pay.payment.factories import get_payment_system_controller
from rozert_pay.payment.models import PaymentTransaction
from rozert_pay.payment.services import errors, transaction_status_validation
from rozert_pay.payment.services.errors import Error


class SetTransactionForm(forms.Form):
    status = forms.ChoiceField(
        choices=const.TransactionStatus.choices,
    )
    comment = forms.CharField(
        widget=forms.Textarea,
        help_text="Comment for transaction status update",
    )
    approve = forms.BooleanField(
        help_text="Check this flag to perform transaction status update",
        initial=False,
        required=False,
    )

    def clean_approve(self) -> bool:
        if not self.cleaned_data.get("approve"):
            raise forms.ValidationError("Should be approved")
        return self.cleaned_data.get("approve", False)


T = TypeVar("T", bound=SetTransactionForm)


class BaseTransactionSetter(Generic[T]):
    form_cls: type[T]

    def __init__(self, transaction: PaymentTransaction, initiator: User):
        self.transaction = transaction
        self.initiator = initiator

    def get_form(self, data: dict[str, Any]) -> Error | T:
        if not self.initiator.has_perm(const.Permissions.CAN_SET_TRANSACTION_STATUS):
            return Error("You don't have permission to set transaction status")
        return self.form_cls(data=data)

    @errors.wrap_errors
    def save_form(self, data: dict[str, Any]) -> Error | T | None:
        if not self.initiator.has_perm(const.Permissions.CAN_SET_TRANSACTION_STATUS):
            return Error("You don't have permission to set transaction status")

        form = self.get_form(data)
        if isinstance(form, Error):
            return form

        if form.is_valid():
            if form.cleaned_data.get("approve"):
                controller = get_payment_system_controller(self.transaction.system)

                controller.create_log(
                    trx_id=self.transaction.id,
                    event_type=const.EventType.TRANSACTION_SET_STATUS,
                    description=f'Transaction actualized by {self.initiator.email} with comment: {form.cleaned_data["comment"]}',
                    extra={
                        "comment": form.cleaned_data["comment"],
                        "status": form.cleaned_data["status"],
                        "initiator": self.initiator.email,
                        "initiator_id": self.initiator.id,
                    },
                )

                controller.sync_remote_status_with_transaction(
                    trx_id=self.transaction.id,
                    remote_status=transaction_status_validation.bypass_validation(
                        RemoteTransactionStatus(
                            operation_status=form.cleaned_data["status"],
                            raw_data={},
                        )
                    ),
                    allow_transition_from_final_statuses=True,
                )
                return None
        return form


class DefaultTransactionSetter(BaseTransactionSetter[SetTransactionForm]):
    form_cls = SetTransactionForm


DEFAULT_TRANSACTION_SETTER = DefaultTransactionSetter
