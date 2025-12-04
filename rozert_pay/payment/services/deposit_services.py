import base64
import contextlib
import io
import typing as ty
from typing import Any, Literal, overload
from uuid import UUID

import qrcode  # type: ignore[import-untyped]
from django.conf import settings
from django.db import transaction
from django.shortcuts import redirect
from django.urls import reverse
from PIL.Image import Image
from rest_framework.request import Request
from rest_framework.response import Response
from rozert_pay.common import const
from rozert_pay.common.const import TransactionExtraFields
from rozert_pay.payment import entities, types
from rozert_pay.payment.api_v1.serializers import InstructionSerializer
from rozert_pay.payment.services import db_services, event_logs, transaction_processing
from rozert_pay.payment.systems.base_controller import PaymentSystemController


@overload
def create_deposit_instruction(
    *,
    trx: "db_services.LockedTransaction",
    type: Literal[const.InstructionType.INSTRUCTION_FILE],
    link: str,
    save: bool = True,
) -> None:
    ...


@overload
def create_deposit_instruction(
    *,
    trx: "db_services.LockedTransaction",
    type: Literal[const.InstructionType.INSTRUCTION_QR_CODE],
    qr_code_payload: str | bytes,
    save: bool = True,
) -> None:
    ...


@overload
def create_deposit_instruction(
    *,
    trx: "db_services.LockedTransaction",
    type: Literal[const.InstructionType.INSTRUCTION_REFERENCE],
    reference: str,
    save: bool = True,
) -> None:
    ...


def create_deposit_instruction(
    *,
    trx: "db_services.LockedTransaction",
    type: const.InstructionType,
    link: str | None = None,
    qr_code_payload: str | bytes | None = None,
    reference: str | None = None,
    save: bool = True,
) -> None:
    serializer_data: dict[str, Any] = {
        "type": type,
    }
    if link:
        serializer_data["link"] = link

    if reference:
        serializer_data["reference"] = reference

    if qr_code_payload:
        image: Image = qrcode.make(qr_code_payload).get_image()
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        bytes = buf.getvalue()
        qr_code = base64.b64encode(bytes).decode("utf-8")
        serializer_data["qr_code"] = qr_code

    s = InstructionSerializer(data=serializer_data)
    s.is_valid(raise_exception=True)
    trx.instruction = s.validated_data

    if save:
        trx.save(update_fields=["instruction", "updated_at"])


class _Client(ty.Protocol):
    def deposit(self) -> entities.PaymentClientDepositResponse:
        ...


@contextlib.contextmanager
def initiate_deposit(
    client: _Client,
    trx_id: types.TransactionId,
    *,
    controller: PaymentSystemController[Any, Any],
    allow_immediate_fail: bool = False,
    schedule_check_immediately: bool = True,
) -> ty.Generator[
    tuple[entities.PaymentClientDepositResponse, "db_services.LockedTransaction"],
    None,
    None,
]:
    response = client.deposit()

    transaction_changed = False

    with transaction.atomic():
        locked_trx = db_services.get_transaction(trx_id=trx_id, for_update=True)

        if response.id_in_payment_system:
            if locked_trx.id_in_payment_system:
                assert response.id_in_payment_system == locked_trx.id_in_payment_system
            else:
                locked_trx.id_in_payment_system = response.id_in_payment_system

        if response.status == const.TransactionStatus.FAILED and allow_immediate_fail:
            assert response.decline_code
            controller.fail_transaction(
                locked_trx,
                decline_code=response.decline_code,
                decline_reason=response.decline_reason,
            )
            yield response, locked_trx
            return

        # Save redirect form
        if response.customer_redirect_form_data:
            locked_trx.form = response.customer_redirect_form_data
            transaction_changed = True

        locked_trx.save()
        transaction_processing.schedule_periodic_status_checks(
            trx=locked_trx,
            schedule_check_immediately=schedule_check_immediately,
        )

        if transaction_changed:
            controller.create_callback(
                trx_id=trx_id,
                callback_type=const.CallbackType.TRANSACTION_UPDATED,
            )

        yield response, locked_trx


def get_return_url(system: str, trx_id: str | UUID) -> str:
    s = reverse("redirect", args=[system])
    return f"{settings.EXTERNAL_ROZERT_HOST}{s}?transaction_id={trx_id}"


def handle_deposit_redirect(
    request: Request,
    controller: PaymentSystemController[ty.Any, ty.Any],
) -> Response:
    transaction_id = request.query_params["transaction_id"]

    with transaction.atomic():
        trx = db_services.get_transaction(
            for_update=True,
            trx_uuid=UUID(transaction_id),
        )
        trx.extra[TransactionExtraFields.REDIRECT_RECEIVED_DATA] = request.data
        trx.save(update_fields=["extra", "updated_at"])

    event_logs.create_transaction_log(
        trx_id=trx.id,
        event_type=const.EventType.CUSTOMER_REDIRECT_RECEIVED,
        description="Customer redirect received",
        extra={
            "request": request.data,
            "trx_uuid": trx.uuid,
        },
    )

    controller.run_deposit_finalization(
        trx_id=trx.id,
    )
    assert trx.redirect_url
    return ty.cast(Response, redirect(trx.redirect_url))
