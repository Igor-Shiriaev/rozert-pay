import random
import typing as ty

from rozert_pay.common import const
from rozert_pay.payment import tasks
from rozert_pay.payment.models import (
    IncomingCallback,
    PaymentSystem,
    PaymentTransaction,
)
from rozert_pay.payment.systems import base_controller


def imitate_callback(
    controller: "base_controller.PaymentSystemController[ty.Any, ty.Any]",
    body: str,
) -> None:
    system = PaymentSystem.objects.filter(type=controller.payment_system).last()
    assert system, "System not found"

    cb = IncomingCallback.objects.create(
        system=system,
        body=body,
        get_params={},
        ip="0.0.0.0",
        headers={"__MESSAGE__": "THIS IS NOT REAL CALLBACK!"},
    )
    tasks.handle_incoming_callback(cb.id, is_sandbox=True)


def approve_transaction(trx: PaymentTransaction) -> None:
    assert trx.is_sandbox
    tasks.sandbox_approve_transaction.apply_async(
        args=(trx.id,),
        countdown=trx.wallet.wallet.sandbox_finalization_delay_seconds,
    )


def get_random_id(type: const.PaymentSystemType) -> str:
    return f"sandbox:{type}:{random.randrange(10**9, 10**11)}"
