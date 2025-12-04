from __future__ import annotations

import typing as ty

import pydantic
from rozert_pay.common import const

if ty.TYPE_CHECKING:  # pragma: no cover
    from rozert_pay.payment.models import PaymentSystem
    from rozert_pay.payment.services import base_classes
    from rozert_pay.payment.systems import base_controller


def get_payment_system_controller(
    db_system: PaymentSystem,
) -> "base_controller.PaymentSystemController[base_classes.BasePaymentClient[pydantic.BaseModel], base_classes.BaseSandboxClientMixin[pydantic.BaseModel]]":
    from rozert_pay.payment import controller_registry

    cfg = controller_registry.PAYMENT_SYSTEMS[db_system.type]
    return cfg["controller"]


def get_payment_system_controller_by_type(
    type: const.PaymentSystemType,
) -> "base_controller.PaymentSystemController[base_classes.BasePaymentClient[pydantic.BaseModel], base_classes.BaseSandboxClientMixin[pydantic.BaseModel]]":
    from rozert_pay.payment import controller_registry

    cfg = controller_registry.PAYMENT_SYSTEMS[type]
    return cfg["controller"]
