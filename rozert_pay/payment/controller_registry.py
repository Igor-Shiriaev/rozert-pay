from typing import Any, TypedDict

from rozert_pay.common import const
from rozert_pay.payment.systems.base_controller import PaymentSystemController

from rozert_pay.payment.systems.d24_mercadopago.controller import (
    d24_mercadopago_controller,
)

_V = TypedDict(
    "_V",
    {
        "name": str,
        "controller": PaymentSystemController[Any, Any],
    },
)


PAYMENT_SYSTEMS: dict[const.PaymentSystemType, _V] = {
    const.PaymentSystemType.D24_MERCADOPAGO: {
        "name": "D24 MercadoPago",
        "controller": d24_mercadopago_controller,
    },
}
