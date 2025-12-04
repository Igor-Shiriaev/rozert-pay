from uuid import UUID

from django.conf import settings
from django.urls import reverse
from rozert_pay.payment.models import PaymentSystem


def get_rozert_callback_url(
    system: PaymentSystem,
    trx_uuid: str | UUID | None = None,
) -> str:
    payment_system_slug = system.slug
    url = reverse("callback", kwargs=dict(system=payment_system_slug))
    result = f"{settings.EXTERNAL_ROZERT_HOST}{url}"
    if trx_uuid:
        result = f"{result}?transaction_uuid={trx_uuid}"

    return result
