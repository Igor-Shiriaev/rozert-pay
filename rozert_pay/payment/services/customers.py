import json

from rozert_pay.payment import models, types
from rozert_pay.payment.entities import UserData


def get_or_create_customer(
    external_identity: types.ExternalCustomerId,
    user_data: UserData | None = None,
) -> models.Customer:
    assert external_identity

    customer, _ = models.Customer.objects.get_or_create(
        external_id=external_identity,
    )
    user_data_history = customer.extra.get("user_data_history", [])
    if user_data:
        d = json.loads(user_data.model_dump_json())
        if d not in user_data_history:
            user_data_history.append(d)

        customer.extra["user_data_history"] = user_data_history

        if user_data.email:
            customer.email = user_data.email

        if user_data.phone:
            customer.phone = user_data.phone

        if user_data.language:
            customer.language = user_data.language

        customer.save()

    return customer
