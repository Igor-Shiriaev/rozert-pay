import logging

import sentry_sdk
from django.apps import AppConfig
from django.conf import settings
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.logging import LoggingIntegration


class PaymentConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "rozert_pay.payment"

    def ready(self) -> None:
        import rozert_pay.payment.controller_registry  # noqa

        if settings.SENTRY_DSN:
            sentry_sdk.init(
                dsn=settings.SENTRY_DSN,
                integrations=[
                    DjangoIntegration(),
                    CeleryIntegration(),
                    LoggingIntegration(
                        level=logging.INFO,  # Capture info and above as breadcrumbs,
                        event_level=logging.ERROR,
                    ),
                ],
                traces_sample_rate=0,
                profiles_sample_rate=0,
                send_default_pii=True,
                environment="production" if settings.IS_PRODUCTION else "development",
            )
