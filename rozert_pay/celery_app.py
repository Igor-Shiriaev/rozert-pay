import logging
import os

from celery import Celery
from celery.schedules import crontab
from celery.signals import (
    after_task_publish,
    setup_logging,
)
from kombu import Queue  # type: ignore[import]
from rozert_pay.common.const import CeleryQueue

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rozert_pay.settings")

app = Celery("rozert_pay")
app.conf.task_queues = [Queue(q) for q in CeleryQueue]

app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


# periodic tasks
app.conf.beat_schedule = {
    "check_pending_transaction_status": {
        "task": "rozert_pay.payment.tasks.check_pending_transaction_status",
        "schedule": crontab(minute="*/1"),
    },
    # Сommented before release just in case
    # "cleanup_duplicate_event_logs": {
    #     "task": "rozert_pay.payment.tasks.cleanup_duplicate_logs",
    #     "schedule": crontab(minute="0", hour="*/2"),
    #     "kwargs": {"is_dry_run": False},
    # },
}


logger = logging.getLogger(__name__)


@setup_logging.connect
def disable_celery_logging(**kwargs):  # type: ignore[no-untyped-def] # pragma: no cover
    pass


@after_task_publish.connect
def after_task_publish_handler(**kwargs):  # type: ignore[no-untyped-def] # pragma: no cover
    logger.info(
        "published celery task",
        extra={
            "routing": kwargs.get("routing_key"),
            "sender": kwargs.get("sender"),
            "body": str(kwargs.get("body")),
        },
    )
