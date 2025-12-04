import json
import logging
from typing import Optional

from django.conf import settings
from slack_sdk import WebClient
from slack_sdk.errors import SlackClientError
from slack_sdk.web.slack_response import SlackResponse

logger = logging.getLogger(__name__)


class SlackClient:
    _client: Optional[WebClient]

    def __init__(self) -> None:
        if settings.SLACK_TOKEN:
            self._client = WebClient(token=settings.SLACK_TOKEN)
        else:
            self._client = None

    def send_message(self, channel: str, text: str) -> None:
        if not self._client:
            logger.warning(
                "SLACK_TOKEN not set, skipping Slack notification.",
                extra={"channel": channel},
            )
            return

        try:
            response: SlackResponse = self._client.chat_postMessage(
                channel=channel, text=text
            )
        except SlackClientError:  # pragma: no cover
            logger.exception("Failed to send Slack message", extra={"channel": channel})
            raise
        except Exception:  # pragma: no cover
            logger.exception(
                "Unexpected error sending Slack message", extra={"channel": channel}
            )
            raise
        response_data = (
            response.data
            if isinstance(response.data, dict)
            else json.loads(response.data)
        )
        if response.status_code != 200:
            logger.error(
                "Failed to send Slack message",
                extra={
                    "message_to_send": text,
                    "channel": channel,
                    "status_code": response.status_code,
                    "response": response_data,
                },
            )
            return
        logger.info(
            "Slack message sent successfully",
            extra={
                "message_to_send": text,
                "channel": channel,
                "response": response_data,
            },
        )
        return


slack_client = SlackClient()
