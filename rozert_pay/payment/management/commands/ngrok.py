import re
import subprocess as su
import threading
import time
from argparse import ArgumentParser
from queue import Empty, Queue
from typing import Any

from django.core.management import BaseCommand
from django.urls import reverse
from rozert_pay.common.helpers.log_utils import LogWriter
from rozert_pay.payment import models
from rozert_pay.payment.factories import get_payment_system_controller

process: su.Popen[Any] | None = None
output_queue = Queue[Any]()


class NgrokThread(threading.Thread):
    def run(self) -> None:
        global process
        try:
            process = su.Popen(
                "ngrok http 8006 --log=stdout",
                shell=True,
                stdout=su.PIPE,
                stderr=su.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            while True:
                if process.stdout:
                    line = process.stdout.readline()
                    if line:
                        output_queue.put(line.strip())
                time.sleep(0.1)
        except Exception as e:
            print(f"Error in ngrok thread: {e}")  # noqa
            output_queue.put(f"Error: {e}")


class Command(BaseCommand):
    external_host: str

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("system", type=str)

    def run_ngrok_and_fill_external_host(self) -> None:
        thread = NgrokThread()
        thread.daemon = True
        thread.start()

        start = time.time()
        while time.time() - start < 10:
            try:
                line = output_queue.get_nowait()
                print(line)  # noqa

                # Ищем URL в строке
                url_match = re.search(r'url=(https://[^\s"]+)', line)
                if url_match:
                    self.external_host = url_match.group(1)
                    return
            except Empty:
                time.sleep(0.1)

        raise RuntimeError("Failed to find URL!")

    def handle(self, *args: Any, **options: Any) -> None:
        system: str = options["system"]

        try:
            self._handle(system)
        finally:
            su.call("pkill -f ngrok", shell=True)

    def _handle(self, system: str) -> None:
        self.run_ngrok_and_fill_external_host()
        print("External host:", self.external_host)  # noqa
        print("Update webhooks for system", system)  # noqa

        self._handle_wallets(system, create_new=True)

        print("All wallets updated!")  # noqa
        print(  # noqa
            "Ngrok is runned, you can do testing. Stop this script when you finish."
        )
        try:
            while True:
                try:
                    line = output_queue.get_nowait()
                    print(line)  # noqa
                except Empty:
                    time.sleep(0.1)
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            self._handle_wallets(system, create_new=False)

    def _handle_wallets(self, system: str, create_new: bool) -> None:
        for w in models.Wallet.objects.filter(
            system__type=system,
            merchant__sandbox=False,
        ):
            print("Set webhook for wallet", w)  # noqa

            controller = get_payment_system_controller(w.system)
            writer = LogWriter()
            creds = controller.client_cls.get_credentials_from_dict(w.credentials)
            controller.client_cls.remove_webhooks(
                re.compile("ngrok-free.app"), creds=creds, log_writer=writer
            )

            if create_new:
                controller.client_cls.create_webhooks(
                    urls=[
                        f'{self.external_host}{reverse("callback", kwargs=dict(system=system))}'
                    ],
                    creds=creds,
                    log_writer=writer,
                )
            print(writer.to_string())  # noqa
