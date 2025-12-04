#!/usr/bin/env python3
"""
Usage:
fab prod run:"cp ../bank_bins/bins.json.zip backend-cronjob-7b6c7d4c78-c8vvc:/www/back/back"
fab prod run:"cp ../bank_bins/bins_updater.py backend-cronjob-7b6c7d4c78-c8vvc:/www/back/back/betmaster/management/commands"
nohup python3 manage.py bins_updater &>/dev/null &
jobs
"""
from argparse import ArgumentParser
from typing import Any

import ijson  # type: ignore[import-untyped]
from django.core.management import BaseCommand
from rozert_pay.payment.models import Bank, PaymentCardBank


class Command(BaseCommand):
    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--path")

    def handle(self, **options: Any) -> None:
        path = options.get("path", "bins.json")

        self.stdout.write(f"Try to open file: {path}")
        with open(path, "rb") as file:
            self.stdout.write("File is opened")
            # Row example:
            # {"213100": {"br": 11, "bn": "Jcb Co., Ltd.", "cc": "JP"}}
            # {"<bin>": {"br": <card type>, "bn": "<bank name>", "cc": "country"}}
            counter = 0
            self.stdout.write("Starting to update bins")
            for bin, bin_data in ijson.kvitems(file, ""):
                bank, _ = Bank.objects.get_or_create(name=bin_data["bn"])
                PaymentCardBank.objects.update_or_create(
                    bin=bin,
                    defaults={
                        "bank_id": bank.pk,
                        "card_type": bin_data["br"],
                        "card_class": bin_data["type"],
                        "country": bin_data["cc"],
                        "is_virtual": bin_data["virtual"],
                        "is_prepaid": bin_data["prepaid"],
                        "raw_category": bin_data["raw_category"],
                    },
                )
                counter += 1
                if counter == 100 or counter % 10000 == 0:
                    self.stdout.write(self.style.NOTICE(f"Processed {counter} bins"))

        self.stdout.write(
            self.style.SUCCESS(f"{counter} BINs were updated successfully")
        )
