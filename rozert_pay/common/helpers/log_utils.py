from django.utils import timezone


class LogWriter:
    def __init__(self) -> None:
        self.logs: list[str] = []

    def write(self, log: str) -> None:
        now = timezone.now().strftime("%H:%M:%S.%f")
        self.logs.append(f"{now}: {log}")

    def to_string(self) -> str:
        return "\n".join(self.logs)
