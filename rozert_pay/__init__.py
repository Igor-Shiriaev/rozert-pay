import os


def get_secrets_value(
    key: str, default: str = "", base_path: str = "/etc/secrets"
) -> str:
    try:
        with open(os.path.join(base_path, key)) as file:
            return file.read().strip()
    except (FileExistsError, FileNotFoundError):
        return default
