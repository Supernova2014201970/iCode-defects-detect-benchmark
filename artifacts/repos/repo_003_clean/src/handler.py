from pathlib import Path

BASE_DIR = Path("/srv/uploads")


def read_user_file(filename: str) -> str:
    target = (BASE_DIR / filename).resolve()
    if BASE_DIR not in target.parents and target != BASE_DIR:
        raise ValueError("path escapes upload directory")
    return target.read_text(encoding="utf-8")

