from pathlib import Path

BASE_DIR = Path("/srv/uploads")

def read_user_file(filename: str) -> str:
    target = BASE_DIR / filename
    return target.read_text(encoding="utf-8")

