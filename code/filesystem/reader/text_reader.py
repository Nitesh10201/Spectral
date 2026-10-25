from pathlib import Path


def read_text_file(path: str | Path) -> str:
    """Read a log, text or JSON file and return its content as text."""
    path = Path(path)
    with open(path, mode="r", encoding="utf-8") as f:
        return f.read()


read_text = read_text_file
