import sqlite3
from pathlib import Path


def read_sql_file(path: str | Path) -> sqlite3.Connection:
    """Load a .sql file into an in-memory SQLite database and return the connection."""
    path = Path(path)
    with open(path, mode="r", encoding="utf-8") as f:
        sql_content = f.read()

    conn = sqlite3.connect(":memory:")
    conn.executescript(sql_content)
    return conn


load_sql_file = read_sql_file
