import sqlite3
from code.config import EVIDENCE_DIR
from code.filesystem.reader.sql_reader import load_sql_file, read_sql_file
from pathlib import Path


def test_read_sql_file_from_dataset():
    sql_files = list((EVIDENCE_DIR / "databases").glob("*.sql"))
    assert len(sql_files) > 0, "No SQL files found in evidence directory"
    target_file = sql_files[0]

    conn = read_sql_file(target_file)
    assert isinstance(conn, sqlite3.Connection)
    cursor = conn.cursor()
    tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    assert len(tables) > 0
    conn.close()


def test_read_sql_file_with_temp_script(tmp_path: Path):
    sql_file = tmp_path / "test_snapshot.sql"
    sql_file.write_text(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
        INSERT INTO users (id, email) VALUES (1, 'alice@example.com');
        INSERT INTO users (id, email) VALUES (2, 'bob@example.com');
        """,
        encoding="utf-8",
    )
    conn = load_sql_file(sql_file)
    cursor = conn.cursor()
    rows = cursor.execute("SELECT id, email FROM users ORDER BY id;").fetchall()
    assert rows == [(1, "alice@example.com"), (2, "bob@example.com")]
    conn.close()
