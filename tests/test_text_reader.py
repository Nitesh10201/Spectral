from code.config import EVIDENCE_DIR
from code.filesystem.reader.text_reader import read_text, read_text_file
from pathlib import Path


def test_read_text_file_log():
    log_files = list((EVIDENCE_DIR / "logs").glob("*.log"))
    assert len(log_files) > 0, "No log files found"
    content = read_text_file(log_files[0])
    assert isinstance(content, str)
    assert len(content) > 0


def test_read_text_file_json():
    json_files = list((EVIDENCE_DIR / "records").glob("*.json"))
    assert len(json_files) > 0, "No JSON files found"
    content = read_text(json_files[0])
    assert isinstance(content, str)
    assert len(content) > 0
    assert content.strip().startswith(("{", "["))


def test_read_text_file_with_temp_file(tmp_path: Path):
    text_file = tmp_path / "sample.txt"
    sample_data = "Hello, world! Unicode: 你好, Café, 🚀"
    text_file.write_text(sample_data, encoding="utf-8")
    result = read_text_file(text_file)
    assert result == sample_data
