import json
from code.llm.vision_client import DEFAULT_VISION_MODEL, VisionClient
from pathlib import Path


def test_vision_client_init(tmp_path: Path):
    cache_path = tmp_path / "vision_cache.json"
    client = VisionClient(api_key="  test_key  ", cache_file=cache_path)
    assert client.api_key == "test_key"
    assert client.model == DEFAULT_VISION_MODEL
    assert client.cache_file == cache_path
    assert client.model_calls == 0


def test_vision_client_cached_extraction(tmp_path: Path):
    cache_path = tmp_path / "vision_cache.json"
    cache_data = {
        "model": DEFAULT_VISION_MODEL,
        "cache": {
            "test_screenshot.png": {
                "text": "Admin Console: user_99 account_123 Active",
                "prompt_tokens": 1500,
                "completion_tokens": 250,
            }
        },
    }
    cache_path.write_text(json.dumps(cache_data), encoding="utf-8")

    client = VisionClient(api_key="test", cache_file=cache_path)
    text = client.extract_image_text(tmp_path / "test_screenshot.png")
    assert text == "Admin Console: user_99 account_123 Active"
    assert client.model_calls == 1
    assert client.prompt_tokens == 1500
    assert client.completion_tokens == 250

    metrics = client.get_metrics()
    assert metrics["provider"] == "NVIDIA NIM"
    assert metrics["model"] == DEFAULT_VISION_MODEL
    assert metrics["total_tokens"] == 1750
    assert metrics["estimated_cost_usd"] > 0


def test_vision_client_missing_file(tmp_path: Path):
    cache_path = tmp_path / "vision_cache.json"
    client = VisionClient(api_key="", cache_file=cache_path)
    text = client.extract_image_text(tmp_path / "non_existent.png")
    assert text == ""


def test_vision_client_classify_intent_no_key():
    client = VisionClient(api_key="")
    res = client.classify_deletion_intent("Please delete my data")
    assert res.get("is_deletion") is True
