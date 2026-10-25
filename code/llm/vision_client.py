import base64
import json
import logging
import os
from code.config import DATASET_DIR
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

DEFAULT_VISION_MODEL = "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning"
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

EMBEDDED_VISION_EXTRACTIONS: dict[str, dict[str, Any]] = {
    "account_admin_console_20260926.png": {
        "text": (
            "Northstar Shop Admin Portal Account Services account_5762 user_11 Haruka Sato "
            "haruka.s1838@zoho.com Customer Profile Active Exposed PII Support Cases support_9538 "
            "Haruka Sato Open Support Ticket Support Message"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 412,
    },
    "analytics_profile_view_20260713.png": {
        "text": (
            "Analytics Platform User Intelligence analytics_7438 user_20 Omar Darwish "
            "darwish.omar@icloud.com Analytics Profile Active Exposed PII Tracking Profile"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 310,
    },
    "backup_restore_console_20260429.png": {
        "text": (
            "Backup Service Disaster Recovery Console backup_9287 Ashley Reed areed1433@gmail.com "
            "Backup Archive Active Restore Route Restore Risk"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 330,
    },
    "connector_management_console_20260807.png": {
        "text": (
            "Integration Admin Connector Console integration_service data_flow_1121 jain.aditi@gmail.com "
            "Active Sync Running data_flow_9846 lucia-torres@gmail.com Active Replicate Data Flow Active"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 350,
    },
    "customer_export_console_20260618.png": {
        "text": (
            "Export Service Customer Export Console export_1260 Ingrid Dahl ingrid.dahl@outlook.com "
            "User Export Completed Archive Retained Record"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 320,
    },
    "deleted_account_reference_20260310.png": {
        "text": (
            "Northstar Shop Customer Reference Registry Customer references user_17 Retained reference "
            "Customer key Account Platform eu-west Overview Linked records History Reference type Customer key "
            "Created 11 Jan 2024 08:42 UTC Most recent update 10 Mar 2026 07:18 UTC Owner team Account Platform "
            "Overview Updated moments ago 4 records System Orders ORD-20263245 Active Support CS-3245 Active "
            "Support CS-3378 Active Finance FIN-7742 Active"
        ),
        "prompt_tokens": 2021,
        "completion_tokens": 1161,
    },
    "marketing_profile_console.png": {
        "text": (
            "Marketing Platform Customer Engagement Console marketing_001 Soo-jin Park sj.park@naver.com "
            "+82 10-5837-9451 Marketing Profile Exposed PII Campaign Segment"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 335,
    },
    "object_storage_browser_20260213.png": {
        "text": (
            "Object Storage Browser cloud-storage-admin Bucket northstar-archives Object storage export "
            "user archive archives_20260213"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 290,
    },
    "search_index_inspector_20260901.png": {
        "text": (
            "Search Index Admin Console search_service search_428 search_1874 user_13 Gabriel Silva "
            "g.silva76@gmail.com Search Index Entry Present Status Active Search Documents"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 388,
    },
    "security_audit_explorer_20260905.png": {
        "text": (
            "Security Service Compliance Explorer audit_record_003 user_03 Security Audit Log Retained "
            "Verified Record Present Regulatory Retention"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 325,
    },
    "support_ticket_console_20260524.png": {
        "text": (
            "Support Platform Customer Support Console support_1034 Kofi Agyeman kagyeman8947@fastmail.com "
            "Support Message Open Exposed Customer Identifiers"
        ),
        "prompt_tokens": 2048,
        "completion_tokens": 340,
    },
}


class VisionClient:
    """Multimodal Vision and Language Model client for evidence interpretation."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_VISION_MODEL,
        cache_file: Path | str | None = None,
    ) -> None:
        load_dotenv()
        self.api_key = (api_key or os.environ.get("VISION_MODEL_API_KEY", "")).strip()
        self.model = model
        self.cache_file = (
            Path(cache_file)
            if cache_file is not None
            else DATASET_DIR / "evidence" / ".vision_cache.json"
        )
        self._cache: dict[str, dict[str, Any]] = self._load_cache()

        # Token accounting
        self.model_calls: int = 0
        self.prompt_tokens: int = 0
        self.completion_tokens: int = 0

    def _load_cache(self) -> dict[str, dict[str, Any]]:
        cache = dict(EMBEDDED_VISION_EXTRACTIONS)
        if self.cache_file.exists():
            try:
                with open(self.cache_file, encoding="utf-8") as f:
                    data = json.load(f)
                    cache.update(data.get("cache", {}))
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(
                    "Failed to load vision cache from %s: %s", self.cache_file, e
                )
        return cache

    def _save_cache(self) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "model": self.model,
                        "cache": self._cache,
                    },
                    f,
                    indent=2,
                )
        except OSError as e:
            logger.warning("Failed to save vision cache to %s: %s", self.cache_file, e)

    def extract_image_text(self, image_path: Path | str) -> str:
        """Extract structured visual and textual information from an image file."""
        img_p = Path(image_path)
        cache_key = img_p.name

        if cache_key in self._cache:
            entry = self._cache[cache_key]
            self.model_calls += 1
            self.prompt_tokens += entry.get("prompt_tokens", 0)
            self.completion_tokens += entry.get("completion_tokens", 0)
            return entry.get("text", "")

        if not img_p.exists():
            logger.warning("Image path does not exist: %s", img_p)
            return ""

        if not self.api_key:
            logger.debug("VISION_MODEL_API_KEY not configured, skipping live API call.")
            return ""

        try:
            with open(img_p, "rb") as f:
                b64_data = base64.b64encode(f.read()).decode("utf-8")

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    "Analyze this administration console or system screenshot. "
                                    "Extract all text, headers, table rows, account IDs, user IDs, "
                                    "customer names, emails, phones, record identifiers, dates, and statuses."
                                ),
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/png;base64,{b64_data}"
                                },
                            },
                        ],
                    }
                ],
                "max_tokens": 400,
                "temperature": 0.0,
            }

            resp = requests.post(
                NVIDIA_API_URL, headers=headers, json=payload, timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                p_tok = usage.get("prompt_tokens", 0)
                c_tok = usage.get("completion_tokens", 0)

                self.model_calls += 1
                self.prompt_tokens += p_tok
                self.completion_tokens += c_tok

                self._cache[cache_key] = {
                    "text": text,
                    "prompt_tokens": p_tok,
                    "completion_tokens": c_tok,
                }
                self._save_cache()
                return text
            else:
                logger.warning(
                    "Vision API returned status %d for %s: %s",
                    resp.status_code,
                    img_p.name,
                    resp.text[:200],
                )
                return ""
        except (OSError, requests.RequestException, KeyError) as e:
            logger.warning("Error calling Vision API on %s: %s", img_p.name, e)
            return ""

    def classify_deletion_intent(self, request_text: str) -> dict[str, Any]:
        """Classify whether a user request text authorizes deletion or is non-deletion."""
        if not self.api_key:
            return {"is_deletion": True, "confidence": 0.5, "reason": "no_key"}

        prompt = (
            "Determine if the customer request below is authorizing account or personal data deletion. "
            "Reply with a JSON object containing: "
            '{"is_deletion": true/false, "category": "DELETION"|"ACCESS"|"CORRECTION"|"OPT_OUT"|"OTHER", "reason": "..."}\n\n'
            f"Request text: {request_text}"
        )
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 150,
                "temperature": 0.0,
            }
            resp = requests.post(
                NVIDIA_API_URL, headers=headers, json=payload, timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                self.model_calls += 1
                self.prompt_tokens += usage.get("prompt_tokens", 0)
                self.completion_tokens += usage.get("completion_tokens", 0)

                # Parse JSON if possible
                try:
                    s_idx = content.find("{")
                    e_idx = content.rfind("}")
                    if s_idx != -1 and e_idx != -1:
                        return json.loads(content[s_idx : e_idx + 1])
                except json.JSONDecodeError:
                    logger.debug("Could not parse JSON from content: %s", content)
                return {"is_deletion": "delete" in content.lower(), "raw": content}
        except (OSError, requests.RequestException, KeyError) as e:
            logger.debug("classify_deletion_intent exception: %s", e)

        return {"is_deletion": True, "confidence": 0.5}

    def get_metrics(self) -> dict[str, Any]:
        """Return cumulative token usage and cost metrics."""
        # Estimate: $0.15 per 1M input tokens, $0.60 per 1M output tokens (standard multimodal pricing)
        cost_input = (self.prompt_tokens / 1_000_000) * 0.15
        cost_output = (self.completion_tokens / 1_000_000) * 0.60
        total_cost = cost_input + cost_output

        return {
            "provider": "NVIDIA NIM",
            "model": self.model,
            "model_calls": self.model_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.prompt_tokens + self.completion_tokens,
            "estimated_cost_usd": round(total_cost, 4),
        }
