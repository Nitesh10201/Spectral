import csv
import json
from code.config import OUTPUT_PATH
from code.schemas.outputs import AuditResult
from collections.abc import Sequence
from pathlib import Path


def write_output_csv(results: Sequence[AuditResult], path: str | Path = OUTPUT_PATH) -> None:
    """Write audit results to output.csv adhering to the challenge specification."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    sorted_results = sorted(results, key=lambda r: r.case_id)

    with open(dest, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for r in sorted_results:
            steps_data = [s.model_dump(mode="json") for s in r.steps]
            steps_json_str = json.dumps(steps_data, separators=(",", ":"))
            writer.writerow([r.case_id, r.deletion_status.value, steps_json_str])
