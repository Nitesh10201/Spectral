import csv
import json
from code.config import OUTPUT_PATH, REPO_ROOT
from code.schemas.outputs import AuditResult
from collections.abc import Sequence
from pathlib import Path


def write_output_csv(
    results: Sequence[AuditResult], path: str | Path | None = OUTPUT_PATH
) -> Path:
    """Write audit results to output.csv adhering to the challenge specification.

    Resolves relative paths against REPO_ROOT so that output is always placed
    in the intended location regardless of the current working directory.
    Returns the resolved Path written to.
    """
    if path is None:
        dest = OUTPUT_PATH
    else:
        dest = Path(path)

    # If relative, anchor to REPO_ROOT
    if not dest.is_absolute():
        dest = (REPO_ROOT / dest).resolve()

    # If pointing to a directory, append default filename
    if dest.is_dir() or str(path).endswith(("/", "\\")):
        dest = (dest / "output.csv").resolve()

    dest.parent.mkdir(parents=True, exist_ok=True)

    sorted_results = sorted(results, key=lambda r: r.case_id)

    with open(dest, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for r in sorted_results:
            steps_data = [s.model_dump(mode="json") for s in r.steps]
            steps_json_str = json.dumps(steps_data, separators=(",", ":"))
            writer.writerow([r.case_id, r.deletion_status.value, steps_json_str])

    return dest
