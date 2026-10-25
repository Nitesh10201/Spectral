import csv
import json
from code.schemas.enums import (
    OPERATION_ORDER,
    OPERATION_SPEC,
    PHASE_ORDER,
    DeletionStatus,
    Operation,
    Phase,
    State,
)
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ValidationReport:
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    row_count: int = 0
    case_ids: list[str] = field(default_factory=list)


def validate_output_file(
    file_path: str | Path,
    expected_count: int | None = None,
) -> ValidationReport:
    """Validate an output CSV file against the HackerRank Orchestrate contract."""
    path = Path(file_path)
    if not path.exists():
        return ValidationReport(is_valid=False, errors=[f"File not found: {path}"])

    errors: list[str] = []
    case_ids: list[str] = []

    try:
        with open(path, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header != ["case_id", "deletion_status", "steps_json"]:
                errors.append(
                    f"Invalid CSV header: expected ['case_id', 'deletion_status', 'steps_json'], got {header}"
                )

            rows = list(reader)
    except OSError as e:
        return ValidationReport(is_valid=False, errors=[f"Failed to read CSV: {e}"])

    row_count = len(rows)
    if expected_count is not None and row_count != expected_count:
        errors.append(f"Row count mismatch: expected {expected_count}, got {row_count}")

    seen_case_ids: set[str] = set()

    for idx, row in enumerate(rows, start=2):
        if len(row) != 3:
            errors.append(f"Line {idx}: row has {len(row)} columns instead of 3")
            continue

        case_id, status_str, steps_json_str = row
        case_ids.append(case_id)

        if not case_id.strip():
            errors.append(f"Line {idx}: empty case_id")
        if case_id in seen_case_ids:
            errors.append(f"Line {idx}: duplicate case_id '{case_id}'")
        seen_case_ids.add(case_id)

        # Validate status
        try:
            status = DeletionStatus(status_str)
        except ValueError:
            errors.append(f"Line {idx}: invalid deletion_status '{status_str}'")
            continue

        # Validate steps_json
        try:
            steps_data = json.loads(steps_json_str)
        except json.JSONDecodeError as e:
            errors.append(f"Line {idx}: invalid JSON in steps_json: {e}")
            continue

        if not isinstance(steps_data, list):
            errors.append(f"Line {idx}: steps_json must be a JSON array")
            continue

        if status == DeletionStatus.NOT_APPLICABLE:
            if len(steps_data) != 0:
                errors.append(
                    f"Line {idx}: NOT_APPLICABLE must have an empty steps array [], got {len(steps_data)} items"
                )
            continue

        # Validate steps
        step_keys: list[tuple[int, int, str, str]] = []

        for step_idx, step_obj in enumerate(steps_data, start=1):
            if not isinstance(step_obj, dict):
                errors.append(f"Line {idx}, step {step_idx}: step must be a JSON object")
                continue

            # Check required fields
            req_fields = {
                "step_no",
                "phase",
                "system_id",
                "resource_id",
                "operation",
                "state",
                "evidence_id",
            }
            missing = req_fields - set(step_obj.keys())
            if missing:
                errors.append(f"Line {idx}, step {step_idx}: missing fields {sorted(missing)}")
                continue

            step_no = step_obj.get("step_no")
            if step_no != step_idx:
                errors.append(
                    f"Line {idx}, step {step_idx}: step_no must be {step_idx}, got {step_no}"
                )

            # Validate enums
            try:
                op = Operation(step_obj["operation"])
            except ValueError:
                errors.append(
                    f"Line {idx}, step {step_idx}: invalid operation '{step_obj.get('operation')}'"
                )
                continue

            try:
                ph = Phase(step_obj["phase"])
            except ValueError:
                errors.append(
                    f"Line {idx}, step {step_idx}: invalid phase '{step_obj.get('phase')}'"
                )
                continue

            try:
                st = State(step_obj["state"])
            except ValueError:
                errors.append(
                    f"Line {idx}, step {step_idx}: invalid state '{step_obj.get('state')}'"
                )
                continue

            # Check operation pairing
            expected_phase, expected_state = OPERATION_SPEC[op]
            if ph != expected_phase or st != expected_state:
                errors.append(
                    f"Line {idx}, step {step_idx}: {op.value} requires phase={expected_phase.value}, "
                    f"state={expected_state.value}; got phase={ph.value}, state={st.value}"
                )

            evidence_id = str(step_obj.get("evidence_id", ""))

            if status == DeletionStatus.COMPLETE:
                if ph != Phase.VERIFICATION:
                    errors.append(
                        f"Line {idx}, step {step_idx}: COMPLETE status allows only VERIFICATION steps, got {ph.value}"
                    )
                if not evidence_id.strip():
                    errors.append(
                        f"Line {idx}, step {step_idx}: COMPLETE status verification step must cite non-empty evidence_id"
                    )

            if status == DeletionStatus.INCOMPLETE:
                if ph == Phase.FINDING and not evidence_id.strip():
                    errors.append(
                        f"Line {idx}, step {step_idx}: FINDING must cite non-empty evidence_id"
                    )
                if ph in (Phase.REMEDIATION, Phase.VERIFICATION) and evidence_id != "":
                    errors.append(
                        f"Line {idx}, step {step_idx}: {ph.value} in INCOMPLETE status must use empty evidence_id"
                    )

            system_id = str(step_obj.get("system_id", ""))
            resource_id = str(step_obj.get("resource_id", ""))
            step_keys.append((PHASE_ORDER[ph], OPERATION_ORDER[op], system_id, resource_id))

        if step_keys != sorted(step_keys):
            errors.append(f"Line {idx}: steps are not sorted according to required ordering rules")

    # Check case_id sorted order
    if case_ids != sorted(case_ids):
        errors.append("Rows are not sorted by case_id in ascending order")

    return ValidationReport(
        is_valid=len(errors) == 0,
        errors=errors,
        row_count=row_count,
        case_ids=case_ids,
    )
