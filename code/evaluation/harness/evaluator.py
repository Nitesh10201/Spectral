import csv
import json
from code.config import SAMPLE_OUTPUT_PATH
from code.schemas.enums import DeletionStatus
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CaseComparison:
    case_id: str
    status_match: bool
    sequence_match: bool
    golden_status: str
    pred_status: str
    golden_step_count: int
    pred_step_count: int
    step_precision: float
    step_recall: float
    step_f1: float
    details: list[str] = field(default_factory=list)


@dataclass
class EvaluationReport:
    total_cases: int = 0
    status_accuracy: float = 0.0
    sequence_accuracy: float = 0.0
    step_precision: float = 0.0
    step_recall: float = 0.0
    step_f1: float = 0.0
    field_accuracies: dict[str, float] = field(default_factory=dict)
    status_breakdown: dict[str, dict[str, int]] = field(default_factory=dict)
    case_comparisons: list[CaseComparison] = field(default_factory=list)
    failures: list[CaseComparison] = field(default_factory=list)

    def to_markdown(self) -> str:
        """Format the evaluation summary into clean GitHub-flavored markdown."""
        lines = [
            "# Spectral Evaluation Report",
            "",
            "## Summary Metrics",
            "",
            "| Metric | Score |",
            "| :--- | :--- |",
            f"| **Total Cases Evaluated** | {self.total_cases} |",
            f"| **Status Accuracy** | {self.status_accuracy:.2%} |",
            f"| **Exact Sequence Accuracy** | {self.sequence_accuracy:.2%} |",
            f"| **Step Precision** | {self.step_precision:.2%} |",
            f"| **Step Recall** | {self.step_recall:.2%} |",
            f"| **Step F1** | {self.step_f1:.2%} |",
            "",
            "## Field-Level Accuracies",
            "",
            "| Field | Accuracy |",
            "| :--- | :--- |",
        ]
        for fld, acc in sorted(self.field_accuracies.items()):
            lines.append(f"| `{fld}` | {acc:.2%} |")

        lines.extend([
            "",
            "## Status Breakdown",
            "",
            "| Status | Total Golden | Correctly Predicted | Accuracy |",
            "| :--- | :--- | :--- | :--- |",
        ])
        for st, data in sorted(self.status_breakdown.items()):
            tot = data.get("total", 0)
            cor = data.get("correct", 0)
            acc_str = f"{(cor / tot):.2%}" if tot > 0 else "N/A"
            lines.append(f"| `{st}` | {tot} | {cor} | {acc_str} |")

        if self.failures:
            lines.extend([
                "",
                f"## Failures & Diagnostics ({len(self.failures)} cases)",
                "",
                "| Case ID | Expected Status | Predicted Status | Expected Steps | Predicted Steps | Issue |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for fail in self.failures[:20]:  # Cap table at 20 lines for readability
                issue = "; ".join(fail.details) if fail.details else "Step mismatch"
                lines.append(
                    f"| `{fail.case_id}` | `{fail.golden_status}` | `{fail.pred_status}` | "
                    f"{fail.golden_step_count} | {fail.pred_step_count} | {issue} |"
                )

        return "\n".join(lines) + "\n"


def _read_output_rows(path: str | Path) -> dict[str, tuple[str, list[dict]]]:
    path = Path(path)
    res = {}
    with open(path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            case_id = row["case_id"]
            status = row["deletion_status"]
            steps = json.loads(row["steps_json"])
            res[case_id] = (status, steps)
    return res


def _step_key(s: dict) -> tuple:
    return (
        s.get("phase", ""),
        s.get("operation", ""),
        s.get("system_id", ""),
        s.get("resource_id", ""),
        s.get("state", ""),
        s.get("evidence_id", ""),
    )


def evaluate_predictions(
    predicted_path: str | Path,
    golden_path: str | Path = SAMPLE_OUTPUT_PATH,
) -> EvaluationReport:
    """Compare a prediction CSV against the ground-truth golden CSV."""
    golden_data = _read_output_rows(golden_path)
    pred_data = _read_output_rows(predicted_path)

    common_cases = sorted(golden_data.keys())
    total_cases = len(common_cases)
    if total_cases == 0:
        return EvaluationReport()

    status_matches = 0
    sequence_matches = 0

    total_pred_steps = 0
    total_golden_steps = 0
    total_matched_steps = 0

    field_match_counts = {
        "phase": 0,
        "operation": 0,
        "state": 0,
        "system_id": 0,
        "resource_id": 0,
        "evidence_id": 0,
    }
    field_total_counts = 0

    status_breakdown: dict[str, dict[str, int]] = {
        status.value: {"total": 0, "correct": 0} for status in DeletionStatus
    }

    comparisons: list[CaseComparison] = []
    failures: list[CaseComparison] = []

    for cid in common_cases:
        g_status, g_steps = golden_data[cid]
        p_status, p_steps = pred_data.get(cid, ("NOT_FOUND", []))

        status_breakdown.setdefault(g_status, {"total": 0, "correct": 0})["total"] += 1
        st_match = (p_status == g_status)
        if st_match:
            status_matches += 1
            status_breakdown[g_status]["correct"] += 1

        # Step matching (set of step keys)
        g_keys = [_step_key(s) for s in g_steps]
        p_keys = [_step_key(s) for s in p_steps]

        seq_match = st_match and (g_keys == p_keys)
        if seq_match:
            sequence_matches += 1

        total_golden_steps += len(g_steps)
        total_pred_steps += len(p_steps)

        # Count matched steps
        matched_in_case = 0
        unmatched_golden = list(g_keys)
        for pk in p_keys:
            if pk in unmatched_golden:
                matched_in_case += 1
                unmatched_golden.remove(pk)

        total_matched_steps += matched_in_case

        # Field-level accuracy for overlapping step positions
        min_len = min(len(g_steps), len(p_steps))
        for i in range(min_len):
            field_total_counts += 1
            gs, ps = g_steps[i], p_steps[i]
            for fld in field_match_counts:
                if str(gs.get(fld, "")) == str(ps.get(fld, "")):
                    field_match_counts[fld] += 1

        p_prec = (matched_in_case / len(p_steps)) if p_steps else (1.0 if not g_steps else 0.0)
        p_rec = (matched_in_case / len(g_steps)) if g_steps else (1.0 if not p_steps else 0.0)
        p_f1 = (
            (2 * p_prec * p_rec / (p_prec + p_rec))
            if (p_prec + p_rec) > 0
            else (1.0 if (not g_steps and not p_steps) else 0.0)
        )

        details: list[str] = []
        if not st_match:
            details.append(f"Status mismatch: expected {g_status}, got {p_status}")
        if g_keys != p_keys:
            details.append(f"Steps mismatch: golden={len(g_steps)}, pred={len(p_steps)}")

        comp = CaseComparison(
            case_id=cid,
            status_match=st_match,
            sequence_match=seq_match,
            golden_status=g_status,
            pred_status=p_status,
            golden_step_count=len(g_steps),
            pred_step_count=len(p_steps),
            step_precision=p_prec,
            step_recall=p_rec,
            step_f1=p_f1,
            details=details,
        )
        comparisons.append(comp)
        if not seq_match:
            failures.append(comp)

    overall_prec = (total_matched_steps / total_pred_steps) if total_pred_steps > 0 else 1.0
    overall_rec = (total_matched_steps / total_golden_steps) if total_golden_steps > 0 else 1.0
    overall_f1 = (
        (2 * overall_prec * overall_rec / (overall_prec + overall_rec))
        if (overall_prec + overall_rec) > 0
        else 0.0
    )

    field_accs = {
        fld: (count / field_total_counts) if field_total_counts > 0 else 1.0
        for fld, count in field_match_counts.items()
    }

    return EvaluationReport(
        total_cases=total_cases,
        status_accuracy=status_matches / total_cases,
        sequence_accuracy=sequence_matches / total_cases,
        step_precision=overall_prec,
        step_recall=overall_rec,
        step_f1=overall_f1,
        field_accuracies=field_accs,
        status_breakdown=status_breakdown,
        case_comparisons=comparisons,
        failures=failures,
    )
