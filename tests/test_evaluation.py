import json
from code.evaluation.harness.evaluator import evaluate_predictions
from code.evaluation.harness.validator import validate_output_file
from pathlib import Path


def _write_csv(path: Path, rows: list[tuple[str, str, str]]) -> None:
    content = "case_id,deletion_status,steps_json\n"
    for cid, st, steps in rows:
        content += f'{cid},{st},"{steps.replace('"', '""')}"\n'
    path.write_text(content, encoding="utf-8")


def test_validator_valid_synthetic_cases(tmp_path: Path):
    target = tmp_path / "valid.csv"
    step_ver = json.dumps([
        {
            "step_no": 1,
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": "acc_01",
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": "ev_01",
        }
    ])
    _write_csv(target, [
        ("case_01", "COMPLETE", step_ver),
        ("case_02", "NOT_APPLICABLE", "[]"),
    ])

    report = validate_output_file(target, expected_count=2)
    assert report.is_valid
    assert len(report.errors) == 0
    assert report.row_count == 2


def test_validator_detects_unsorted_case_ids(tmp_path: Path):
    target = tmp_path / "unsorted.csv"
    _write_csv(target, [
        ("case_02", "NOT_APPLICABLE", "[]"),
        ("case_01", "NOT_APPLICABLE", "[]"),
    ])
    report = validate_output_file(target)
    assert not report.is_valid
    assert any("sorted by case_id" in err for err in report.errors)


def test_validator_detects_not_applicable_with_steps(tmp_path: Path):
    target = tmp_path / "invalid_na.csv"
    step_data = json.dumps([
        {
            "step_no": 1,
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": "acc_01",
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": "ev_01",
        }
    ])
    _write_csv(target, [
        ("case_01", "NOT_APPLICABLE", step_data),
    ])
    report = validate_output_file(target)
    assert not report.is_valid
    assert any("NOT_APPLICABLE must have an empty steps array" in err for err in report.errors)


def test_validator_detects_invalid_step_pairing(tmp_path: Path):
    target = tmp_path / "invalid_pairing.csv"
    step_bad = json.dumps([
        {
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "acc_01",
            "operation": "DELETE_RECORD",  # DELETE_RECORD is REMEDIATION, not FINDING
            "state": "ABSENT",
            "evidence_id": "ev_01",
        }
    ])
    _write_csv(target, [
        ("case_01", "INCOMPLETE", step_bad),
    ])
    report = validate_output_file(target)
    assert not report.is_valid
    assert any("requires phase=REMEDIATION" in err for err in report.errors)


def test_evaluate_predictions_synthetic_match(tmp_path: Path):
    golden = tmp_path / "golden.csv"
    pred = tmp_path / "pred.csv"

    step_json = json.dumps([
        {
            "step_no": 1,
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": "acc_10",
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": "ev_01",
        }
    ])

    rows = [
        ("case_01", "COMPLETE", step_json),
        ("case_02", "NOT_APPLICABLE", "[]"),
    ]
    _write_csv(golden, rows)
    _write_csv(pred, rows)

    report = evaluate_predictions(pred, golden)
    assert report.total_cases == 2
    assert report.status_accuracy == 1.0
    assert report.sequence_accuracy == 1.0
    assert report.step_f1 == 1.0
    assert len(report.failures) == 0


def test_evaluate_predictions_synthetic_mismatch(tmp_path: Path):
    golden = tmp_path / "golden.csv"
    pred = tmp_path / "pred.csv"

    step_1 = json.dumps([
        {
            "step_no": 1,
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": "acc_10",
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": "ev_01",
        }
    ])
    step_2 = json.dumps([
        {
            "step_no": 1,
            "phase": "VERIFICATION",
            "system_id": "account_service",
            "resource_id": "acc_99",  # different resource
            "operation": "VERIFY_RECORD_ABSENT",
            "state": "ABSENT",
            "evidence_id": "ev_01",
        }
    ])

    _write_csv(golden, [("case_01", "COMPLETE", step_1)])
    _write_csv(pred, [("case_01", "INCOMPLETE", step_2)])

    report = evaluate_predictions(pred, golden)
    assert report.total_cases == 1
    assert report.status_accuracy == 0.0
    assert report.sequence_accuracy == 0.0
    assert report.step_precision == 0.0
    assert len(report.failures) == 1
    assert "Status mismatch" in report.failures[0].details[0]

    md = report.to_markdown()
    assert "# Spectral Evaluation Report" in md
    assert "0.00%" in md
