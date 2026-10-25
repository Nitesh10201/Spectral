import csv
import json
from code.filesystem.writer.csv_writer import write_output_csv
from code.schemas.enums import DeletionStatus, Operation, Phase, State
from code.schemas.outputs import AuditResult, Step
from pathlib import Path


def test_write_output_csv_empty(tmp_path: Path):
    dest = tmp_path / "output.csv"
    write_output_csv([], dest)

    assert dest.exists()
    content = dest.read_text(encoding="utf-8").strip().splitlines()
    assert content == ["case_id,deletion_status,steps_json"]


def test_write_output_csv_mixed_cases(tmp_path: Path):
    dest = tmp_path / "output.csv"

    # Synthetic AuditResult for NOT_APPLICABLE
    res_na = AuditResult(
        case_id="case_02",
        deletion_status=DeletionStatus.NOT_APPLICABLE,
        steps=[],
    )

    # Synthetic AuditResult for COMPLETE
    res_complete = AuditResult(
        case_id="case_01",
        deletion_status=DeletionStatus.COMPLETE,
        steps=[
            Step(
                step_no=1,
                phase=Phase.VERIFICATION,
                system_id="account_service",
                resource_id="account_001",
                operation=Operation.VERIFY_RECORD_ABSENT,
                state=State.ABSENT,
                evidence_id="evidence_54",
            )
        ],
    )

    # Synthetic AuditResult for INCOMPLETE
    res_incomplete = AuditResult(
        case_id="case_03",
        deletion_status=DeletionStatus.INCOMPLETE,
        steps=[
            Step(
                step_no=1,
                phase=Phase.FINDING,
                system_id="account_service",
                resource_id="account_005",
                operation=Operation.REPORT_REMAINING_RECORD,
                state=State.PRESENT,
                evidence_id="evidence_54",
            ),
            Step(
                step_no=2,
                phase=Phase.REMEDIATION,
                system_id="account_service",
                resource_id="account_005",
                operation=Operation.DELETE_RECORD,
                state=State.ABSENT,
                evidence_id="",
            ),
            Step(
                step_no=3,
                phase=Phase.VERIFICATION,
                system_id="account_service",
                resource_id="account_005",
                operation=Operation.VERIFY_RECORD_ABSENT,
                state=State.ABSENT,
                evidence_id="",
            ),
        ],
    )

    # Pass in unsorted order (case_02, case_03, case_01)
    write_output_csv([res_na, res_incomplete, res_complete], dest)

    # Read back and verify CSV rows
    with open(dest, mode="r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    assert len(reader) == 3
    # Verify sorted order by case_id
    assert [r["case_id"] for r in reader] == ["case_01", "case_02", "case_03"]

    # Verify case_01 (COMPLETE)
    assert reader[0]["deletion_status"] == "COMPLETE"
    steps_01 = json.loads(reader[0]["steps_json"])
    assert len(steps_01) == 1
    assert steps_01[0]["operation"] == "VERIFY_RECORD_ABSENT"
    assert steps_01[0]["evidence_id"] == "evidence_54"

    # Verify case_02 (NOT_APPLICABLE)
    assert reader[1]["deletion_status"] == "NOT_APPLICABLE"
    assert reader[1]["steps_json"] == "[]"

    # Verify case_03 (INCOMPLETE)
    assert reader[2]["deletion_status"] == "INCOMPLETE"
    steps_03 = json.loads(reader[2]["steps_json"])
    assert len(steps_03) == 3
    assert [s["phase"] for s in steps_03] == ["FINDING", "REMEDIATION", "VERIFICATION"]
