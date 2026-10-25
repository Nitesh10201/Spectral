from code.evaluation.harness.validator import validate_output_file
from code.pipeline.runner.context import CaseContext, DetectionResult
from code.pipeline.runner.orchestrator import PipelineOrchestrator
from code.pipeline.steps.builder import create_step
from code.schemas.enums import DeletionStatus, Operation, ReportedStatus
from code.schemas.findings import Finding
from code.schemas.inputs import DeletionRequest, DeletionRule, RequiredAction
from datetime import datetime
from pathlib import Path


class MockGhostRecordDetector:
    """Synthetic detector that flags user_02 as having a ghost record."""

    def detect(self, ctx: CaseContext) -> DetectionResult:
        if ctx.request.case_id == "case_incomplete":
            return DetectionResult(
                findings=[
                    Finding(
                        system_id="search_service",
                        resource_id="search_999",
                        kind=Operation.REPORT_REMAINING_RECORD,
                        evidence_id="ev_ghost",
                        data_category="SEARCH_INDEX_ENTRY",
                    )
                ]
            )
        # Otherwise clean: return compliant verification step
        return DetectionResult(
            verifications=[
                create_step(
                    Operation.VERIFY_RECORD_ABSENT,
                    system_id="account_service",
                    resource_id="acc_001",
                    evidence_id="ev_clean",
                )
            ]
        )


def _make_request(case_id: str, text: str) -> DeletionRequest:
    return DeletionRequest(
        case_id=case_id,
        email="user@example.com",
        requested_at=datetime.fromisoformat("2026-08-01T00:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        audit_at=datetime.fromisoformat("2026-08-05T00:00:00Z"),
        request_text=text,
    )


def test_orchestrator_not_applicable_classification():
    # Classifier flags non-deletion requests
    def mock_classifier(req: DeletionRequest) -> bool:
        return "delete" in req.request_text.lower()

    orchestrator = PipelineOrchestrator(
        classifier=mock_classifier,
        detectors=[MockGhostRecordDetector()],
    )

    req_opt_out = _make_request("case_na", "Please unsubscribe me from marketing emails")
    res = orchestrator.audit_case(req_opt_out)

    assert res.deletion_status == DeletionStatus.NOT_APPLICABLE
    assert res.steps == []


def test_orchestrator_complete_case():
    orchestrator = PipelineOrchestrator(
        classifier=lambda req: True,
        detectors=[MockGhostRecordDetector()],
    )

    req_clean = _make_request("case_complete", "Please delete my entire profile")
    res = orchestrator.audit_case(req_clean)

    assert res.deletion_status == DeletionStatus.COMPLETE
    assert len(res.steps) == 1
    assert res.steps[0].operation == Operation.VERIFY_RECORD_ABSENT
    assert res.steps[0].evidence_id == "ev_clean"


def test_orchestrator_incomplete_case():
    rule = DeletionRule(
        rule_id="r1",
        data_category="SEARCH_INDEX_ENTRY",
        condition="Always",
        required_action=RequiredAction.DELETE,
    )
    orchestrator = PipelineOrchestrator(
        classifier=lambda req: True,
        detectors=[MockGhostRecordDetector()],
        rules=[rule],
    )

    req_ghost = _make_request("case_incomplete", "Please delete my account")
    res = orchestrator.audit_case(req_ghost)

    assert res.deletion_status == DeletionStatus.INCOMPLETE
    assert len(res.steps) == 3
    assert [s.phase.value for s in res.steps] == ["FINDING", "REMEDIATION", "VERIFICATION"]
    assert res.steps[0].evidence_id == "ev_ghost"
    assert res.steps[1].evidence_id == ""
    assert res.steps[2].evidence_id == ""


def test_orchestrator_run_pipeline_end_to_end(tmp_path: Path):
    requests_csv = tmp_path / "requests.csv"
    requests_csv.write_text(
        "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
        "case_01,a@test.com,2026-08-01T00:00:00Z,COMPLETE,,2026-08-02T00:00:00Z,Delete my data\n"
        "case_02,b@test.com,2026-08-01T00:00:00Z,COMPLETE,,2026-08-02T00:00:00Z,Export my data\n",
        encoding="utf-8",
    )
    output_csv = tmp_path / "output.csv"

    def mock_classifier(req: DeletionRequest) -> bool:
        return "delete" in req.request_text.lower()

    orchestrator = PipelineOrchestrator(
        classifier=mock_classifier,
        detectors=[MockGhostRecordDetector()],
    )

    result_path = orchestrator.run_pipeline(
        requests_path=requests_csv,
        output_path=output_csv,
    )
    assert result_path == output_csv
    assert output_csv.exists()

    report = validate_output_file(output_csv, expected_count=2)
    assert report.is_valid
    assert len(report.errors) == 0
