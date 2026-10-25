from code.detectors.logs.scanner import TextLogScanner
from code.pipeline.runner.context import CaseContext, SubjectContext
from code.schemas.enums import Operation
from code.schemas.inputs import DeletionRequest, EvidenceFile, ReportedStatus
from datetime import datetime
from pathlib import Path


def test_text_log_scanner_findings(tmp_path: Path):
    """Test log scanner detecting restore risk, active flow, and search hit."""
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True)
    log_file = logs_dir / "service_events.log"

    log_file.write_text(
        """
2026-09-15T11:54:41Z level=ERROR service=backup_service resource_id=backup_synth_01 event=restore_candidate_evaluated eligible=true deletion_block=false subject_reference=user_synth_10
2026-09-15T11:58:11Z level=WARN service=integration_service resource_id=data_flow_synth_01 event=connector_heartbeat enabled=true lookup_key=synth_carol@example.com
2026-09-15T11:58:26Z level=INFO service=search_service resource_id=search_synth_01 event=index_query_completed result=hit lookup_key=synth_carol@example.com
        """,
        encoding="utf-8",
    )

    scanner = TextLogScanner(dataset_dir=tmp_path)
    subject = SubjectContext(
        user_id="user_synth_10",
        current_email="synth_carol@example.com",
        emails=frozenset({"synth_carol@example.com"}),
    )
    req = DeletionRequest(
        case_id="case_synth_log_01",
        email="synth_carol@example.com",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-20T12:00:00+00:00"),
        request_text="Delete my info",
    )
    ef = EvidenceFile(
        file_id="evidence_log_01",
        file_path="logs/service_events.log",
        origin="test_origin",
        captured_at=datetime.fromisoformat("2026-09-15T12:00:00+00:00"),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef],
    )
    res = scanner.detect(ctx)

    assert len(res.findings) == 3
    f_ops = {f.kind for f in res.findings}
    assert Operation.REPORT_RESTORE_RISK in f_ops
    assert Operation.REPORT_ACTIVE_DATA_FLOW in f_ops
    assert Operation.REPORT_REMAINING_RECORD in f_ops


def test_text_log_scanner_verifications(tmp_path: Path):
    """Test log scanner detecting verification states: account 404/0 rows, audit present, analytics anonymized."""
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "lookup_trace.log"

    log_file.write_text(
        """
2026-09-26T08:57:37Z level=INFO service=account_service resource_id=account_synth_01 rows=0 http_status=404 lookup_key=synth_dan@example.com
2026-09-26T09:40:29Z level=INFO service=security_service resource_id=audit_synth_02 rows=1 subject_reference=user_synth_11
2026-09-26T09:54:09Z level=INFO service=analytics_platform resource_id=analytics_synth_02 customer_reference=null email=null phone=null correlation_key=synth_dan@example.com
        """,
        encoding="utf-8",
    )

    scanner = TextLogScanner(dataset_dir=tmp_path)
    subject = SubjectContext(
        user_id="user_synth_11",
        current_email="synth_dan@example.com",
        emails=frozenset({"synth_dan@example.com"}),
    )
    req = DeletionRequest(
        case_id="case_synth_log_02",
        email="synth_dan@example.com",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-27T12:00:00+00:00"),
        request_text="Delete my info",
    )
    ef = EvidenceFile(
        file_id="evidence_log_02",
        file_path="logs/lookup_trace.log",
        origin="test_origin",
        captured_at=datetime.fromisoformat("2026-09-26T12:00:00+00:00"),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef],
    )
    res = scanner.detect(ctx)

    assert len(res.findings) == 0
    assert len(res.verifications) == 3
    v_ops = {v.operation for v in res.verifications}
    assert Operation.VERIFY_RECORD_ABSENT in v_ops
    assert Operation.VERIFY_RECORD_PRESENT in v_ops
    assert Operation.VERIFY_RECORD_ANONYMIZED in v_ops
