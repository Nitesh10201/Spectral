import io
from code.detectors.document.scanner import DocumentAndImageScanner
from code.pipeline.runner.context import CaseContext, SubjectContext
from code.schemas.enums import Operation
from code.schemas.inputs import DeletionRequest, EvidenceFile
from datetime import datetime
from pathlib import Path

import pypdf


def _create_synthetic_pdf(text: str) -> bytes:
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    # We can write minimal PDF stream or use pypdf annotation/metadata
    # To keep synthetic fixture simple without disk dependencies, let's create a minimal PDF
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


def test_image_registry_matching(tmp_path: Path):
    scanner = DocumentAndImageScanner(dataset_dir=tmp_path)

    # Subject matching one of the registry items
    subject = SubjectContext(
        user_id="user_13",
        current_email="g.silva76@gmail.com",
        emails=frozenset(["g.silva76@gmail.com"]),
        names=frozenset(["Gabriel Silva"]),
    )

    req = DeletionRequest(
        case_id="case_test_img",
        email="g.silva76@gmail.com",
        requested_at=datetime(2026, 9, 1, 8, 0, 0),
        reported_status="NOT_STARTED",
        reported_at=datetime(2026, 9, 1, 9, 0, 0),
        audit_at=datetime(2026, 9, 1, 10, 0, 0),
        request_text="Please delete my account and search index entries.",
    )

    ef = EvidenceFile(
        file_id="evidence_test_img",
        file_path="evidence/images/search_index_inspector_20260901.png",
        origin="search_service",
        captured_at=datetime(2026, 9, 1, 9, 15, 0),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef],
    )

    res = scanner.detect(ctx)
    assert len(res.findings) == 2
    ops = [f.kind for f in res.findings]
    assert ops == [Operation.REPORT_REMAINING_RECORD, Operation.REPORT_REMAINING_RECORD]
    rids = {f.resource_id for f in res.findings}
    assert rids == {"search_428", "search_1874"}


def test_handover_text_scanning(tmp_path: Path):
    records_dir = tmp_path / "evidence" / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    handover_file = records_dir / "customer_account_handover_20261001.txt"

    content = """CUSTOMER PLATFORM - SHIFT HANDOVER
Snapshot: 2026-10-01T12:00:00Z

Account and downstream checks completed during the shift:

- 2026-10-01T12:00:00Z | account_service | account_9999 | USER_PROFILE | NOT_FOUND | synth.user@example.com
- 2026-10-01T12:00:00Z | search_service | search_8888 | SEARCH_INDEX_ENTRY | FOUND | synth.user@example.com
- 2026-10-01T12:00:00Z | integration_service | data_flow_7777 | DATA_FLOW | ACTIVE | synth.user@example.com
- 2026-10-01T12:00:00Z | backup_service | backup_6666 | BACKUP_ARCHIVE | BLOCKED | synth_user_01
"""
    handover_file.write_text(content, encoding="utf-8")

    scanner = DocumentAndImageScanner(dataset_dir=tmp_path)

    subject = SubjectContext(
        user_id="synth_user_01",
        current_email="synth.user@example.com",
        emails=frozenset(["synth.user@example.com"]),
    )

    req = DeletionRequest(
        case_id="case_synth_txt",
        email="synth.user@example.com",
        requested_at=datetime(2026, 10, 1, 10, 0, 0),
        reported_status="NOT_STARTED",
        reported_at=datetime(2026, 10, 1, 11, 0, 0),
        audit_at=datetime(2026, 10, 1, 13, 0, 0),
        request_text="Delete my data completely.",
    )

    ef = EvidenceFile(
        file_id="evidence_txt",
        file_path="evidence/records/customer_account_handover_20261001.txt",
        origin="customer_account_service",
        captured_at=datetime(2026, 10, 1, 12, 0, 0),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef],
    )

    res = scanner.detect(ctx)

    # Findings: search_8888 (REPORT_REMAINING_RECORD) and data_flow_7777 (REPORT_ACTIVE_DATA_FLOW)
    assert len(res.findings) == 2
    f_sys = {f.system_id: f.kind for f in res.findings}
    assert f_sys["search_service"] == Operation.REPORT_REMAINING_RECORD
    assert f_sys["integration_service"] == Operation.REPORT_ACTIVE_DATA_FLOW

    # Verifications: account_9999 (VERIFY_RECORD_ABSENT) and backup_6666 (VERIFY_RESTORE_BLOCKED)
    assert len(res.verifications) == 2
    v_sys = {v.system_id: v.operation for v in res.verifications}
    assert v_sys["account_service"] == Operation.VERIFY_RECORD_ABSENT
    assert v_sys["backup_service"] == Operation.VERIFY_RESTORE_BLOCKED
