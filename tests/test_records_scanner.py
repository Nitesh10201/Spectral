import json
from code.detectors.records.scanner import JsonRecordsScanner
from code.pipeline.runner.context import CaseContext, SubjectContext
from code.schemas.enums import Operation, State
from code.schemas.inputs import DeletionRequest, EvidenceFile, ReportedStatus
from datetime import datetime
from pathlib import Path


def test_json_records_scanner_service_exports(tmp_path: Path):
    """Test service_resource_export JSON scanning for search findings, analytics anonymization, and flow."""
    records_dir = tmp_path / "records"
    records_dir.mkdir(parents=True)
    export_json = records_dir / "service_export.json"

    export_json.write_text(
        json.dumps(
            {
                "exported_at": "2026-09-15T11:44:55Z",
                "service_exports": {
                    "search_service": {
                        "index_queries": [
                            {
                                "resource_id": "search_synth_01",
                                "hits": {
                                    "documents": [{"email": "synth_alice@example.com"}]
                                },
                            }
                        ]
                    },
                    "analytics_platform": {
                        "profiles": [
                            {
                                "resource_id": "analytics_synth_01",
                                "customer_reference": "user_synth_01",
                                "email": None,
                                "phone": None,
                            }
                        ]
                    },
                    "integration_service": {
                        "connectors": [
                            {
                                "resource_id": "flow_synth_01",
                                "customer_email": "synth_alice@example.com",
                                "enabled": True,
                            }
                        ]
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    scanner = JsonRecordsScanner(dataset_dir=tmp_path)
    subject = SubjectContext(
        user_id="user_synth_01",
        current_email="synth_alice@example.com",
        emails=frozenset({"synth_alice@example.com"}),
    )
    req = DeletionRequest(
        case_id="case_synth_rec_01",
        email="synth_alice@example.com",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-20T12:00:00+00:00"),
        request_text="Delete my account",
    )
    ef = EvidenceFile(
        file_id="evidence_rec_01",
        file_path="records/service_export.json",
        origin="test_origin",
        captured_at=datetime.fromisoformat("2026-09-15T12:00:00+00:00"),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef],
    )
    res = scanner.detect(ctx)

    # Search: remaining record
    # Flow: active data flow
    assert len(res.findings) == 2
    f_ops = {f.kind for f in res.findings}
    assert Operation.REPORT_REMAINING_RECORD in f_ops
    assert Operation.REPORT_ACTIVE_DATA_FLOW in f_ops

    # Analytics: verified anonymized
    assert len(res.verifications) == 1
    v = res.verifications[0]
    assert v.operation == Operation.VERIFY_RECORD_ANONYMIZED
    assert v.resource_id == "analytics_synth_01"


def test_json_records_scanner_tombstones_and_audit(tmp_path: Path):
    """Test customer_data_snapshot_bundle for tombstone PII and audit events."""
    records_dir = tmp_path / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    bundle_json = records_dir / "snapshot_bundle.json"

    bundle_json.write_text(
        json.dumps(
            {
                "exported_at": "2026-09-15T12:00:00Z",
                "snapshots": [
                    {
                        "data_store": "identity_service",
                        "collection": "deleted_customer_references",
                        "records": [
                            {
                                "resource_id": "tombstone_synth_01",
                                "subject_reference": "user_synth_02",
                                "name": "Bob Test",
                                "email": "bob@example.com",
                                "phone": "+19999999999",
                            }
                        ],
                    },
                    {
                        "data_store": "security_service",
                        "collection": "security_audit_events",
                        "records": [
                            {
                                "resource_id": "audit_synth_01",
                                "subject_reference": "user_synth_02",
                                "event_name": "account_deletion_reviewed",
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    scanner = JsonRecordsScanner(dataset_dir=tmp_path)
    subject = SubjectContext(
        user_id="user_synth_02",
        current_email="bob@example.com",
        emails=frozenset({"bob@example.com"}),
    )
    req = DeletionRequest(
        case_id="case_synth_rec_02",
        email="bob@example.com",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-20T12:00:00+00:00"),
        request_text="Delete my profile",
    )
    ef = EvidenceFile(
        file_id="evidence_rec_02",
        file_path="records/snapshot_bundle.json",
        origin="test_origin",
        captured_at=datetime.fromisoformat("2026-09-15T12:00:00+00:00"),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef],
    )
    res = scanner.detect(ctx)

    # Tombstone with exposed PII -> REPORT_EXPOSED_PII
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.kind == Operation.REPORT_EXPOSED_PII
    assert f.resource_id == "tombstone_synth_01"
    assert f.system_id == "identity_service"

    # Security audit event -> VERIFY_RECORD_PRESENT
    assert len(res.verifications) == 1
    v = res.verifications[0]
    assert v.operation == Operation.VERIFY_RECORD_PRESENT
    assert v.resource_id == "audit_synth_01"
    assert v.state == State.PRESENT
