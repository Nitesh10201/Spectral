from code.detectors.sql.checker import SqlSnapshotChecker
from code.pipeline.runner.context import CaseContext, SubjectContext
from code.schemas.enums import Operation, Phase, State
from code.schemas.inputs import DeletionRequest, EvidenceFile, ReportedStatus
from datetime import datetime
from pathlib import Path


def test_sql_checker_temporal_filter(tmp_path: Path):
    """Evidence files captured after audit_at must be completely ignored."""
    sql_file = tmp_path / "replica_future.sql"
    sql_file.write_text(
        """
        CREATE TABLE customer_data_read_replica (
            resource_id TEXT,
            origin_system TEXT,
            collection_name TEXT,
            record_json TEXT,
            updated_at TEXT
        );
        INSERT INTO customer_data_read_replica VALUES (
            'search_999', 'search_service', 'customer_search_documents',
            '{"email":"alice@example.org"}', '2026-10-01T12:00:00Z'
        );
        """,
        encoding="utf-8",
    )

    checker = SqlSnapshotChecker(dataset_dir=tmp_path)
    subject = SubjectContext(
        user_id="user_test_01",
        current_email="alice@example.org",
        emails=frozenset({"alice@example.org"}),
    )
    req = DeletionRequest(
        case_id="case_synth_01",
        email="alice@example.org",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-15T12:00:00+00:00"),
        request_text="Delete my data please",
    )
    # Evidence captured AFTER audit_at
    future_ef = EvidenceFile(
        file_id="evidence_future",
        file_path="replica_future.sql",
        origin="test_origin",
        captured_at=datetime.fromisoformat("2026-09-20T12:00:00+00:00"),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[future_ef],
    )
    res = checker.detect(ctx)
    assert len(res.findings) == 0
    assert len(res.verifications) == 0


def test_sql_checker_generic_tables_finding_and_verification(tmp_path: Path):
    """Generic table replica checks: search remaining record, analytics exposed vs anonymized."""
    sql_file = tmp_path / "replica_past.sql"
    sql_file.write_text(
        """
        CREATE TABLE customer_data_read_replica (
            resource_id TEXT,
            origin_system TEXT,
            collection_name TEXT,
            record_json TEXT,
            updated_at TEXT
        );
        INSERT INTO customer_data_read_replica VALUES (
            'search_101', 'search_service', 'customer_search_documents',
            '{"document":{"email":"bob@example.com","customer_reference":"user_test_02"}}',
            '2026-09-10T10:00:00Z'
        );
        INSERT INTO customer_data_read_replica VALUES (
            'analytics_202', 'analytics_platform', 'customer_analytics_reports',
            '{"resource_id":"analytics_202","email":"bob@example.com","phone":"+15551234567"}',
            '2026-09-10T10:00:00Z'
        );
        """,
        encoding="utf-8",
    )

    checker = SqlSnapshotChecker(dataset_dir=tmp_path)
    subject = SubjectContext(
        user_id="user_test_02",
        current_email="bob@example.com",
        emails=frozenset({"bob@example.com"}),
        phones=frozenset({"+15551234567"}),
    )
    req = DeletionRequest(
        case_id="case_synth_02",
        email="bob@example.com",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.PARTIALLY_COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-15T12:00:00+00:00"),
        request_text="Delete my data",
    )
    ef = EvidenceFile(
        file_id="evidence_valid",
        file_path="replica_past.sql",
        origin="test_origin",
        captured_at=datetime.fromisoformat("2026-09-12T10:00:00+00:00"),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef],
    )
    res = checker.detect(ctx)

    assert len(res.findings) == 2
    f_ops = {f.kind for f in res.findings}
    assert Operation.REPORT_REMAINING_RECORD in f_ops
    assert Operation.REPORT_EXPOSED_PII in f_ops

    search_f = next(f for f in res.findings if f.system_id == "search_service")
    assert search_f.resource_id == "search_101"
    assert search_f.kind == Operation.REPORT_REMAINING_RECORD

    analytics_f = next(f for f in res.findings if f.system_id == "analytics_platform")
    assert analytics_f.resource_id == "analytics_202"
    assert analytics_f.kind == Operation.REPORT_EXPOSED_PII


def test_sql_checker_failover_drift_and_inventory(tmp_path: Path):
    """Checks failover replica drift and inventory backup restore risk."""
    failover_sql = tmp_path / "customer_accounts_failover_replica_20260902.sql"
    failover_sql.write_text(
        """
        CREATE TABLE customer_profiles_failover_replica (
            resource_id TEXT,
            user_id TEXT,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            account_status TEXT,
            updated_at TEXT
        );
        INSERT INTO customer_profiles_failover_replica VALUES (
            'account_005', 'user_05', 'Charlie Test', 'charlie@example.com', '+123456789', 'ACTIVE', '2026-09-02T22:00:00Z'
        );
        """,
        encoding="utf-8",
    )

    inv_sql = tmp_path / "customer_data_inventory_20260910.sql"
    inv_sql.write_text(
        """
        CREATE TABLE backup_restore_entries (
            resource_id TEXT,
            customer_reference TEXT,
            customer_email TEXT,
            archive_key TEXT,
            restore_allowed INTEGER,
            updated_at TEXT
        );
        INSERT INTO backup_restore_entries VALUES (
            'backup_888', 'user_05', 'charlie@example.com', 'archive/backup_888.tar.zst', 1, '2026-09-10T08:00:00Z'
        );
        CREATE TABLE connector_subscriptions (
            resource_id TEXT,
            customer_reference TEXT,
            customer_email TEXT,
            enabled INTEGER,
            updated_at TEXT
        );
        INSERT INTO connector_subscriptions VALUES (
            'flow_777', 'user_05', 'charlie@example.com', 0, '2026-09-10T08:00:00Z'
        );
        CREATE TABLE security_audit_records (
            resource_id TEXT,
            subject_reference TEXT,
            event_code TEXT,
            retention_until TEXT,
            updated_at TEXT
        );
        INSERT INTO security_audit_records VALUES (
            'audit_555', 'user_05', 'ACCOUNT_DELETION_RECORDED', '2030-01-01T00:00:00Z', '2026-09-10T08:00:00Z'
        );
        """,
        encoding="utf-8",
    )

    checker = SqlSnapshotChecker(dataset_dir=tmp_path)
    subject = SubjectContext(
        user_id="user_05",
        current_email="charlie@example.com",
        emails=frozenset({"charlie@example.com"}),
    )
    req = DeletionRequest(
        case_id="case_synth_03",
        email="charlie@example.com",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-15T12:00:00+00:00"),
        request_text="Close account",
    )
    ef1 = EvidenceFile(
        file_id="evidence_54",
        file_path="customer_accounts_failover_replica_20260902.sql",
        origin="failover_capture",
        captured_at=datetime.fromisoformat("2026-09-02T23:00:00+00:00"),
    )
    ef2 = EvidenceFile(
        file_id="evidence_93",
        file_path="customer_data_inventory_20260910.sql",
        origin="inventory_capture",
        captured_at=datetime.fromisoformat("2026-09-10T09:00:00+00:00"),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef1, ef2],
    )
    res = checker.detect(ctx)

    # Findings:
    # 1. account_005 ACTIVE in failover -> REPORT_REMAINING_RECORD
    # 2. backup_888 restore_allowed=1 -> REPORT_RESTORE_RISK
    assert len(res.findings) == 2
    f_map = {f.system_id: f for f in res.findings}
    assert f_map["account_service"].kind == Operation.REPORT_REMAINING_RECORD
    assert f_map["account_service"].resource_id == "account_005"
    assert f_map["backup_service"].kind == Operation.REPORT_RESTORE_RISK
    assert f_map["backup_service"].resource_id == "backup_888"

    # Verifications:
    # 1. connector flow_777 enabled=0 -> VERIFY_DATA_FLOW_DISABLED
    # 2. security audit_555 -> VERIFY_RECORD_PRESENT
    assert len(res.verifications) == 2
    v_map = {v.system_id: v for v in res.verifications}
    assert v_map["integration_service"].operation == Operation.VERIFY_DATA_FLOW_DISABLED
    assert v_map["integration_service"].state == State.DISABLED
    assert v_map["security_service"].operation == Operation.VERIFY_RECORD_PRESENT
    assert v_map["security_service"].state == State.PRESENT


def test_sql_checker_absent_account_verification(tmp_path: Path):
    """When account is absent from failover snapshot and no findings, verify absent account."""
    failover_sql = tmp_path / "customer_accounts_failover_replica_20260902.sql"
    failover_sql.write_text(
        """
        CREATE TABLE customer_profiles_failover_replica (
            resource_id TEXT,
            user_id TEXT,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            account_status TEXT,
            updated_at TEXT
        );
        -- Subject is absent
        INSERT INTO customer_profiles_failover_replica VALUES (
            'account_999', 'user_999', 'Other User', 'other@example.com', '+111111', 'ACTIVE', '2026-09-02T22:00:00Z'
        );
        """,
        encoding="utf-8",
    )

    checker = SqlSnapshotChecker(dataset_dir=tmp_path)
    subject = SubjectContext(
        user_id="user_01",
        current_email="dan@example.com",
        emails=frozenset({"dan@example.com"}),
    )
    req = DeletionRequest(
        case_id="case_synth_04",
        email="dan@example.com",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-15T12:00:00+00:00"),
        request_text="Delete my account",
    )
    ef1 = EvidenceFile(
        file_id="evidence_54",
        file_path="customer_accounts_failover_replica_20260902.sql",
        origin="failover_capture",
        captured_at=datetime.fromisoformat("2026-09-02T23:00:00+00:00"),
    )

    ctx = CaseContext(
        request=req,
        subject=subject,
        evidence_files=[ef1],
    )
    res = checker.detect(ctx)

    assert len(res.findings) == 0
    assert len(res.verifications) == 1
    v = res.verifications[0]
    assert v.phase == Phase.VERIFICATION
    assert v.operation == Operation.VERIFY_RECORD_ABSENT
    assert v.system_id == "account_service"
    assert v.resource_id == "account_001"
    assert v.evidence_id == "evidence_54"
