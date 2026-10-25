from code.config import (
    DELETION_RULES_PATH,
    EVIDENCE_FILES_PATH,
    SAMPLE_DELETION_REQUESTS_PATH,
    SYSTEM_ACTIVITY_PATH,
    USER_AUDIT_LOG_PATH,
    USER_IDENTITIES_PATH,
)
from code.filesystem.reader.csv_reader import (
    _clean_row,
    read_deletion_requests,
    read_deletion_rules,
    read_evidence_files,
    read_system_activity,
    read_user_audit_log,
    read_user_identities,
)
from code.schemas.inputs import (
    ActivityRecord,
    AuditLogEntry,
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
    ReportedResult,
    ReportedStatus,
    RequiredAction,
    UserIdentity,
)
from pathlib import Path


def test_clean_row_converts_empty_and_whitespace_to_none():
    raw_row = {
        "user_id": "user_01",
        "name": "",
        "phone": "   ",
        "email": "test@example.com",
        "note": None,
    }
    cleaned = _clean_row(raw_row)
    assert cleaned["user_id"] == "user_01"
    assert cleaned["name"] is None
    assert cleaned["phone"] is None
    assert cleaned["email"] == "test@example.com"
    assert cleaned["note"] is None


def test_read_deletion_requests_default_path():
    requests = read_deletion_requests()
    assert len(requests) == 518
    assert all(isinstance(r, DeletionRequest) for r in requests)
    first = requests[0]
    assert first.case_id == "case_33"
    assert first.email == "ingrid.dahl@outlook.com"
    assert isinstance(first.reported_status, ReportedStatus)
    assert first.audit_at is not None


def test_read_deletion_requests_custom_path():
    requests = read_deletion_requests(SAMPLE_DELETION_REQUESTS_PATH)
    assert len(requests) == 32
    assert all(isinstance(r, DeletionRequest) for r in requests)
    assert requests[0].case_id == "case_01"


def test_read_user_identities():
    identities = read_user_identities(USER_IDENTITIES_PATH)
    assert len(identities) == 850
    assert all(isinstance(u, UserIdentity) for u in identities)
    first = identities[0]
    assert first.user_id == "user_01"
    assert first.email == "amina.elmasri@gmail.com"
    assert first.email_hash is not None


def test_read_user_audit_log():
    audit_entries = read_user_audit_log(USER_AUDIT_LOG_PATH)
    assert len(audit_entries) == 306
    assert all(isinstance(e, AuditLogEntry) for e in audit_entries)
    first = audit_entries[0]
    assert first.audit_id == "audit_01"
    assert first.user_id == "user_485"
    assert first.field_name == "phone"


def test_read_system_activity():
    activities = read_system_activity(SYSTEM_ACTIVITY_PATH)
    assert len(activities) == 4011
    assert all(isinstance(a, ActivityRecord) for a in activities)
    first = activities[0]
    assert first.activity_id == "activity_01"
    assert first.event_type == "INDEX_RECORD"
    assert isinstance(first.reported_result, ReportedResult)


def test_read_deletion_rules():
    rules = read_deletion_rules(DELETION_RULES_PATH)
    assert len(rules) == 15
    assert all(isinstance(r, DeletionRule) for r in rules)
    first = rules[0]
    assert first.rule_id == "rule_01"
    assert first.data_category == "USER_PROFILE"
    assert first.required_action == RequiredAction.DELETE


def test_read_evidence_files():
    evidence_files = read_evidence_files(EVIDENCE_FILES_PATH)
    assert len(evidence_files) == 94
    assert all(isinstance(ef, EvidenceFile) for ef in evidence_files)
    first = evidence_files[0]
    assert first.file_id == "evidence_01"
    assert first.file_path.startswith("evidence/")
    assert first.captured_at is not None


def test_csv_reader_with_temporary_file(tmp_path: Path):
    temp_csv = tmp_path / "custom_requests.csv"
    temp_csv.write_text(
        "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
        "case_999,test@domain.com,2026-08-01T00:00:00Z,NOT_STARTED,,2026-08-02T00:00:00Z,Please delete my data\n",
        encoding="utf-8",
    )
    result = read_deletion_requests(temp_csv)
    assert len(result) == 1
    req = result[0]
    assert req.case_id == "case_999"
    assert req.reported_at is None
    assert req.reported_status == ReportedStatus.NOT_STARTED
