from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class ReportedStatus(str, Enum):  # or import from enums.py
    COMPLETE = "COMPLETE"
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    NOT_STARTED = "NOT_STARTED"


class RequiredAction(str, Enum):
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


class ReportedResult(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class DeletionRequest(BaseModel):
    case_id: str
    email: str
    requested_at: datetime
    reported_status: ReportedStatus
    reported_at: datetime | None = None
    audit_at: datetime
    request_text: str


class UserIdentity(BaseModel):
    user_id: str
    name: str | None = None
    email: str | None = None
    phone: str | None = None
    email_hash: str | None = None  # SHA-256 hex of the email
    updated_at: datetime | None = None


class AuditLogEntry(BaseModel):
    audit_id: str  # citable as evidence_id
    user_id: str
    event_time: datetime
    field_name: str  # seen: email, phone (check for others)
    old_value: str | None = None
    new_value: str | None = None


class ActivityRecord(BaseModel):
    activity_id: str  # citable as evidence_id
    event_time: datetime
    event_type: str  # keep str until you list all values
    source_system: str | None = None
    target_system: str | None = None
    resource_id: str | None = None
    reported_result: ReportedResult
    details: str | None = None


class DeletionRule(BaseModel):
    rule_id: str
    data_category: str  # str: the dataset defines the categories
    condition: str  # free text, e.g. "Always"
    required_action: RequiredAction


class EvidenceFile(BaseModel):
    file_id: str  # citable as evidence_id
    file_path: str  # relative to dataset/
    origin: str | None = None
    captured_at: datetime  # must be <= audit_at to count


# Reader helper: CSV blanks arrive as "" and must become None before validation
