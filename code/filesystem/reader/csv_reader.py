import csv
from code.config import (
    DELETION_REQUESTS_PATH,
    DELETION_RULES_PATH,
    EVIDENCE_FILES_PATH,
    REPO_ROOT,
    SYSTEM_ACTIVITY_PATH,
    USER_AUDIT_LOG_PATH,
    USER_IDENTITIES_PATH,
)
from code.schemas.inputs import (
    ActivityRecord,
    AuditLogEntry,
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
    UserIdentity,
)
from pathlib import Path

from pydantic import BaseModel


def _clean_row(row: dict[str, str | None]) -> dict[str, str | None]:
    """Convert empty strings or whitespace-only strings to None before validation."""
    cleaned: dict[str, str | None] = {}
    for key, value in row.items():
        if value is None:
            cleaned[key] = None
        else:
            val_str = str(value).strip()
            cleaned[key] = val_str if val_str != "" else None
    return cleaned


def _read_csv_to_models[T: BaseModel](path: str | Path, model_cls: type[T]) -> list[T]:
    resolved_path = Path(path)
    if not resolved_path.is_absolute():
        resolved_path = (REPO_ROOT / resolved_path).resolve()
    with open(resolved_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [model_cls.model_validate(_clean_row(row)) for row in reader]


def read_deletion_requests(
    path: str | Path = DELETION_REQUESTS_PATH,
) -> list[DeletionRequest]:
    """Read deletion requests CSV into a list of DeletionRequest models."""
    return _read_csv_to_models(path, DeletionRequest)


def read_user_identities(path: str | Path = USER_IDENTITIES_PATH) -> list[UserIdentity]:
    """Read user identities CSV into a list of UserIdentity models."""
    return _read_csv_to_models(path, UserIdentity)


def read_user_audit_log(path: str | Path = USER_AUDIT_LOG_PATH) -> list[AuditLogEntry]:
    """Read user audit log CSV into a list of AuditLogEntry models."""
    return _read_csv_to_models(path, AuditLogEntry)


def read_system_activity(
    path: str | Path = SYSTEM_ACTIVITY_PATH,
) -> list[ActivityRecord]:
    """Read system activity CSV into a list of ActivityRecord models."""
    return _read_csv_to_models(path, ActivityRecord)


def read_deletion_rules(path: str | Path = DELETION_RULES_PATH) -> list[DeletionRule]:
    """Read deletion rules CSV into a list of DeletionRule models."""
    return _read_csv_to_models(path, DeletionRule)


def read_evidence_files(path: str | Path = EVIDENCE_FILES_PATH) -> list[EvidenceFile]:
    """Read evidence manifest CSV into a list of EvidenceFile models."""
    return _read_csv_to_models(path, EvidenceFile)
