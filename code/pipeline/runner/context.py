from code.schemas.findings import Finding
from code.schemas.inputs import (
    ActivityRecord,
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
)
from code.schemas.outputs import Step
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class SubjectContext:
    """Consolidated current and historical identity context for a subject as of audit_at."""

    user_id: str
    current_email: str
    emails: frozenset[str] = frozenset()
    phones: frozenset[str] = frozenset()
    email_hashes: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    account_ids: frozenset[str] = frozenset()


@dataclass
class DetectionResult:
    """Output emitted by a detector during investigation."""

    findings: list[Finding] = field(default_factory=list)
    verifications: list[Step] = field(default_factory=list)


@dataclass
class CaseContext:
    """Execution context provided to pluggable detectors for a single case."""

    request: DeletionRequest
    subject: SubjectContext | None = None
    rules: list[DeletionRule] = field(default_factory=list)
    evidence_files: list[EvidenceFile] = field(default_factory=list)
    system_activity: list[ActivityRecord] = field(default_factory=list)

    @property
    def audit_at(self) -> datetime:
        return self.request.audit_at

    def filter_evidence_before_audit(self) -> list[EvidenceFile]:
        """Return evidence files captured on or before audit_at."""
        return [ef for ef in self.evidence_files if ef.captured_at <= self.audit_at]


class Detector(Protocol):
    """Protocol that all pluggable evidence detectors must implement."""

    def detect(self, ctx: CaseContext) -> DetectionResult:
        """Analyze evidence within the case context and return findings/verifications."""
        ...
