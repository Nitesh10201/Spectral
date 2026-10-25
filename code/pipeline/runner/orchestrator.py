from code.config import DELETION_REQUESTS_PATH, OUTPUT_PATH
from code.filesystem.reader import (
    read_deletion_requests,
    read_deletion_rules,
    read_evidence_files,
    read_system_activity,
)
from code.filesystem.writer import write_output_csv
from code.pipeline.runner.context import CaseContext, Detector, SubjectContext
from code.pipeline.steps.builder import build_audit_result, expand_finding
from code.schemas.enums import DeletionStatus
from code.schemas.inputs import (
    ActivityRecord,
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
    RequiredAction,
)
from code.schemas.outputs import AuditResult, Step
from collections.abc import Callable, Sequence
from pathlib import Path


class PipelineOrchestrator:
    """Coordinates classification, identity resolution, detectors, step building, and output writing."""

    def __init__(
        self,
        detectors: Sequence[Detector] = (),
        classifier: Callable[[DeletionRequest], bool] | None = None,
        identity_resolver: Callable[[DeletionRequest], SubjectContext | None]
        | None = None,
        rules: Sequence[DeletionRule] | None = None,
        evidence_files: Sequence[EvidenceFile] | None = None,
        system_activity: Sequence[ActivityRecord] | None = None,
    ) -> None:
        self.detectors: list[Detector] = list(detectors)
        self.classifier = classifier
        self.identity_resolver = identity_resolver
        self.rules: list[DeletionRule] = list(rules) if rules is not None else []
        self.evidence_files: list[EvidenceFile] = (
            list(evidence_files) if evidence_files is not None else []
        )
        self.system_activity: list[ActivityRecord] = (
            list(system_activity) if system_activity is not None else []
        )

    def register_detector(self, detector: Detector) -> None:
        """Register a new evidence detector plugin."""
        self.detectors.append(detector)

    def load_defaults_if_empty(self) -> None:
        """Lazy load rules, evidence manifest, and activity from disk if not supplied."""
        if not self.rules:
            try:
                self.rules = read_deletion_rules()
            except OSError:
                self.rules = []
        if not self.evidence_files:
            try:
                self.evidence_files = read_evidence_files()
            except OSError:
                self.evidence_files = []
        if not self.system_activity:
            try:
                self.system_activity = read_system_activity()
            except OSError:
                self.system_activity = []

    def audit_case(self, request: DeletionRequest) -> AuditResult:
        """Audit a single case end-to-end and produce the compliant AuditResult."""
        # 1. Intent Classification Check
        if self.classifier is not None and not self.classifier(request):
            return build_audit_result(
                case_id=request.case_id,
                status=DeletionStatus.NOT_APPLICABLE,
                steps=[],
            )

        # 2. Resolve Subject Identity
        subject = None
        if self.identity_resolver is not None:
            subject = self.identity_resolver(request)

        ctx = CaseContext(
            request=request,
            subject=subject,
            rules=self.rules,
            evidence_files=self.evidence_files,
            system_activity=self.system_activity,
        )

        # 3. Execute Pluggable Detectors
        all_findings = []
        all_verifications = []

        for detector in self.detectors:
            result = detector.detect(ctx)
            all_findings.extend(result.findings)
            all_verifications.extend(result.verifications)

        # 4. Formulate Verdict and Step Sequence
        if all_findings:
            # INCOMPLETE
            remediation_steps: list[Step] = []
            for finding in all_findings:
                # Determine action from finding data_category if available
                action = self._resolve_action(finding.data_category)
                steps = expand_finding(finding, action)
                remediation_steps.extend(steps)

            # In INCOMPLETE cases, any retained-record verification steps use evidence_id=""
            for v in all_verifications:
                remediation_steps.append(v.model_copy(update={"evidence_id": ""}))

            return build_audit_result(
                case_id=request.case_id,
                status=DeletionStatus.INCOMPLETE,
                steps=remediation_steps,
            )

        # COMPLETE
        # Verification steps proving compliant state, must cite evidence
        complete_verifications = [v for v in all_verifications if v.evidence_id != ""]
        return build_audit_result(
            case_id=request.case_id,
            status=DeletionStatus.COMPLETE,
            steps=complete_verifications,
        )

    def _resolve_action(self, data_category: str | None) -> RequiredAction:
        """Resolve policy action for a given data category."""
        if not data_category:
            return RequiredAction.DELETE

        for r in self.rules:
            if r.data_category.upper() == data_category.upper():
                return r.required_action

        return RequiredAction.DELETE

    def audit_all(self, requests: Sequence[DeletionRequest]) -> list[AuditResult]:
        """Audit a batch of requests sequentially."""
        return [self.audit_case(r) for r in requests]

    def run_pipeline(
        self,
        requests_path: str | Path = DELETION_REQUESTS_PATH,
        output_path: str | Path = OUTPUT_PATH,
    ) -> Path:
        """Run the end-to-end pipeline from CSV input to output.csv."""
        self.load_defaults_if_empty()
        requests = read_deletion_requests(requests_path)
        results = self.audit_all(requests)
        write_output_csv(results, output_path)
        return Path(output_path)
