from code.pipeline.steps.sorter import sort_and_number_steps
from code.schemas.enums import OPERATION_SPEC, DeletionStatus, Operation
from code.schemas.findings import Finding
from code.schemas.inputs import RequiredAction
from code.schemas.outputs import AuditResult, Step
from collections.abc import Sequence


def create_step(
    operation: Operation,
    system_id: str,
    resource_id: str,
    evidence_id: str = "",
    step_no: int = 1,
) -> Step:
    """Create a validated Step instance with automatic phase and state pairing."""
    phase, state = OPERATION_SPEC[operation]
    return Step(
        step_no=step_no,
        phase=phase,
        system_id=system_id,
        resource_id=resource_id,
        operation=operation,
        state=state,
        evidence_id=evidence_id,
    )


def expand_finding(
    finding: Finding,
    action: RequiredAction = RequiredAction.DELETE,
) -> list[Step]:
    """Expand a Finding into finding, remediation, and post-verification steps."""
    # 1. Finding step
    f_phase, f_state = OPERATION_SPEC[finding.kind]
    finding_step = Step(
        step_no=1,
        phase=f_phase,
        system_id=finding.system_id,
        resource_id=finding.resource_id,
        operation=finding.kind,
        state=f_state,
        evidence_id=finding.evidence_id,
    )

    # 2. Remediation and Verification pair
    if finding.kind == Operation.REPORT_ACTIVE_DATA_FLOW:
        rem_op = Operation.DISABLE_DATA_FLOW
        ver_op = Operation.VERIFY_DATA_FLOW_DISABLED
    elif finding.kind == Operation.REPORT_RESTORE_RISK:
        rem_op = Operation.BLOCK_RESTORE
        ver_op = Operation.VERIFY_RESTORE_BLOCKED
    elif finding.kind == Operation.REPORT_EXPOSED_PII:
        if action == RequiredAction.ANONYMIZE:
            rem_op = Operation.ANONYMIZE_RECORD
            ver_op = Operation.VERIFY_RECORD_ANONYMIZED
        else:
            rem_op = Operation.REDACT_RECORD
            ver_op = Operation.VERIFY_RECORD_REDACTED
    else:  # REPORT_REMAINING_RECORD
        if action == RequiredAction.REDACT:
            rem_op = Operation.REDACT_RECORD
            ver_op = Operation.VERIFY_RECORD_REDACTED
        elif action == RequiredAction.ANONYMIZE:
            rem_op = Operation.ANONYMIZE_RECORD
            ver_op = Operation.VERIFY_RECORD_ANONYMIZED
        else:
            rem_op = Operation.DELETE_RECORD
            ver_op = Operation.VERIFY_RECORD_ABSENT

    rem_phase, rem_state = OPERATION_SPEC[rem_op]
    remediation_step = Step(
        step_no=1,
        phase=rem_phase,
        system_id=finding.system_id,
        resource_id=finding.resource_id,
        operation=rem_op,
        state=rem_state,
        evidence_id="",
    )

    ver_phase, ver_state = OPERATION_SPEC[ver_op]
    verification_step = Step(
        step_no=1,
        phase=ver_phase,
        system_id=finding.system_id,
        resource_id=finding.resource_id,
        operation=ver_op,
        state=ver_state,
        evidence_id="",
    )

    return [finding_step, remediation_step, verification_step]


def build_audit_result(
    case_id: str,
    status: DeletionStatus,
    steps: Sequence[Step] = (),
) -> AuditResult:
    """Build and validate an AuditResult ensuring consecutive step ordering."""
    if status == DeletionStatus.NOT_APPLICABLE:
        ordered_steps = []
    else:
        ordered_steps = sort_and_number_steps(steps)

    return AuditResult(
        case_id=case_id,
        deletion_status=status,
        steps=ordered_steps,
    )
