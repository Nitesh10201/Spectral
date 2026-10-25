from pydantic import BaseModel, Field, model_validator

from .enums import (
    OPERATION_ORDER,
    OPERATION_SPEC,
    PHASE_ORDER,
    DeletionStatus,
    Operation,
    Phase,
    State,
)


class Step(BaseModel):
    step_no: int = Field(ge=1)
    phase: Phase
    system_id: str
    resource_id: str
    operation: Operation
    state: State
    evidence_id: str = ""

    @model_validator(mode="after")
    def check_operation_pairing(self):
        phase, state = OPERATION_SPEC[self.operation]
        if self.phase != phase or self.state != state:
            raise ValueError(
                f"{self.operation.value} requires phase={phase.value}, state={state.value}"
            )
        return self


class AuditResult(BaseModel):
    case_id: str
    deletion_status: DeletionStatus
    steps: list[Step] = []

    @model_validator(mode="after")
    def check_contract(self):
        s = self.steps
        if [x.step_no for x in s] != list(range(1, len(s) + 1)):
            raise ValueError("step_no must be consecutive from 1")

        keys = [(PHASE_ORDER[x.phase], OPERATION_ORDER[x.operation],
                 x.system_id, x.resource_id) for x in s]
        if keys != sorted(keys):
            raise ValueError("steps are not in the required order")

        if self.deletion_status == DeletionStatus.NOT_APPLICABLE and s:
            raise ValueError("NOT_APPLICABLE must have no steps")

        if self.deletion_status == DeletionStatus.COMPLETE:
            if any(x.phase != Phase.VERIFICATION for x in s):
                raise ValueError("COMPLETE allows only VERIFICATION steps")
            if any(not x.evidence_id for x in s):
                raise ValueError("COMPLETE verification steps must cite evidence")

        if self.deletion_status == DeletionStatus.INCOMPLETE:
            for x in s:
                if x.phase == Phase.FINDING and not x.evidence_id:
                    raise ValueError("findings must cite evidence")
                if x.phase == Phase.REMEDIATION and x.evidence_id:
                    raise ValueError("remediation steps use an empty evidence_id")
        return self