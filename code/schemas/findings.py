from pydantic import BaseModel, model_validator

from .enums import Operation, Phase, OPERATION_SPEC


class Finding(BaseModel):
    """What detectors return. The step builder expands each one into
    finding + remediation + verification steps."""
    system_id: str
    resource_id: str
    kind: Operation            # must be one of the four REPORT_* operations
    evidence_id: str
    data_category: str | None = None   # lets the rules engine pick delete/redact/anonymize
    detail: str | None = None          # free text for debugging, never output

    @model_validator(mode="after")
    def must_be_finding(self):
        if OPERATION_SPEC[self.kind][0] != Phase.FINDING:
            raise ValueError("Finding.kind must be a REPORT_* operation")
        return self