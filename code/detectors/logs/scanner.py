import re
from code.config import DATASET_DIR
from code.pipeline.runner.context import CaseContext, DetectionResult, SubjectContext
from code.schemas.enums import Operation, Phase, State
from code.schemas.findings import Finding
from code.schemas.inputs import EvidenceFile
from code.schemas.outputs import Step
from pathlib import Path

KV_REGEX = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')


def _parse_log_kv(line: str) -> dict[str, str]:
    """Parse key=value or key=\"value\" pairs from a log line."""
    parsed: dict[str, str] = {}
    for match in KV_REGEX.finditer(line):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        parsed[key] = val
    return parsed


def _line_mentions_subject(line: str, kv: dict[str, str], subject: SubjectContext) -> bool:
    """Check whether a log line refers to the subject."""
    # Fast string check
    if subject.user_id in line:
        return True
    for em in subject.emails:
        if em in line.lower():
            return True
    for ph in subject.phones:
        if ph in line:
            return True
    for eh in subject.email_hashes:
        if eh in line.lower():
            return True

    # Check parsed fields
    sref = kv.get("subject_reference") or kv.get("customer_reference")
    if sref and sref == subject.user_id:
        return True
    lkey = kv.get("lookup_key", "").strip().lower()
    if lkey in subject.emails or lkey == subject.user_id:
        return True
    ckey = kv.get("correlation_key", "").strip().lower()
    return bool(ckey in subject.emails or ckey in subject.email_hashes)


class TextLogScanner:
    """Pluggable detector that analyzes service log files and traces for findings and verifications."""

    def __init__(self, dataset_dir: Path | str | None = None) -> None:
        self.dataset_dir = Path(dataset_dir) if dataset_dir is not None else DATASET_DIR

    def detect(self, ctx: CaseContext) -> DetectionResult:
        result = DetectionResult()
        subject = ctx.subject
        if not subject:
            return result

        log_evidence = [
            ef
            for ef in ctx.evidence_files
            if ef.file_path.endswith(".log") and ef.captured_at <= ctx.audit_at
        ]
        if not log_evidence:
            return result

        log_evidence.sort(key=lambda x: x.captured_at, reverse=True)

        seen_findings: set[tuple[str, str, Operation]] = set()
        seen_verifications: set[tuple[str, str, Operation]] = set()

        for ef in log_evidence:
            full_path = self.dataset_dir / ef.file_path
            if not full_path.exists():
                continue

            try:
                with open(full_path, mode="r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        kv = _parse_log_kv(line)
                        if not _line_mentions_subject(line, kv, subject):
                            continue

                        self._process_log_entry(
                            kv, ef, subject, result, seen_findings, seen_verifications
                        )
            except OSError:
                continue

        return result

    def _process_log_entry(
        self,
        kv: dict[str, str],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
        seen_verifications: set[tuple[str, str, Operation]],
    ) -> None:
        service = kv.get("service", "")
        if service == "support_replica":
            service = "support_platform"

        rid = kv.get("resource_id", "")
        if not rid:
            return

        # 1. Search service
        if service == "search_service":
            res_val = kv.get("result", "").lower()
            rows_val = kv.get("rows", "")
            if res_val == "hit" or rows_val == "1":
                key = ("search_service", rid, Operation.REPORT_REMAINING_RECORD)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="search_service",
                            resource_id=rid,
                            kind=Operation.REPORT_REMAINING_RECORD,
                            evidence_id=ef.file_id,
                            data_category="SEARCH_INDEX_ENTRY",
                        )
                    )

        # 2. Backup service
        elif service == "backup_service":
            eligible = kv.get("eligible", "").lower() == "true"
            del_block = kv.get("deletion_block", "").lower() == "true"
            if eligible and not del_block:
                key = ("backup_service", rid, Operation.REPORT_RESTORE_RISK)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="backup_service",
                            resource_id=rid,
                            kind=Operation.REPORT_RESTORE_RISK,
                            evidence_id=ef.file_id,
                            data_category="BACKUP_ARCHIVE",
                        )
                    )
            elif del_block:
                vkey = ("backup_service", rid, Operation.VERIFY_RESTORE_BLOCKED)
                if vkey not in seen_verifications:
                    seen_verifications.add(vkey)
                    result.verifications.append(
                        Step(
                            step_no=1,
                            phase=Phase.VERIFICATION,
                            system_id="backup_service",
                            resource_id=rid,
                            operation=Operation.VERIFY_RESTORE_BLOCKED,
                            state=State.BLOCKED,
                            evidence_id=ef.file_id,
                        )
                    )

        # 3. Integration service
        elif service == "integration_service":
            enabled = kv.get("enabled", "").lower() == "true"
            if enabled:
                key = ("integration_service", rid, Operation.REPORT_ACTIVE_DATA_FLOW)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="integration_service",
                            resource_id=rid,
                            kind=Operation.REPORT_ACTIVE_DATA_FLOW,
                            evidence_id=ef.file_id,
                        )
                    )
            else:
                vkey = (
                    "integration_service",
                    rid,
                    Operation.VERIFY_DATA_FLOW_DISABLED,
                )
                if vkey not in seen_verifications:
                    seen_verifications.add(vkey)
                    result.verifications.append(
                        Step(
                            step_no=1,
                            phase=Phase.VERIFICATION,
                            system_id="integration_service",
                            resource_id=rid,
                            operation=Operation.VERIFY_DATA_FLOW_DISABLED,
                            state=State.DISABLED,
                            evidence_id=ef.file_id,
                        )
                    )

        # 4. Support platform
        elif service == "support_platform":
            marker_found = kv.get("marker_found", "").lower() == "true"
            if "marker_found" in kv and not marker_found:
                key = ("support_platform", rid, Operation.REPORT_REMAINING_RECORD)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="support_platform",
                            resource_id=rid,
                            kind=Operation.REPORT_REMAINING_RECORD,
                            evidence_id=ef.file_id,
                            data_category="SUPPORT_ATTACHMENT",
                        )
                    )
            elif "requester_email" in kv and kv.get("requester_email") != "null":
                key = ("support_platform", rid, Operation.REPORT_EXPOSED_PII)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="support_platform",
                            resource_id=rid,
                            kind=Operation.REPORT_EXPOSED_PII,
                            evidence_id=ef.file_id,
                            data_category="SUPPORT_MESSAGE",
                        )
                    )

        # 5. Analytics platform
        elif service == "analytics_platform":
            # Check if anonymized or active
            em = kv.get("email", "")
            cref = kv.get("customer_reference", "")
            rows_val = kv.get("rows", "")
            if em == "null" and cref == "null":
                vkey = ("analytics_platform", rid, Operation.VERIFY_RECORD_ANONYMIZED)
                if vkey not in seen_verifications:
                    seen_verifications.add(vkey)
                    result.verifications.append(
                        Step(
                            step_no=1,
                            phase=Phase.VERIFICATION,
                            system_id="analytics_platform",
                            resource_id=rid,
                            operation=Operation.VERIFY_RECORD_ANONYMIZED,
                            state=State.ANONYMIZED,
                            evidence_id=ef.file_id,
                        )
                    )
            elif rows_val == "1":
                key = ("analytics_platform", rid, Operation.REPORT_REMAINING_RECORD)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="analytics_platform",
                            resource_id=rid,
                            kind=Operation.REPORT_REMAINING_RECORD,
                            evidence_id=ef.file_id,
                            data_category="ANALYTICS_PROFILE",
                        )
                    )

        # 6. Account service
        elif service == "account_service":
            rows_val = kv.get("rows", "")
            status_val = kv.get("http_status", "")
            if rows_val == "0" or status_val == "404":
                vkey = ("account_service", rid, Operation.VERIFY_RECORD_ABSENT)
                if vkey not in seen_verifications:
                    seen_verifications.add(vkey)
                    result.verifications.append(
                        Step(
                            step_no=1,
                            phase=Phase.VERIFICATION,
                            system_id="account_service",
                            resource_id=rid,
                            operation=Operation.VERIFY_RECORD_ABSENT,
                            state=State.ABSENT,
                            evidence_id=ef.file_id,
                        )
                    )

        # 7. Security service
        elif service == "security_service":
            sref = kv.get("subject_reference", "")
            if sref and sref == subject.user_id:
                vkey = ("security_service", rid, Operation.VERIFY_RECORD_PRESENT)
                if vkey not in seen_verifications:
                    seen_verifications.add(vkey)
                    result.verifications.append(
                        Step(
                            step_no=1,
                            phase=Phase.VERIFICATION,
                            system_id="security_service",
                            resource_id=rid,
                            operation=Operation.VERIFY_RECORD_PRESENT,
                            state=State.PRESENT,
                            evidence_id=ef.file_id,
                        )
                    )
