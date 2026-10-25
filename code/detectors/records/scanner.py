import json
from code.config import DATASET_DIR
from code.pipeline.runner.context import CaseContext, DetectionResult, SubjectContext
from code.schemas.enums import Operation, Phase, State
from code.schemas.findings import Finding
from code.schemas.inputs import EvidenceFile
from code.schemas.outputs import Step
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _val_matches_subject(val: Any, subject: SubjectContext) -> bool:
    if not isinstance(val, str):
        return False
    v_clean = val.strip()
    v_lower = v_clean.lower()
    if v_clean == subject.user_id:
        return True
    if v_lower in subject.emails:
        return True
    if v_clean in subject.phones:
        return True
    if v_lower in subject.email_hashes:
        return True
    return v_clean in subject.names


def _record_matches(rec: Any, subject: SubjectContext) -> bool:
    if isinstance(rec, dict):
        for v in rec.values():
            if _val_matches_subject(v, subject):
                return True
            if isinstance(v, (dict, list)) and _record_matches(v, subject):
                return True
    elif isinstance(rec, list):
        for item in rec:
            if _val_matches_subject(item, subject):
                return True
            if isinstance(item, (dict, list)) and _record_matches(item, subject):
                return True
    elif _val_matches_subject(rec, subject):
        return True
    return False


class JsonRecordsScanner:
    """Pluggable detector that analyzes structured JSON evidence bundles and exports."""

    def __init__(self, dataset_dir: Path | str | None = None) -> None:
        self.dataset_dir = Path(dataset_dir) if dataset_dir is not None else DATASET_DIR
        self._cache: dict[str, Any] = {}

    def _load_json(self, ef: EvidenceFile) -> Any:
        if ef.file_id in self._cache:
            return self._cache[ef.file_id]

        full_path = self.dataset_dir / ef.file_path
        if not full_path.exists():
            return None

        try:
            with open(full_path, mode="r", encoding="utf-8") as f:
                data = json.load(f)
            self._cache[ef.file_id] = data
            return data
        except (OSError, json.JSONDecodeError):
            return None

    def detect(self, ctx: CaseContext) -> DetectionResult:
        result = DetectionResult()
        subject = ctx.subject
        if not subject:
            return result

        json_evidence = [
            ef
            for ef in ctx.evidence_files
            if ef.file_path.endswith(".json") and ef.captured_at <= ctx.audit_at
        ]
        if not json_evidence:
            return result

        json_evidence.sort(key=lambda x: x.captured_at, reverse=True)

        seen_findings: set[tuple[str, str, Operation]] = set()
        seen_verifications: set[tuple[str, str, Operation]] = set()

        for ef in json_evidence:
            data = self._load_json(ef)
            if not isinstance(data, dict):
                continue

            # Type 1: service_resource_export (service_exports dict)
            if "service_exports" in data and isinstance(data["service_exports"], dict):
                self._scan_service_exports(
                    data["service_exports"],
                    ef,
                    subject,
                    result,
                    seen_findings,
                    seen_verifications,
                )

            # Type 2: customer_data_snapshot_bundle (snapshots list)
            if "snapshots" in data and isinstance(data["snapshots"], list):
                self._scan_snapshot_bundle(
                    data["snapshots"],
                    ef,
                    subject,
                    result,
                    seen_findings,
                    seen_verifications,
                )

            # Type 3: single resource report (customer_analytics_report_*.json)
            if "reporting_window" in data or "audience_cohort" in data:
                self._scan_single_analytics(
                    data, ef, subject, result, seen_findings, seen_verifications
                )

            # Type 4: export jobs
            if "export_jobs" in data and isinstance(data["export_jobs"], list):
                self._scan_export_jobs(
                    data["export_jobs"], ef, subject, result, seen_findings
                )
            elif (
                data.get("collection") == "customer_export_jobs"
                and "records" in data
                and isinstance(data["records"], list)
            ):
                self._scan_export_jobs(
                    data["records"], ef, subject, result, seen_findings
                )

        return result

    def _scan_service_exports(
        self,
        exports: dict[str, Any],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
        seen_verifications: set[tuple[str, str, Operation]],
    ) -> None:
        # Search service
        search_data = exports.get("search_service", {})
        queries = (
            search_data.get("index_queries", [])
            if isinstance(search_data, dict)
            else []
        )
        for q in queries:
            if not isinstance(q, dict):
                continue
            if _record_matches(q, subject):
                rid = q.get("resource_id", "search_unknown")
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
        # Account service
        account_data = exports.get("account_service", {})
        lookups = (
            account_data.get("profile_lookups", [])
            if isinstance(account_data, dict)
            else []
        )
        for lk in lookups:
            if not isinstance(lk, dict):
                continue
            rid = lk.get("resource_id", "")
            prof = lk.get("profile")
            status_code = lk.get("status_code", 0)

            matches = False
            if (
                prof
                and isinstance(prof, dict)
                and _record_matches(prof, subject)
                or rid
                and rid in getattr(subject, "account_ids", frozenset())
            ):
                matches = True

            if matches:
                if status_code == 200:
                    key = ("account_service", rid, Operation.REPORT_REMAINING_RECORD)
                    if key not in seen_findings:
                        seen_findings.add(key)
                        result.findings.append(
                            Finding(
                                system_id="account_service",
                                resource_id=rid,
                                kind=Operation.REPORT_REMAINING_RECORD,
                                evidence_id=ef.file_id,
                                data_category="CUSTOMER_PROFILE",
                            )
                        )
                elif status_code == 404:
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

        # Analytics platform
        analytics_data = exports.get("analytics_platform", {})
        profiles = (
            analytics_data.get("profiles", [])
            if isinstance(analytics_data, dict)
            else []
        )
        for p in profiles:
            if not isinstance(p, dict):
                continue
            rid = p.get("resource_id", "")
            cref = p.get("customer_reference")
            has_id_match = (cref and cref == subject.user_id) or _record_matches(
                p, subject
            )
            if has_id_match:
                has_pii = bool(p.get("email") or p.get("phone") or p.get("full_name"))
                if has_pii:
                    key = ("analytics_platform", rid, Operation.REPORT_EXPOSED_PII)
                    if key not in seen_findings:
                        seen_findings.add(key)
                        result.findings.append(
                            Finding(
                                system_id="analytics_platform",
                                resource_id=rid,
                                kind=Operation.REPORT_EXPOSED_PII,
                                evidence_id=ef.file_id,
                                data_category="ANALYTICS_PROFILE",
                            )
                        )
                else:
                    vkey = (
                        "analytics_platform",
                        rid,
                        Operation.VERIFY_RECORD_ANONYMIZED,
                    )
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

        # Integration service
        integration_data = exports.get("integration_service", {})
        connectors = (
            integration_data.get("connectors", [])
            if isinstance(integration_data, dict)
            else []
        )
        for c in connectors:
            if not isinstance(c, dict):
                continue
            rid = c.get("resource_id", "")
            cref = c.get("customer_reference")
            cem = c.get("customer_email")
            matches = (cref and cref == subject.user_id) or (
                cem and cem.strip().lower() in subject.emails
            )
            if matches:
                enabled = c.get("enabled", False)
                if enabled:
                    key = (
                        "integration_service",
                        rid,
                        Operation.REPORT_ACTIVE_DATA_FLOW,
                    )
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

        # Backup service
        backup_data = exports.get("backup_service", {})
        restore_entries = (
            backup_data.get("restore_entries", [])
            if isinstance(backup_data, dict)
            else []
        )
        for b in restore_entries:
            if not isinstance(b, dict):
                continue
            rid = b.get("resource_id", "")
            cref = b.get("customer_reference")
            cem = b.get("customer_email")
            matches = (cref and cref == subject.user_id) or (
                cem and cem.strip().lower() in subject.emails
            )
            if matches:
                restore_allowed = b.get("restore_allowed", False)
                if restore_allowed:
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
                else:
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

        # Support platform
        support_data = exports.get("support_platform", {})
        tickets = (
            support_data.get("tickets", []) if isinstance(support_data, dict) else []
        )
        for t in tickets:
            if not isinstance(t, dict):
                continue
            rid = t.get("resource_id", "")
            cref = t.get("customer_reference")
            rem = t.get("requester_email")
            matches = (cref and cref == subject.user_id) or (
                rem and rem.strip().lower() in subject.emails
            )
            if matches:
                has_pii = bool(
                    t.get("requester_email")
                    or t.get("requester_name")
                    or t.get("requester_phone")
                )
                if has_pii:
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
                else:
                    vkey = (
                        "support_platform",
                        rid,
                        Operation.VERIFY_RECORD_REDACTED,
                    )
                    if vkey not in seen_verifications:
                        seen_verifications.add(vkey)
                        result.verifications.append(
                            Step(
                                step_no=1,
                                phase=Phase.VERIFICATION,
                                system_id="support_platform",
                                resource_id=rid,
                                operation=Operation.VERIFY_RECORD_REDACTED,
                                state=State.REDACTED,
                                evidence_id=ef.file_id,
                            )
                        )

        # Security service
        security_data = exports.get("security_service", {})
        records = (
            security_data.get("audit_records", [])
            if isinstance(security_data, dict)
            else []
        )
        for a in records:
            if not isinstance(a, dict):
                continue
            sref = a.get("subject_reference")
            if sref and sref == subject.user_id:
                rid = a.get("resource_id", "")
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

        # Export service
        export_data = exports.get("export_service", {})
        exports_list = (
            export_data.get("exports", []) if isinstance(export_data, dict) else []
        )
        for ex in exports_list:
            if not isinstance(ex, dict):
                continue
            rid = ex.get("resource_id", "")
            cref = ex.get("customer_reference")
            oem = ex.get("owner_email")
            matches = (cref and cref == subject.user_id) or (
                oem and oem.strip().lower() in subject.emails
            )
            if matches:
                key = ("export_service", rid, Operation.REPORT_REMAINING_RECORD)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="export_service",
                            resource_id=rid,
                            kind=Operation.REPORT_REMAINING_RECORD,
                            evidence_id=ef.file_id,
                            data_category="USER_EXPORT",
                        )
                    )

    def _scan_snapshot_bundle(
        self,
        snapshots: Sequence[dict[str, Any]],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
        seen_verifications: set[tuple[str, str, Operation]],
    ) -> None:
        for snap in snapshots:
            if not isinstance(snap, dict):
                continue
            dstore = snap.get("data_store", "")
            col = snap.get("collection", "")
            records = snap.get("records", [])

            if dstore == "identity_service" and col == "deleted_customer_references":
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    sref = rec.get("subject_reference")
                    if sref and sref == subject.user_id:
                        rid = rec.get("resource_id", "")
                        has_pii = bool(
                            rec.get("email")
                            or rec.get("name")
                            or rec.get("phone")
                            or rec.get("email_hash")
                        )
                        if has_pii:
                            key = (
                                "identity_service",
                                rid,
                                Operation.REPORT_EXPOSED_PII,
                            )
                            if key not in seen_findings:
                                seen_findings.add(key)
                                result.findings.append(
                                    Finding(
                                        system_id="identity_service",
                                        resource_id=rid,
                                        kind=Operation.REPORT_EXPOSED_PII,
                                        evidence_id=ef.file_id,
                                        data_category="ACCOUNT_TOMBSTONE",
                                    )
                                )
                        else:
                            vkey = (
                                "identity_service",
                                rid,
                                Operation.VERIFY_RECORD_REDACTED,
                            )
                            if vkey not in seen_verifications:
                                seen_verifications.add(vkey)
                                result.verifications.append(
                                    Step(
                                        step_no=1,
                                        phase=Phase.VERIFICATION,
                                        system_id="identity_service",
                                        resource_id=rid,
                                        operation=Operation.VERIFY_RECORD_REDACTED,
                                        state=State.REDACTED,
                                        evidence_id=ef.file_id,
                                    )
                                )

            elif dstore == "security_service" and col == "security_audit_events":
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    sref = rec.get("subject_reference")
                    if sref and sref == subject.user_id:
                        rid = rec.get("resource_id", "")
                        vkey = (
                            "security_service",
                            rid,
                            Operation.VERIFY_RECORD_PRESENT,
                        )
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
            elif dstore == "account_service" and col == "customer_profiles":
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    if _record_matches(rec, subject):
                        rid = rec.get("resource_id", "")
                        status = rec.get("account_status", "")
                        if status == "ACTIVE":
                            key = (
                                "account_service",
                                rid,
                                Operation.REPORT_REMAINING_RECORD,
                            )
                            if key not in seen_findings:
                                seen_findings.add(key)
                                result.findings.append(
                                    Finding(
                                        system_id="account_service",
                                        resource_id=rid,
                                        kind=Operation.REPORT_REMAINING_RECORD,
                                        evidence_id=ef.file_id,
                                        data_category="CUSTOMER_PROFILE",
                                    )
                                )
                        else:
                            vkey = (
                                "account_service",
                                rid,
                                Operation.VERIFY_RECORD_ABSENT,
                            )
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

            elif col == "operational_record_history":
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    lval = rec.get("lookup_value", "").strip()
                    lval_lower = lval.lower()
                    matches = (
                        lval == subject.user_id
                        or lval_lower in subject.emails
                        or lval in subject.phones
                        or lval in subject.names
                        or lval in getattr(subject, "account_ids", frozenset())
                    )
                    if not matches:
                        continue

                    sys_id = rec.get("system", "")
                    rid = rec.get("resource_id", "")
                    res_type = rec.get("result", "")

                    if res_type == "NOT_FOUND":
                        vkey = (sys_id, rid, Operation.VERIFY_RECORD_ABSENT)
                        if vkey not in seen_verifications:
                            seen_verifications.add(vkey)
                            result.verifications.append(
                                Step(
                                    step_no=1,
                                    phase=Phase.VERIFICATION,
                                    system_id=sys_id,
                                    resource_id=rid,
                                    operation=Operation.VERIFY_RECORD_ABSENT,
                                    state=State.ABSENT,
                                    evidence_id=ef.file_id,
                                )
                            )
                    elif res_type == "FOUND":
                        if sys_id in ("security_service", "legal_service"):
                            vkey = (sys_id, rid, Operation.VERIFY_RECORD_PRESENT)
                            if vkey not in seen_verifications:
                                seen_verifications.add(vkey)
                                result.verifications.append(
                                    Step(
                                        step_no=1,
                                        phase=Phase.VERIFICATION,
                                        system_id=sys_id,
                                        resource_id=rid,
                                        operation=Operation.VERIFY_RECORD_PRESENT,
                                        state=State.PRESENT,
                                        evidence_id=ef.file_id,
                                    )
                                )
                        else:
                            fkey = (sys_id, rid, Operation.REPORT_REMAINING_RECORD)
                            if fkey not in seen_findings:
                                seen_findings.add(fkey)
                                result.findings.append(
                                    Finding(
                                        system_id=sys_id,
                                        resource_id=rid,
                                        kind=Operation.REPORT_REMAINING_RECORD,
                                        evidence_id=ef.file_id,
                                        data_category=rec.get("record_type", ""),
                                    )
                                )
                    elif res_type == "IDENTIFIABLE":
                        fkey = (sys_id, rid, Operation.REPORT_EXPOSED_PII)
                        if fkey not in seen_findings:
                            seen_findings.add(fkey)
                            result.findings.append(
                                Finding(
                                    system_id=sys_id,
                                    resource_id=rid,
                                    kind=Operation.REPORT_EXPOSED_PII,
                                    evidence_id=ef.file_id,
                                    data_category=rec.get("record_type", ""),
                                )
                            )
                    elif res_type == "ACTIVE":
                        if sys_id == "integration_service":
                            fkey = (sys_id, rid, Operation.REPORT_ACTIVE_DATA_FLOW)
                            if fkey not in seen_findings:
                                seen_findings.add(fkey)
                                result.findings.append(
                                    Finding(
                                        system_id=sys_id,
                                        resource_id=rid,
                                        kind=Operation.REPORT_ACTIVE_DATA_FLOW,
                                        evidence_id=ef.file_id,
                                    )
                                )
                        elif sys_id == "backup_service":
                            fkey = (sys_id, rid, Operation.REPORT_RESTORE_RISK)
                            if fkey not in seen_findings:
                                seen_findings.add(fkey)
                                result.findings.append(
                                    Finding(
                                        system_id=sys_id,
                                        resource_id=rid,
                                        kind=Operation.REPORT_RESTORE_RISK,
                                        evidence_id=ef.file_id,
                                    )
                                )
                    elif res_type == "DISABLED":
                        vkey = (sys_id, rid, Operation.VERIFY_DATA_FLOW_DISABLED)
                        if vkey not in seen_verifications:
                            seen_verifications.add(vkey)
                            result.verifications.append(
                                Step(
                                    step_no=1,
                                    phase=Phase.VERIFICATION,
                                    system_id=sys_id,
                                    resource_id=rid,
                                    operation=Operation.VERIFY_DATA_FLOW_DISABLED,
                                    state=State.DISABLED,
                                    evidence_id=ef.file_id,
                                )
                            )
                    elif res_type == "BLOCKED":
                        vkey = (sys_id, rid, Operation.VERIFY_RESTORE_BLOCKED)
                        if vkey not in seen_verifications:
                            seen_verifications.add(vkey)
                            result.verifications.append(
                                Step(
                                    step_no=1,
                                    phase=Phase.VERIFICATION,
                                    system_id=sys_id,
                                    resource_id=rid,
                                    operation=Operation.VERIFY_RESTORE_BLOCKED,
                                    state=State.BLOCKED,
                                    evidence_id=ef.file_id,
                                )
                            )
                    elif res_type == "ANONYMIZED":
                        vkey = (sys_id, rid, Operation.VERIFY_RECORD_ANONYMIZED)
                        if vkey not in seen_verifications:
                            seen_verifications.add(vkey)
                            result.verifications.append(
                                Step(
                                    step_no=1,
                                    phase=Phase.VERIFICATION,
                                    system_id=sys_id,
                                    resource_id=rid,
                                    operation=Operation.VERIFY_RECORD_ANONYMIZED,
                                    state=State.ANONYMIZED,
                                    evidence_id=ef.file_id,
                                )
                            )
                    elif res_type == "REDACTED":
                        vkey = (sys_id, rid, Operation.VERIFY_RECORD_REDACTED)
                        if vkey not in seen_verifications:
                            seen_verifications.add(vkey)
                            result.verifications.append(
                                Step(
                                    step_no=1,
                                    phase=Phase.VERIFICATION,
                                    system_id=sys_id,
                                    resource_id=rid,
                                    operation=Operation.VERIFY_RECORD_REDACTED,
                                    state=State.REDACTED,
                                    evidence_id=ef.file_id,
                                )
                            )

    def _scan_single_analytics(
        self,
        data: dict[str, Any],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
        seen_verifications: set[tuple[str, str, Operation]],
    ) -> None:
        rid = data.get("resource_id", "")
        if not rid:
            return
        if _record_matches(data, subject):
            has_pii = bool(
                data.get("email") or data.get("phone") or data.get("full_name")
            )
            if has_pii:
                key = ("analytics_platform", rid, Operation.REPORT_EXPOSED_PII)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="analytics_platform",
                            resource_id=rid,
                            kind=Operation.REPORT_EXPOSED_PII,
                            evidence_id=ef.file_id,
                            data_category="ANALYTICS_PROFILE",
                        )
                    )
            else:
                vkey = (
                    "analytics_platform",
                    rid,
                    Operation.VERIFY_RECORD_ANONYMIZED,
                )
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

    def _scan_export_jobs(
        self,
        jobs: Sequence[dict[str, Any]],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
    ) -> None:
        for job in jobs:
            if not isinstance(job, dict):
                continue
            rid = job.get("resource_id", "")
            if _record_matches(job, subject):
                key = ("export_service", rid, Operation.REPORT_REMAINING_RECORD)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="export_service",
                            resource_id=rid,
                            kind=Operation.REPORT_REMAINING_RECORD,
                            evidence_id=ef.file_id,
                            data_category="USER_EXPORT",
                        )
                    )
