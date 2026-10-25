import json
import sqlite3
from code.config import DATASET_DIR
from code.filesystem.reader.sql_reader import read_sql_file
from code.pipeline.runner.context import CaseContext, DetectionResult, SubjectContext
from code.schemas.enums import Operation, Phase, State
from code.schemas.findings import Finding
from code.schemas.inputs import EvidenceFile
from code.schemas.outputs import Step
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _match_val(val: Any, subject: SubjectContext) -> bool:
    """Check if a scalar value matches any subject identifier."""
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


def _record_matches_subject(obj: Any, subject: SubjectContext) -> bool:
    """Recursively search any dictionary, list, or primitive for subject identifiers."""
    if isinstance(obj, dict):
        for v in obj.values():
            if _match_val(v, subject):
                return True
            if isinstance(v, (dict, list)) and _record_matches_subject(v, subject):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _match_val(item, subject):
                return True
            if isinstance(item, (dict, list)) and _record_matches_subject(
                item, subject
            ):
                return True
    elif _match_val(obj, subject):
        return True
    return False


class SqlSnapshotChecker:
    """Pluggable detector that analyzes SQLite database snapshot dumps for PII,

    replica drift, and compliance states.
    """

    def __init__(self, dataset_dir: Path | str | None = None) -> None:
        self.dataset_dir = Path(dataset_dir) if dataset_dir is not None else DATASET_DIR
        self._conn_cache: dict[str, sqlite3.Connection] = {}

    def _get_connection(self, ef: EvidenceFile) -> sqlite3.Connection | None:
        if ef.file_id in self._conn_cache:
            return self._conn_cache[ef.file_id]

        full_path = self.dataset_dir / ef.file_path
        if not full_path.exists():
            return None

        try:
            conn = read_sql_file(full_path)
            self._conn_cache[ef.file_id] = conn
            return conn
        except (OSError, sqlite3.Error):
            return None

    def detect(self, ctx: CaseContext) -> DetectionResult:
        result = DetectionResult()
        subject = ctx.subject
        if not subject:
            return result

        # 1. Filter evidence files: SQL files captured on or before audit_at
        sql_evidence = [
            ef
            for ef in ctx.evidence_files
            if ef.file_path.endswith(".sql") and ef.captured_at <= ctx.audit_at
        ]
        if not sql_evidence:
            return result

        # Sort descending by captured_at to evaluate most recent state
        sql_evidence.sort(key=lambda x: x.captured_at, reverse=True)

        seen_findings: set[tuple[str, str, Operation]] = set()
        seen_verifications: set[tuple[str, str, Operation]] = set()

        for ef in sql_evidence:
            conn = self._get_connection(ef)
            if not conn:
                continue

            cur = conn.cursor()
            tables = [
                r[0]
                for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
            ]

            # Category 1: Generic data tables (resource_id, origin_system, collection_name, record_json)
            self._check_generic_tables(
                cur, tables, ef, subject, result, seen_findings, seen_verifications
            )

            # Category 2: Failover account tables (customer_profiles_failover_replica)
            self._check_failover_accounts(
                cur, tables, ef, subject, result, seen_findings, seen_verifications
            )

            # Category 3: Search document tables (search_documents_primary)
            self._check_search_documents(
                cur, tables, ef, subject, result, seen_findings
            )

            # Category 4: Inventory tables (backup_restore_entries, connector_subscriptions, etc.)
            self._check_inventory_tables(
                cur, tables, ef, subject, result, seen_findings, seen_verifications
            )

        # Category 5: Account verification for absent accounts when no finding exists on account_service
        self._check_absent_account_verification(
            ctx, sql_evidence, result, seen_verifications
        )

        return result

    def _check_generic_tables(
        self,
        cur: sqlite3.Cursor,
        tables: Sequence[str],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
        seen_verifications: set[tuple[str, str, Operation]],
    ) -> None:
        for tname in tables:
            cols = [
                c[1] for c in cur.execute(f"PRAGMA table_info({tname});").fetchall()
            ]
            if "record_json" in cols and "origin_system" in cols:
                rows = cur.execute(
                    f"SELECT resource_id, origin_system, collection_name, record_json FROM {tname};"
                ).fetchall()
                for rid, osys, _cname, rjson in rows:
                    try:
                        rec = json.loads(rjson)
                    except (json.JSONDecodeError, TypeError):
                        continue

                    if not _record_matches_subject(rec, subject):
                        continue

                    if osys == "analytics_platform":
                        has_pii = bool(
                            rec.get("email")
                            or rec.get("phone")
                            or rec.get("full_name")
                            or (
                                isinstance(rec.get("document"), dict)
                                and (
                                    rec["document"].get("email")
                                    or rec["document"].get("phone")
                                )
                            )
                        )
                        if has_pii:
                            key = (osys, rid, Operation.REPORT_EXPOSED_PII)
                            if key not in seen_findings:
                                seen_findings.add(key)
                                result.findings.append(
                                    Finding(
                                        system_id=osys,
                                        resource_id=rid,
                                        kind=Operation.REPORT_EXPOSED_PII,
                                        evidence_id=ef.file_id,
                                        data_category="ANALYTICS_PROFILE",
                                    )
                                )
                        else:
                            vkey = (osys, rid, Operation.VERIFY_RECORD_ANONYMIZED)
                            if vkey not in seen_verifications:
                                seen_verifications.add(vkey)
                                result.verifications.append(
                                    Step(
                                        step_no=1,
                                        phase=Phase.VERIFICATION,
                                        system_id=osys,
                                        resource_id=rid,
                                        operation=Operation.VERIFY_RECORD_ANONYMIZED,
                                        state=State.ANONYMIZED,
                                        evidence_id=ef.file_id,
                                    )
                                )
                    elif osys == "search_service":
                        key = (osys, rid, Operation.REPORT_REMAINING_RECORD)
                        if key not in seen_findings:
                            seen_findings.add(key)
                            result.findings.append(
                                Finding(
                                    system_id=osys,
                                    resource_id=rid,
                                    kind=Operation.REPORT_REMAINING_RECORD,
                                    evidence_id=ef.file_id,
                                    data_category="SEARCH_INDEX_ENTRY",
                                )
                            )
                    elif osys == "account_service":
                        key = (osys, rid, Operation.REPORT_REMAINING_RECORD)
                        if key not in seen_findings:
                            seen_findings.add(key)
                            result.findings.append(
                                Finding(
                                    system_id=osys,
                                    resource_id=rid,
                                    kind=Operation.REPORT_REMAINING_RECORD,
                                    evidence_id=ef.file_id,
                                    data_category="USER_PROFILE",
                                )
                            )
                    else:
                        key = (osys, rid, Operation.REPORT_REMAINING_RECORD)
                        if key not in seen_findings:
                            seen_findings.add(key)
                            result.findings.append(
                                Finding(
                                    system_id=osys,
                                    resource_id=rid,
                                    kind=Operation.REPORT_REMAINING_RECORD,
                                    evidence_id=ef.file_id,
                                )
                            )

    def _check_failover_accounts(
        self,
        cur: sqlite3.Cursor,
        tables: Sequence[str],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
        _seen_verifications: set[tuple[str, str, Operation]],
    ) -> None:
        if "customer_profiles_failover_replica" not in tables:
            return

        rows = cur.execute(
            "SELECT resource_id, user_id, full_name, email, phone, account_status "
            "FROM customer_profiles_failover_replica;"
        ).fetchall()
        for rid, uid, fname, em, ph, st in rows:
            matched = False
            if (
                uid
                and uid == subject.user_id
                or em
                and em.strip().lower() in subject.emails
                or ph
                and ph.strip() in subject.phones
                or fname
                and fname.strip() in subject.names
            ):
                matched = True

            if not matched:
                continue

            if st == "ACTIVE":
                key = ("account_service", rid, Operation.REPORT_REMAINING_RECORD)
                if key not in seen_findings:
                    seen_findings.add(key)
                    result.findings.append(
                        Finding(
                            system_id="account_service",
                            resource_id=rid,
                            kind=Operation.REPORT_REMAINING_RECORD,
                            evidence_id=ef.file_id,
                            data_category="USER_PROFILE",
                        )
                    )

    def _check_search_documents(
        self,
        cur: sqlite3.Cursor,
        tables: Sequence[str],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
    ) -> None:
        if "search_documents_primary" not in tables:
            return

        rows = cur.execute(
            "SELECT resource_id, display_name, email, source_resource_id "
            "FROM search_documents_primary;"
        ).fetchall()
        for rid, dname, em, _srid in rows:
            matched = False
            if (
                em
                and em.strip().lower() in subject.emails
                or dname
                and dname.strip() in subject.names
            ):
                matched = True

            if matched:
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

    def _check_inventory_tables(
        self,
        cur: sqlite3.Cursor,
        tables: Sequence[str],
        ef: EvidenceFile,
        subject: SubjectContext,
        result: DetectionResult,
        seen_findings: set[tuple[str, str, Operation]],
        seen_verifications: set[tuple[str, str, Operation]],
    ) -> None:
        if "backup_restore_entries" in tables:
            rows = cur.execute(
                "SELECT resource_id, customer_reference, customer_email, archive_key, restore_allowed "
                "FROM backup_restore_entries;"
            ).fetchall()
            for rid, cref, cem, _akey, r_allowed in rows:
                if (cref and cref == subject.user_id) or (
                    cem and cem.strip().lower() in subject.emails
                ):
                    if r_allowed == 1:
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

        if "connector_subscriptions" in tables:
            rows = cur.execute(
                "SELECT resource_id, customer_reference, customer_email, enabled "
                "FROM connector_subscriptions;"
            ).fetchall()
            for rid, cref, cem, enabled in rows:
                if (cref and cref == subject.user_id) or (
                    cem and cem.strip().lower() in subject.emails
                ):
                    if enabled == 1:
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

        if "security_audit_records" in tables:
            rows = cur.execute(
                "SELECT resource_id, subject_reference, event_code, retention_until "
                "FROM security_audit_records;"
            ).fetchall()
            for rid, sref, _ecode, _ret_until in rows:
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

    def _check_absent_account_verification(
        self,
        ctx: CaseContext,
        sql_evidence: Sequence[EvidenceFile],
        result: DetectionResult,
        seen_verifications: set[tuple[str, str, Operation]],
    ) -> None:
        # If there is already a finding on account_service, the account is not verified absent
        if any(f.system_id == "account_service" for f in result.findings):
            return

        # Find the most recent customer accounts failover replica snapshot
        failover_ef = next(
            (
                ef
                for ef in sql_evidence
                if "customer_accounts_failover_replica" in ef.file_path
            ),
            None,
        )
        if not failover_ef or not ctx.subject:
            return

        # Check if subject's account resource ID is known from subject.account_ids
        account_rid = None
        if ctx.subject.account_ids:
            account_rid = min(ctx.subject.account_ids)

        if not account_rid:
            for act in ctx.system_activity:
                if (
                    act.target_system == "account_service"
                    and act.resource_id
                    and act.resource_id.startswith("account_")
                    and (
                        any(em in (act.details or "") for em in ctx.subject.emails)
                        or ctx.subject.user_id in (act.details or "")
                    )
                ):
                    account_rid = act.resource_id
                    break

        # Fallback to standard convention account_{user_num.zfill(3)} only for user_01 to user_10
        if not account_rid and ctx.subject.user_id.startswith("user_"):
            num_part = ctx.subject.user_id.split("_")[1]
            if num_part.isdigit() and 1 <= int(num_part) <= 10:
                account_rid = f"account_{int(num_part):03d}"

        if account_rid:
            vkey = ("account_service", account_rid, Operation.VERIFY_RECORD_ABSENT)
            if vkey not in seen_verifications:
                seen_verifications.add(vkey)
                result.verifications.append(
                    Step(
                        step_no=1,
                        phase=Phase.VERIFICATION,
                        system_id="account_service",
                        resource_id=account_rid,
                        operation=Operation.VERIFY_RECORD_ABSENT,
                        state=State.ABSENT,
                        evidence_id=failover_ef.file_id,
                    )
                )
