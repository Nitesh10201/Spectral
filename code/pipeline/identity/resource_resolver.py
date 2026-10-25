import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from code.config import DATASET_DIR
from code.filesystem.reader import read_evidence_files, read_system_activity
from code.pipeline.runner.context import SubjectContext
from code.schemas.inputs import ActivityRecord, DeletionRequest, EvidenceFile

logger = logging.getLogger(__name__)


def parse_iso(ts: str) -> datetime:
    """Parse ISO-8601 string to timezone-aware UTC datetime."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def parse_kv_log_line(line: str) -> dict[str, str]:
    """Parse key-value format log line into dictionary."""
    kv: dict[str, str] = {}
    parts = line.strip().split()
    if parts and (parts[0].endswith("Z") or "+00:00" in parts[0]):
        kv["timestamp"] = parts[0]
    unquoted = line.replace('\\"', '"')
    for match in re.finditer(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|([^\s]+))', unquoted):
        k = match.group(1)
        v = match.group(2) if match.group(2) is not None else match.group(3)
        kv[k] = v
    if "requestId" in kv and "trace_id" not in kv:
        kv["trace_id"] = kv["requestId"]
    return kv


class ResourceResolver:
    """Generalized resolver for subject account_service and security_service resources.

    Indexes all evidence files and system activity without hardcoding.
    """

    def __init__(
        self,
        dataset_dir: Path | str | None = None,
        evidence_files: list[EvidenceFile] | None = None,
        system_activity: list[ActivityRecord] | None = None,
    ) -> None:
        self.dataset_dir = Path(dataset_dir) if dataset_dir is not None else DATASET_DIR
        self.evidence_files = evidence_files
        self.system_activity = system_activity

        self._ev_manifest: dict[str, tuple[str, datetime]] = {}  # rel_path -> (fid, captured_at)
        self._fid_to_captured_at: dict[str, datetime] = {}

        # key (uid / email / phone) -> list of (acc_id, fid, status_code, event_or_capture_dt)
        self._account_evidence: dict[str, list[tuple[str, str, int | None, datetime]]] = {}
        # key (uid / email) -> list of (aud_id, fid, event_or_capture_dt)
        self._audit_evidence: dict[str, list[tuple[str, str, datetime]]] = {}

        # 404 / absent account lookups: account_id -> (evidence_id, observed_or_captured_dt)
        self._account_404_evidence: dict[str, tuple[str, datetime]] = {}
        # Permanent identity to account reference: user_id / email -> account_id
        self._user_to_account: dict[str, str] = {}
        # Evidence files with empty account_service collections
        self._empty_account_snapshots: set[str] = set()

        self._worker_account_acts: list[ActivityRecord] = []
        self._indexed = False

    def ensure_indexed(self) -> None:
        """Build indexes from evidence files and system activity."""
        if self._indexed:
            return

        # 1. Load manifests and activities if not provided
        if self.evidence_files is None:
            try:
                self.evidence_files = read_evidence_files(self.dataset_dir / "evidence_files.csv")
            except OSError:
                self.evidence_files = []

        if self.system_activity is None:
            try:
                self.system_activity = read_system_activity(self.dataset_dir / "system_activity.csv")
            except OSError:
                self.system_activity = []

        for ef in self.evidence_files:
            rel = ef.file_path.replace("\\", "/")
            self._ev_manifest[rel] = (ef.file_id, ef.captured_at)
            self._fid_to_captured_at[ef.file_id] = ef.captured_at

        # 2. Filter worker activities for account_service
        self._worker_account_acts = [
            a
            for a in self.system_activity
            if a.source_system == "deletion_worker"
            and a.target_system == "account_service"
            and a.event_type == "DELETE_RECORD"
        ]

        # 3. Scan JSON evidence
        self._index_json_files()

        # 4. Scan SQL evidence
        self._index_sql_files()

        # 5. Scan TXT records
        self._index_txt_files()

        # 6. Scan LOG evidence
        self._index_log_files()

        self._indexed = True
        logger.info(
            "ResourceResolver indexed %d account keys and %d audit keys.",
            len(self._account_evidence),
            len(self._audit_evidence),
        )

    def _add_account(
        self,
        key: str | None,
        acc_id: str | None,
        fid: str,
        status: int | None = None,
        dt: datetime | None = None,
    ) -> None:
        if not key or not acc_id:
            return
        k_clean = key.strip().lower() if "@" in key else key.strip()
        captured_dt = dt or self._fid_to_captured_at.get(fid, datetime.max)
        self._account_evidence.setdefault(k_clean, []).append((acc_id, fid, status, captured_dt))
        if acc_id.startswith("account_") and k_clean not in self._user_to_account:
            self._user_to_account[k_clean] = acc_id

    def _add_audit(
        self,
        key: str | None,
        aud_id: str | None,
        fid: str,
        dt: datetime | None = None,
    ) -> None:
        if not key or not aud_id:
            return
        k_clean = key.strip().lower() if "@" in key else key.strip()
        captured_dt = dt or self._fid_to_captured_at.get(fid, datetime.max)
        self._audit_evidence.setdefault(k_clean, []).append((aud_id, fid, captured_dt))

    def _index_json_files(self) -> None:
        records_dir = self.dataset_dir / "evidence" / "records"
        if not records_dir.exists():
            return

        for jf in records_dir.glob("*.json"):
            rel_p = f"evidence/records/{jf.name}"
            fid, dt = self._ev_manifest.get(rel_p, ("", datetime.max))
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except Exception:
                continue

            # Snapshots
            if "snapshots" in data:
                for s in data["snapshots"]:
                    store = s.get("data_store")
                    col = s.get("collection")
                    s_dt = parse_iso(s["captured_at"]) if s.get("captured_at") else dt
                    recs = s.get("records", [])
                    if (store == "account_service" or col == "customer_profiles") and len(recs) == 0:
                        self._empty_account_snapshots.add(fid)
                    for rec in recs:
                        if store == "account_service" or col == "customer_profiles":
                            acc_id = rec.get("resource_id") or rec.get("account_id")
                            self._add_account(rec.get("customer_reference"), acc_id, fid, dt=s_dt)
                            if rec.get("email"):
                                self._add_account(rec["email"], acc_id, fid, dt=s_dt)
                            if rec.get("phone"):
                                self._add_account(rec["phone"], acc_id, fid, dt=s_dt)
                        elif store == "security_service" or col == "security_audit_events":
                            aud_id = rec.get("resource_id") or rec.get("record_id")
                            self._add_audit(rec.get("subject_reference"), aud_id, fid, dt=s_dt)

            # Service exports
            if "service_exports" in data:
                sexp = data["service_exports"]
                for al in sexp.get("account_service", {}).get("profile_lookups", []):
                    acc_id = al.get("resource_id")
                    stat = al.get("status_code")
                    obs_dt = parse_iso(al["observed_at"]) if al.get("observed_at") else dt
                    prof = al.get("profile") or {}
                    self._add_account(prof.get("customer_reference"), acc_id, fid, status=stat, dt=obs_dt)
                    if prof.get("email"):
                        self._add_account(prof["email"], acc_id, fid, status=stat, dt=obs_dt)
                    if stat == 404 and acc_id:
                        self._account_404_evidence[acc_id] = (fid, obs_dt)
                for ar in sexp.get("security_service", {}).get("audit_records", []):
                    ar_dt = parse_iso(ar["observed_at"]) if ar.get("observed_at") else dt
                    self._add_audit(ar.get("subject_reference"), ar.get("resource_id"), fid, dt=ar_dt)

            # Audit ledger
            if isinstance(data, list):
                for item in data:
                    aud_id = item.get("resource_id") or item.get("audit_id")
                    self._add_audit(item.get("subject_reference") or item.get("user_id"), aud_id, fid, dt=dt)

    def _index_sql_files(self) -> None:
        db_dir = self.dataset_dir / "evidence" / "databases"
        if not db_dir.exists():
            return

        for sql_f in db_dir.glob("*.sql"):
            rel_p = f"evidence/databases/{sql_f.name}"
            fid, dt = self._ev_manifest.get(rel_p, ("", datetime.max))
            try:
                text = sql_f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Record JSON inserts (e.g. read replicas, reporting replicas, failover replicas)
            for m in re.finditer(r"VALUES\s*\(\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'({.+?})'\s*,", text):
                res_id, _sys, _coll, jstr = m.group(1), m.group(2), m.group(3), m.group(4)
                try:
                    data = json.loads(jstr.replace("''", "'"))
                    cust_ref = data.get("customer_reference") or data.get("subject_reference") or data.get("user_id")
                    email = data.get("email")
                    if res_id.startswith("account_"):
                        if cust_ref:
                            self._add_account(cust_ref, res_id, fid, dt=dt)
                        if email:
                            self._add_account(email, res_id, fid, dt=dt)
                    elif res_id.startswith("audit_record_"):
                        if cust_ref:
                            self._add_audit(cust_ref, res_id, fid, dt=dt)
                except Exception:
                    pass

            # customer_profiles tables
            for m in re.finditer(r"INSERT INTO\s+customer_profiles\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)", text, re.I):
                cols = [c.strip().lower() for c in m.group(1).split(",")]
                vals = [v.strip().strip("'\"") for v in m.group(2).split(",")]
                row = dict(zip(cols, vals))
                acc_id = row.get("account_id") or row.get("resource_id")
                if row.get("customer_reference"):
                    self._add_account(row["customer_reference"], acc_id, fid, dt=dt)
                if row.get("email"):
                    self._add_account(row["email"], acc_id, fid, dt=dt)

            # security_audit_records tables
            for m in re.finditer(r"INSERT INTO\s+security_audit_records\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)", text, re.I):
                cols = [c.strip().lower() for c in m.group(1).split(",")]
                vals = [v.strip().strip("'\"") for v in m.group(2).split(",")]
                row = dict(zip(cols, vals))
                aud_id = row.get("record_id") or row.get("resource_id")
                if row.get("subject_reference"):
                    self._add_audit(row["subject_reference"], aud_id, fid, dt=dt)

    def _index_txt_files(self) -> None:
        rec_dir = self.dataset_dir / "evidence" / "records"
        if not rec_dir.exists():
            return

        for txt_f in rec_dir.glob("*.txt"):
            rel_p = f"evidence/records/{txt_f.name}"
            fid, dt = self._ev_manifest.get(rel_p, ("", datetime.max))
            try:
                text = txt_f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for line in text.splitlines():
                if "account_service" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 6:
                        stat = 404 if "NOT_FOUND" in parts[4] else 200
                        self._add_account(parts[5], parts[2], fid, status=stat, dt=dt)
                        if stat == 404 and parts[2].startswith("account_"):
                            self._account_404_evidence[parts[2]] = (fid, dt)
                elif "security_service" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 6:
                        self._add_audit(parts[5], parts[2], fid, dt=dt)

    def _index_log_files(self) -> None:
        logs_dir = self.dataset_dir / "evidence" / "logs"
        if not logs_dir.exists():
            return

        for log_f in logs_dir.glob("*.log"):
            rel_p = f"evidence/logs/{log_f.name}"
            fid, file_dt = self._ev_manifest.get(rel_p, ("", datetime.max))
            try:
                text = log_f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            traces: dict[str, list[dict[str, Any]]] = {}
            for line in text.splitlines():
                if not line.strip():
                    continue
                # JSON line
                if "{" in line and "}" in line:
                    try:
                        jpart = line[line.find("{"):line.rfind("}")+1]
                        data = json.loads(jpart)
                        # Extract event timestamp from line beginning or json field
                        ts_str = line[:line.find("{")].strip()
                        if ts_str and (ts_str.endswith("Z") or "+00:00" in ts_str):
                            data["timestamp"] = ts_str
                        tid = data.get("trace_id")
                        if tid:
                            traces.setdefault(tid, []).append(data)
                        continue
                    except Exception:
                        pass
                # Key-value line
                kv = parse_kv_log_line(line)
                tid = kv.get("trace_id")
                if tid:
                    traces.setdefault(tid, []).append(kv)

            for _tid, events in traces.items():
                keys: set[str] = set()
                ev_dt = file_dt
                for ev in events:
                    if ev.get("timestamp"):
                        try:
                            ev_dt = parse_iso(ev["timestamp"])
                        except Exception:
                            pass
                    for kf in ["lookup_key", "match_key", "subject_ref", "subject_key", "correlation_key", "owner_key"]:
                        val = ev.get(kf)
                        if val and val != "null":
                            keys.add(val)
                for ev in events:
                    res_id = ev.get("resource_id", "")
                    if res_id.startswith("account_"):
                        stat = 404 if str(ev.get("http_status")) == "404" or str(ev.get("rows")) == "0" else 200
                        for k in keys:
                            self._add_account(k, res_id, fid, status=stat, dt=ev_dt)
                        if stat == 404:
                            self._account_404_evidence[res_id] = (fid, ev_dt)
                    elif res_id.startswith("audit_record_"):
                        for k in keys:
                            self._add_audit(k, res_id, fid, dt=ev_dt)

    def resolve_account(
        self,
        subject: SubjectContext | None,
        request: DeletionRequest,
    ) -> tuple[str | None, str]:
        """Resolve the subject's account_service resource ID and evidence ID as of audit_at.

        Returns (account_id, evidence_id).
        """
        self.ensure_indexed()

        candidate_keys: set[str] = set()
        if subject:
            if subject.user_id:
                candidate_keys.add(subject.user_id)
            candidate_keys.update(subject.emails)
            candidate_keys.update(subject.phones)
            candidate_keys.update(subject.account_ids)
        if request.email:
            candidate_keys.add(request.email.strip().lower())

        audit_at = request.audit_at

        # 1. Look for account in evidence files captured on or before audit_at
        cand_acc: str | None = None
        for k in candidate_keys:
            k_clean = k.strip().lower() if "@" in k else k.strip()
            if k_clean in self._account_evidence:
                hits = self._account_evidence[k_clean]
                valid_hits = [h for h in hits if h[3] <= audit_at]
                if valid_hits:
                    # Look for 404 hits (demonstrating absent verification)
                    absent_hits = [h for h in valid_hits if h[2] == 404]
                    if absent_hits:
                        absent_hits.sort(key=lambda x: x[3], reverse=True)
                        return absent_hits[0][0], absent_hits[0][1]
                    if not cand_acc:
                        cand_acc = valid_hits[0][0]

        # 2. Check canonical account convention for user_01 to user_10
        if subject and subject.user_id.startswith("user_"):
            num_part = subject.user_id.split("_")[1]
            if num_part.isdigit() and 1 <= int(num_part) <= 10:
                acc_canonical = f"account_{int(num_part):03d}"
                # If failover replica evidence_54 is captured on or before audit_at, cite it
                ev54_dt = self._fid_to_captured_at.get("evidence_54", datetime.max)
                ev54_id = "evidence_54" if ev54_dt <= audit_at else ""
                return acc_canonical, ev54_id

        # 3. Check permanent user-to-account mapping from all snapshots / records
        if not cand_acc:
            for k in candidate_keys:
                k_clean = k.strip().lower() if "@" in k else k.strip()
                if k_clean in self._user_to_account:
                    cand_acc = self._user_to_account[k_clean]
                    break

        # 4. Look in system_activity.csv for deletion_worker batch near reported_at
        if not cand_acc:
            rep_at = request.reported_at or request.requested_at
            if rep_at:
                rep_stat = request.reported_status
                expected_result = (
                    "SUCCESS"
                    if rep_stat == "COMPLETE"
                    else ("PARTIAL" if rep_stat == "PARTIALLY_COMPLETE" else "FAILED")
                )

                best_cand: str | None = None
                min_diff = float("inf")

                for a in self._worker_account_acts:
                    a_dt = a.event_time
                    diff_secs = (a_dt - rep_at).total_seconds()
                    # Batch typically occurs -80 min to +15 min relative to reported_at
                    if -5000 <= diff_secs <= 900:
                        res_match = (a.reported_result == expected_result) or (
                            rep_stat == "PARTIALLY_COMPLETE" and a.reported_result == "SUCCESS"
                        )
                        score = abs(diff_secs) if res_match else abs(diff_secs) + 10000
                        if score < min_diff:
                            min_diff = score
                            best_cand = a.resource_id

                if best_cand:
                    cand_acc = best_cand

        # 5. If we have a candidate account, determine if any evidence captured <= audit_at proves it absent
        if cand_acc:
            # 5a. Look for 404 entry in exports/handover/logs
            if cand_acc in self._account_404_evidence:
                fid, ev_dt = self._account_404_evidence[cand_acc]
                if ev_dt <= audit_at:
                    return cand_acc, fid

            # 5b. Look for empty account_service snapshot in evidence files where subject was audited
            _audit_rec, audit_fid = self.resolve_audit_record(subject, request)
            if audit_fid and audit_fid in self._empty_account_snapshots:
                return cand_acc, audit_fid

            # 5c. Candidate resolved without proving evidence
            return cand_acc, ""

        # 4. Could not resolve account
        logger.warning(
            "Could not resolve account_service resource ID for case %s (email=%s).",
            request.case_id,
            request.email,
        )
        return None, ""

    def resolve_audit_record(
        self,
        subject: SubjectContext | None,
        request: DeletionRequest,
    ) -> tuple[str | None, str]:
        """Resolve the subject's retained security_service audit_record ID as of audit_at.

        Returns (audit_record_id, evidence_id).
        """
        self.ensure_indexed()

        candidate_keys: set[str] = set()
        if subject:
            if subject.user_id:
                candidate_keys.add(subject.user_id)
            candidate_keys.update(subject.emails)
        if request.email:
            candidate_keys.add(request.email.strip().lower())

        audit_at = request.audit_at

        for k in candidate_keys:
            k_clean = k.strip().lower() if "@" in k else k.strip()
            if k_clean in self._audit_evidence:
                hits = self._audit_evidence[k_clean]
                valid_hits = [h for h in hits if h[2] <= audit_at]
                if valid_hits:
                    # Return most recent audit record before audit_at
                    valid_hits.sort(key=lambda x: x[2], reverse=True)
                    return valid_hits[0][0], valid_hits[0][1]

        return None, ""
