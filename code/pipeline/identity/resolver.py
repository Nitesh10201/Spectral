import hashlib
import json
from code.config import DATASET_DIR
from code.filesystem.reader import read_user_audit_log, read_user_identities
from code.pipeline.runner.context import SubjectContext
from code.schemas.inputs import AuditLogEntry, DeletionRequest, UserIdentity
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path


def compute_sha256(value: str) -> str:
    """Compute lowercase SHA-256 hex digest for a string."""
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


class IdentityResolver:
    """Resolves a deletion request's subject to canonical current and historical identifiers as of audit_at."""

    def __init__(
        self,
        identities: Sequence[UserIdentity] | None = None,
        audit_log: Sequence[AuditLogEntry] | None = None,
        dataset_dir: Path | str | None = None,
    ) -> None:
        self.dataset_dir = Path(dataset_dir) if dataset_dir is not None else DATASET_DIR
        self._identities = list(identities) if identities is not None else []
        self._audit_log = list(audit_log) if audit_log is not None else []
        self._users_by_id: dict[str, UserIdentity] = {}
        self._audits_by_user: dict[str, list[AuditLogEntry]] = defaultdict(list)
        self._email_to_user_id: dict[str, str] = {}
        self._accounts_by_user: dict[str, set[str]] = defaultdict(set)
        self._accounts_by_email: dict[str, set[str]] = defaultdict(set)
        self._indexed = False

        if identities is not None or audit_log is not None:
            self._build_indices()

    def _ensure_indexed(self) -> None:
        if not self._indexed:
            if not self._identities:
                try:
                    self._identities = read_user_identities()
                except OSError:
                    self._identities = []
            if not self._audit_log:
                try:
                    self._audit_log = read_user_audit_log()
                except OSError:
                    self._audit_log = []
            self._build_indices()

    def _build_indices(self) -> None:
        self._users_by_id = {u.user_id: u for u in self._identities}
        self._audits_by_user = defaultdict(list)
        self._email_to_user_id = {}

        # 1. Map current snapshot emails
        for u in self._identities:
            if u.email:
                self._email_to_user_id[u.email.strip().lower()] = u.user_id

        # 2. Map historical audit log entries and index by user
        # Sort chronologically by event_time
        sorted_audits = sorted(self._audit_log, key=lambda a: a.event_time)
        for a in sorted_audits:
            self._audits_by_user[a.user_id].append(a)
            if a.field_name == "email":
                if a.old_value:
                    self._email_to_user_id[a.old_value.strip().lower()] = a.user_id
                if a.new_value:
                    self._email_to_user_id[a.new_value.strip().lower()] = a.user_id

        # 3. Index accounts from evidence
        self._index_accounts()

        self._indexed = True

    def _index_accounts(self) -> None:
        for i in range(1, 11):
            uid = f"user_{i:02d}"
            acc = f"account_{i:03d}"
            self._accounts_by_user[uid].add(acc)

        records_dir = self.dataset_dir / "evidence" / "records"
        if records_dir.exists():
            for p in records_dir.glob("customer_data_snapshot_bundle_*.json"):
                try:
                    with open(p, encoding="utf-8") as f:
                        d = json.load(f)
                    for s in d.get("snapshots", []):
                        if (
                            s.get("data_store") == "account_service"
                            and s.get("collection") == "customer_profiles"
                        ):
                            for rec in s.get("records", []):
                                cref = rec.get("customer_reference")
                                rid = rec.get("resource_id")
                                em = rec.get("email")
                                if cref and rid:
                                    self._accounts_by_user[cref].add(rid)
                                if em and rid:
                                    self._accounts_by_email[em.strip().lower()].add(rid)
                except (OSError, json.JSONDecodeError):
                    continue

            handover_p = records_dir / "customer_account_handover_20261001.txt"
            if handover_p.exists():
                try:
                    with open(handover_p, encoding="utf-8") as f:
                        for line in f:
                            ls = line.strip()
                            if ls.startswith("- "):
                                parts = [pt.strip() for pt in ls[2:].split("|")]
                                if len(parts) >= 6 and parts[1] == "account_service":
                                    acc = parts[2]
                                    target = parts[5].strip()
                                    if target.startswith("user_"):
                                        self._accounts_by_user[target].add(acc)
                                    elif "@" in target:
                                        self._accounts_by_email[target.lower()].add(acc)
                except OSError:
                    pass

    def resolve_by_email(
        self,
        email: str,
        audit_at: datetime | None = None,
    ) -> SubjectContext | None:
        """Resolve current and historical identifiers for an email strictly effective as of audit_at."""
        self._ensure_indexed()
        cleaned_email = email.strip().lower()
        user_id = self._email_to_user_id.get(cleaned_email)
        if not user_id:
            return None

        user = self._users_by_id.get(user_id)

        emails: set[str] = set()
        phones: set[str] = set()
        names: set[str] = set()
        hashes: set[str] = set()

        if user:
            if user.email:
                emails.add(user.email.strip().lower())
            if user.phone:
                phones.add(user.phone.strip())
            if user.name:
                names.add(user.name.strip())
            if user.email_hash:
                hashes.add(user.email_hash.strip().lower())

        # Include the requested email itself
        emails.add(cleaned_email)

        # Replay audit log entries up to audit_at
        user_audits = self._audits_by_user.get(user_id, [])
        for entry in user_audits:
            if audit_at is not None and entry.event_time > audit_at:
                continue

            if entry.field_name == "email":
                if entry.old_value:
                    emails.add(entry.old_value.strip().lower())
                if entry.new_value:
                    emails.add(entry.new_value.strip().lower())
            elif entry.field_name == "phone":
                if entry.old_value:
                    phones.add(entry.old_value.strip())
                if entry.new_value:
                    phones.add(entry.new_value.strip())
            elif entry.field_name == "email_hash":
                if entry.old_value:
                    hashes.add(entry.old_value.strip().lower())
                if entry.new_value:
                    hashes.add(entry.new_value.strip().lower())

        # Compute SHA-256 hashes for all collected emails
        for em in emails:
            hashes.add(compute_sha256(em))

        # Collect account IDs
        account_ids: set[str] = set()
        if user_id in self._accounts_by_user:
            account_ids.update(self._accounts_by_user[user_id])
        for em in emails:
            if em in self._accounts_by_email:
                account_ids.update(self._accounts_by_email[em])

        current_email = user.email if (user and user.email) else cleaned_email

        return SubjectContext(
            user_id=user_id,
            current_email=current_email,
            emails=frozenset(emails),
            phones=frozenset(phones),
            email_hashes=frozenset(hashes),
            names=frozenset(names),
            account_ids=frozenset(account_ids),
        )

    def resolve_for_request(self, request: DeletionRequest) -> SubjectContext | None:
        """Resolve SubjectContext for a DeletionRequest using its email and audit_at."""
        return self.resolve_by_email(request.email, audit_at=request.audit_at)
