from code.pipeline.identity.resolver import IdentityResolver, compute_sha256
from code.schemas.enums import ReportedStatus
from code.schemas.inputs import AuditLogEntry, DeletionRequest, UserIdentity
from datetime import datetime


def test_compute_sha256():
    # Deterministic test
    assert compute_sha256("test@example.com") == (
        "973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b"
    )


def test_resolve_current_email_synthetic():
    u = UserIdentity(
        user_id="user_999",
        name="Alice Smith",
        email="alice.smith@example.org",
        phone="+1 555-0199",
        email_hash=compute_sha256("alice.smith@example.org"),
        updated_at=datetime.fromisoformat("2026-01-01T00:00:00Z"),
    )
    resolver = IdentityResolver(identities=[u], audit_log=[])

    ctx = resolver.resolve_by_email("alice.smith@example.org")
    assert ctx is not None
    assert ctx.user_id == "user_999"
    assert ctx.current_email == "alice.smith@example.org"
    assert "alice.smith@example.org" in ctx.emails
    assert "+1 555-0199" in ctx.phones
    assert "Alice Smith" in ctx.names
    assert compute_sha256("alice.smith@example.org") in ctx.email_hashes


def test_resolve_historical_email_synthetic():
    u = UserIdentity(
        user_id="user_888",
        name="Bob Jones",
        email="bob.new@example.org",
        phone="+1 555-0188",
        email_hash=compute_sha256("bob.new@example.org"),
        updated_at=datetime.fromisoformat("2026-06-01T00:00:00Z"),
    )
    audit = AuditLogEntry(
        audit_id="audit_888",
        user_id="user_888",
        event_time=datetime.fromisoformat("2026-03-01T00:00:00Z"),
        field_name="email",
        old_value="bob.old@example.org",
        new_value="bob.new@example.org",
    )
    resolver = IdentityResolver(identities=[u], audit_log=[audit])

    # Request submitted with old email
    ctx = resolver.resolve_by_email("bob.old@example.org")
    assert ctx is not None
    assert ctx.user_id == "user_888"
    assert "bob.old@example.org" in ctx.emails
    assert "bob.new@example.org" in ctx.emails
    # Both SHA-256 hashes must be present
    assert compute_sha256("bob.old@example.org") in ctx.email_hashes
    assert compute_sha256("bob.new@example.org") in ctx.email_hashes


def test_temporal_audit_cutoff_synthetic():
    u = UserIdentity(
        user_id="user_777",
        name="Charlie Brown",
        email="charlie@example.org",
        phone="+1 555-0177",
    )
    # Event before cutoff
    audit_valid = AuditLogEntry(
        audit_id="audit_1",
        user_id="user_777",
        event_time=datetime.fromisoformat("2026-02-01T00:00:00Z"),
        field_name="phone",
        old_value="+1 555-0001",
        new_value="+1 555-0177",
    )
    # Event after cutoff
    audit_future = AuditLogEntry(
        audit_id="audit_2",
        user_id="user_777",
        event_time=datetime.fromisoformat("2026-09-01T00:00:00Z"),
        field_name="phone",
        old_value="+1 555-0177",
        new_value="+1 555-9999",
    )
    resolver = IdentityResolver(identities=[u], audit_log=[audit_valid, audit_future])

    cutoff = datetime.fromisoformat("2026-05-01T00:00:00Z")
    ctx = resolver.resolve_by_email("charlie@example.org", audit_at=cutoff)

    assert ctx is not None
    assert "+1 555-0001" in ctx.phones
    # Future phone must NOT be included
    assert "+1 555-9999" not in ctx.phones


def test_resolve_unknown_email():
    resolver = IdentityResolver(identities=[], audit_log=[])
    assert resolver.resolve_by_email("unknown@nowhere.com") is None


def test_resolve_for_request():
    u = UserIdentity(
        user_id="user_555",
        name="David Lee",
        email="david@example.org",
    )
    resolver = IdentityResolver(identities=[u], audit_log=[])

    req = DeletionRequest(
        case_id="case_01",
        email="david@example.org",
        requested_at=datetime.fromisoformat("2026-04-01T00:00:00Z"),
        reported_status=ReportedStatus.COMPLETE,
        audit_at=datetime.fromisoformat("2026-04-05T00:00:00Z"),
        request_text="Delete my account",
    )

    ctx = resolver.resolve_for_request(req)
    assert ctx is not None
    assert ctx.user_id == "user_555"
