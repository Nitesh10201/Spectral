from code.pipeline.classifier.request_classifier import HybridRequestClassifier
from code.schemas.inputs import DeletionRequest, ReportedStatus
from datetime import datetime


def _make_req(text: str) -> DeletionRequest:
    return DeletionRequest(
        case_id="case_synth_clf",
        email="user@example.com",
        requested_at=datetime.fromisoformat("2026-09-01T10:00:00+00:00"),
        reported_status=ReportedStatus.COMPLETE,
        reported_at=datetime.fromisoformat("2026-09-02T10:00:00+00:00"),
        audit_at=datetime.fromisoformat("2026-09-20T12:00:00+00:00"),
        request_text=text,
    )


def test_request_classifier_positive_intents():
    clf = HybridRequestClassifier()
    assert clf.is_deletion_authorized(_make_req("Please delete my account."))
    assert clf.is_deletion_authorized(_make_req("I would like to erase all personal data."))
    assert clf.is_deletion_authorized(_make_req("Please close my account immediately."))
    assert clf.is_deletion_authorized(_make_req("Veuillez supprimer mon compte."))
    assert clf.is_deletion_authorized(_make_req("Solicito a exclusão permanente da conta."))
    assert clf.is_deletion_authorized(_make_req("계정 탈퇴 및 정보 삭제를 요청합니다."))
    assert clf.is_deletion_authorized(_make_req("アカウントの削除をお願いします。"))


def test_request_classifier_negative_non_deletion_intents():
    clf = HybridRequestClassifier()
    assert not clf.is_deletion_authorized(
        _make_req("Please replace my mobile number and leave the account active.")
    )
    assert not clf.is_deletion_authorized(
        _make_req("Stop promotional emails. I am not asking for deletion.")
    )
    assert not clf.is_deletion_authorized(
        _make_req("I'd like to download my data in a portable format. Please keep the account as it is.")
    )
    assert not clf.is_deletion_authorized(
        _make_req("I need help resetting the login. Do not close the account.")
    )
    assert not clf.is_deletion_authorized(
        _make_req("My surname is misspelled. Can you correct it without removing any of my records?")
    )
    assert not clf.is_deletion_authorized(
        _make_req("Remove me from marketing lists only. I still want receipts.")
    )
    assert not clf.is_deletion_authorized(
        _make_req("Send me a copy of my records. Please don't delete anything.")
    )


def test_request_classifier_llm_fallback():
    called = []

    def mock_llm(text: str) -> bool:
        called.append(text)
        return False

    clf = HybridRequestClassifier(llm_fallback=mock_llm)
    # Phrasing with neither obvious positive nor negative regexes
    req = _make_req("Can we adjust our agreement?")
    res = clf.is_deletion_authorized(req)
    assert not res
    assert len(called) == 1
