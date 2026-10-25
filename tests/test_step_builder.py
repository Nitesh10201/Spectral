
from code.pipeline.steps.builder import build_audit_result, create_step, expand_finding
from code.pipeline.steps.sorter import sort_and_number_steps
from code.schemas.enums import DeletionStatus, Operation, Phase, State
from code.schemas.findings import Finding
from code.schemas.inputs import RequiredAction


def test_sort_and_number_steps_empty():
    assert sort_and_number_steps([]) == []


def test_sort_and_number_steps_ordering():
    # Provide steps out of order
    step_ver = create_step(
        operation=Operation.VERIFY_RECORD_ABSENT,
        system_id="b_service",
        resource_id="res_02",
        step_no=99,
    )
    step_find = create_step(
        operation=Operation.REPORT_REMAINING_RECORD,
        system_id="a_service",
        resource_id="res_01",
        evidence_id="ev_01",
        step_no=50,
    )
    step_rem = create_step(
        operation=Operation.DELETE_RECORD,
        system_id="a_service",
        resource_id="res_01",
        step_no=10,
    )

    sorted_steps = sort_and_number_steps([step_ver, step_find, step_rem])
    assert len(sorted_steps) == 3
    assert [s.step_no for s in sorted_steps] == [1, 2, 3]
    assert sorted_steps[0].phase == Phase.FINDING
    assert sorted_steps[1].phase == Phase.REMEDIATION
    assert sorted_steps[2].phase == Phase.VERIFICATION


def test_sort_and_number_steps_deduplication():
    step1 = create_step(Operation.DELETE_RECORD, "svc", "res_1")
    step2 = create_step(Operation.DELETE_RECORD, "svc", "res_1")
    deduped = sort_and_number_steps([step1, step2])
    assert len(deduped) == 1
    assert deduped[0].step_no == 1


def test_expand_finding_data_flow():
    f = Finding(
        system_id="integration_service",
        resource_id="flow_1",
        kind=Operation.REPORT_ACTIVE_DATA_FLOW,
        evidence_id="ev_01",
    )
    steps = expand_finding(f)
    assert len(steps) == 3
    assert steps[0].operation == Operation.REPORT_ACTIVE_DATA_FLOW
    assert steps[0].state == State.ACTIVE
    assert steps[0].evidence_id == "ev_01"

    assert steps[1].operation == Operation.DISABLE_DATA_FLOW
    assert steps[1].state == State.DISABLED
    assert steps[1].evidence_id == ""

    assert steps[2].operation == Operation.VERIFY_DATA_FLOW_DISABLED
    assert steps[2].state == State.DISABLED
    assert steps[2].evidence_id == ""


def test_expand_finding_restore_risk():
    f = Finding(
        system_id="backup_service",
        resource_id="backup_1",
        kind=Operation.REPORT_RESTORE_RISK,
        evidence_id="ev_02",
    )
    steps = expand_finding(f)
    assert len(steps) == 3
    assert steps[0].operation == Operation.REPORT_RESTORE_RISK
    assert steps[1].operation == Operation.BLOCK_RESTORE
    assert steps[2].operation == Operation.VERIFY_RESTORE_BLOCKED


def test_expand_finding_remaining_record_delete():
    f = Finding(
        system_id="account_service",
        resource_id="acc_1",
        kind=Operation.REPORT_REMAINING_RECORD,
        evidence_id="ev_03",
    )
    steps = expand_finding(f, RequiredAction.DELETE)
    assert steps[0].operation == Operation.REPORT_REMAINING_RECORD
    assert steps[1].operation == Operation.DELETE_RECORD
    assert steps[2].operation == Operation.VERIFY_RECORD_ABSENT


def test_expand_finding_remaining_record_redact():
    f = Finding(
        system_id="support_platform",
        resource_id="ticket_1",
        kind=Operation.REPORT_REMAINING_RECORD,
        evidence_id="ev_04",
    )
    steps = expand_finding(f, RequiredAction.REDACT)
    assert steps[0].operation == Operation.REPORT_REMAINING_RECORD
    assert steps[1].operation == Operation.REDACT_RECORD
    assert steps[2].operation == Operation.VERIFY_RECORD_REDACTED


def test_expand_finding_exposed_pii_anonymize():
    f = Finding(
        system_id="analytics_platform",
        resource_id="profile_1",
        kind=Operation.REPORT_EXPOSED_PII,
        evidence_id="ev_05",
    )
    steps = expand_finding(f, RequiredAction.ANONYMIZE)
    assert steps[0].operation == Operation.REPORT_EXPOSED_PII
    assert steps[1].operation == Operation.ANONYMIZE_RECORD
    assert steps[2].operation == Operation.VERIFY_RECORD_ANONYMIZED


def test_build_audit_result_not_applicable():
    res = build_audit_result(
        case_id="case_00",
        status=DeletionStatus.NOT_APPLICABLE,
        steps=[create_step(Operation.VERIFY_RECORD_ABSENT, "svc", "res")],
    )
    assert res.deletion_status == DeletionStatus.NOT_APPLICABLE
    assert res.steps == []


def test_build_audit_result_complete():
    res = build_audit_result(
        case_id="case_01",
        status=DeletionStatus.COMPLETE,
        steps=[
            create_step(
                Operation.VERIFY_RECORD_ABSENT,
                "account_service",
                "acc_01",
                evidence_id="ev_10",
            )
        ],
    )
    assert res.deletion_status == DeletionStatus.COMPLETE
    assert len(res.steps) == 1
    assert res.steps[0].step_no == 1
    assert res.steps[0].evidence_id == "ev_10"


def test_build_audit_result_incomplete():
    f = Finding(
        system_id="account_service",
        resource_id="acc_02",
        kind=Operation.REPORT_REMAINING_RECORD,
        evidence_id="ev_12",
    )
    expanded = expand_finding(f, RequiredAction.DELETE)
    res = build_audit_result(
        case_id="case_02",
        status=DeletionStatus.INCOMPLETE,
        steps=expanded,
    )
    assert res.deletion_status == DeletionStatus.INCOMPLETE
    assert len(res.steps) == 3
    assert [s.step_no for s in res.steps] == [1, 2, 3]
    assert res.steps[0].evidence_id == "ev_12"
    assert res.steps[1].evidence_id == ""
    assert res.steps[2].evidence_id == ""
