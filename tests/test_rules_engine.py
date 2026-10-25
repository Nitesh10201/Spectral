from code.policy.engine.rules_engine import DeletionRulesEngine
from code.schemas.inputs import DeletionRule, RequiredAction


def test_rules_engine_default_actions():
    engine = DeletionRulesEngine(rules=[])
    assert engine.get_action_for_category("USER_PROFILE") == RequiredAction.DELETE
    assert engine.get_action_for_category("ANALYTICS_PROFILE") == RequiredAction.ANONYMIZE
    assert engine.get_action_for_category("SUPPORT_MESSAGE") == RequiredAction.REDACT
    assert engine.get_action_for_category("SECURITY_AUDIT_LOG") == RequiredAction.RETAIN
    assert engine.get_action_for_category("ACCOUNT_TOMBSTONE") == RequiredAction.REDACT
    assert engine.get_action_for_category("NON_EXISTENT") == RequiredAction.DELETE


def test_rules_engine_custom_rules():
    custom_rule = DeletionRule(
        rule_id="custom_01",
        data_category="CUSTOM_CATEGORY",
        condition="Always",
        required_action=RequiredAction.ANONYMIZE,
    )
    engine = DeletionRulesEngine(rules=[custom_rule])
    assert engine.get_action_for_category("CUSTOM_CATEGORY") == RequiredAction.ANONYMIZE
    assert not engine.is_retained_category("CUSTOM_CATEGORY")


def test_rules_engine_retained():
    engine = DeletionRulesEngine(rules=[])
    assert engine.is_retained_category("SECURITY_AUDIT_LOG")
    assert engine.is_retained_category("LEGAL_HOLD_RECORD")
    assert engine.is_retained_category("BACKUP_ARCHIVE")
    assert not engine.is_retained_category("USER_PROFILE")
