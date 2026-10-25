from code.filesystem.reader import read_deletion_rules
from code.schemas.inputs import DeletionRule, RequiredAction
from collections.abc import Sequence

DEFAULT_ACTIONS: dict[str, RequiredAction] = {
    "USER_PROFILE": RequiredAction.DELETE,
    "SECONDARY_IDENTIFIER": RequiredAction.DELETE,
    "SEARCH_INDEX_ENTRY": RequiredAction.DELETE,
    "CACHE_ENTRY": RequiredAction.DELETE,
    "SUPPORT_MESSAGE": RequiredAction.REDACT,
    "SUPPORT_ATTACHMENT": RequiredAction.DELETE,
    "ANALYTICS_PROFILE": RequiredAction.ANONYMIZE,
    "PRODUCT_TELEMETRY": RequiredAction.ANONYMIZE,
    "USER_EXPORT": RequiredAction.DELETE,
    "MARKETING_PROFILE": RequiredAction.DELETE,
    "EMAIL_DELIVERY_LOG": RequiredAction.REDACT,
    "SECURITY_AUDIT_LOG": RequiredAction.RETAIN,
    "LEGAL_HOLD_RECORD": RequiredAction.RETAIN,
    "BACKUP_ARCHIVE": RequiredAction.RETAIN,
    "ACCOUNT_TOMBSTONE": RequiredAction.REDACT,
}


class DeletionRulesEngine:
    """Evaluates data categories against deletion_rules.csv policy."""

    def __init__(self, rules: Sequence[DeletionRule] | None = None) -> None:
        self._rules = list(rules) if rules is not None else []
        self._rule_map: dict[str, RequiredAction] = dict(DEFAULT_ACTIONS)

        if not self._rules:
            try:
                self._rules = read_deletion_rules()
            except OSError:
                self._rules = []

        for rule in self._rules:
            self._rule_map[rule.data_category] = rule.required_action

    def get_action_for_category(
        self,
        category: str | None,
        default: RequiredAction = RequiredAction.DELETE,
    ) -> RequiredAction:
        """Resolve the required action (DELETE, REDACT, ANONYMIZE, RETAIN) for a data category."""
        if not category:
            return default
        return self._rule_map.get(category.strip().upper(), default)

    def is_retained_category(self, category: str | None) -> bool:
        """Check whether records in this category must be retained according to policy."""
        return self.get_action_for_category(category) == RequiredAction.RETAIN
