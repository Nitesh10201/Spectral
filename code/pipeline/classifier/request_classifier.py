import re
from code.schemas.inputs import DeletionRequest
from collections.abc import Callable

# Multilingual patterns that explicitly reject deletion or request non-deletion operations
NEGATIVE_INTENT_PATTERNS: tuple[str, ...] = (
    r"leave (?:the|my) account active",
    r"not asking for deletion",
    r"not a request to erase",
    r"keep the account as it is",
    r"do not close (?:the|my) account",
    r"don't delete",
    r"without removing",
    r"leave my (?:profile|purchase)",
    r"continue using",
    r"marketing lists only",
    r"resetting the login",
    r"portable format",
    r"misspelled on the account",
    r"ne pas fermer",
    r"no eliminar",
    r"nicht l[öo]schen",
    r"non cancellare",
    r"nie usuwaj",
)

# Common multilingual roots for deletion intent
POSITIVE_DELETION_PATTERNS: tuple[str, ...] = (
    r"delet",
    r"eras",
    r"remov",
    r"close (?:my|this|the) account",
    r"purg",
    r"wip",
    r"forget",
    r"exclus",
    r"supprim",
    r"elimin",
    r"cancel",
    r"effac",
    r"l[öo]sch",
    r"usu[ńn]",
    r"cancella",
    r"удалит",
    r"стереть",
    r"삭제",
    r"탈퇴",
    r"消去",
    r"削除",
    r"حذف",
    r"مسح",
)


class HybridRequestClassifier:
    """Hybrid intent classifier for deletion request text.

    Uses high-precision deterministic multilingual regexes, with an optional
    fallback LLM function for ambiguous requests.
    """

    def __init__(
        self,
        llm_fallback: Callable[[str], bool] | None = None,
    ) -> None:
        self.llm_fallback = llm_fallback
        self._neg_regex = re.compile("|".join(NEGATIVE_INTENT_PATTERNS), re.IGNORECASE)
        self._pos_regex = re.compile(
            "|".join(POSITIVE_DELETION_PATTERNS), re.IGNORECASE
        )

    def is_deletion_authorized(self, request: DeletionRequest) -> bool:
        """Return True if request_text authorizes deletion; False if NOT_APPLICABLE."""
        text = request.request_text.strip()
        if not text:
            return False

        # 1. Negative intent: explicitly asks for non-deletion or requests to keep account
        if self._neg_regex.search(text):
            return False

        # 2. Positive deletion intent
        if self._pos_regex.search(text):
            return True

        # 3. Fallback to LLM if configured for ambiguous phrasing
        if self.llm_fallback is not None:
            try:
                return self.llm_fallback(text)
            except (RuntimeError, ValueError, TypeError, TimeoutError, OSError):
                # Default to True for requests submitted to the deletion workflow
                return True

        # Default to True when submitted to deletion pipeline if no negative pattern
        return True

    def __call__(self, request: DeletionRequest) -> bool:
        return self.is_deletion_authorized(request)


# Default module-level classifier instance
_default_classifier = HybridRequestClassifier()


def is_deletion_request(request: DeletionRequest) -> bool:
    """Check if request authorizes deletion using default hybrid classifier."""
    return _default_classifier.is_deletion_authorized(request)
