from code.schemas.enums import OPERATION_ORDER, PHASE_ORDER
from code.schemas.outputs import Step
from collections.abc import Sequence


def sort_and_number_steps(steps: Sequence[Step]) -> list[Step]:
    """Deduplicate, sort by contract key, and consecutively number steps starting from 1."""
    if not steps:
        return []

    seen: set[tuple[str, str, str, str]] = set()
    unique_steps: list[Step] = []
    for s in steps:
        key = (s.phase.value, s.operation.value, s.system_id, s.resource_id)
        if key not in seen:
            seen.add(key)
            unique_steps.append(s)

    sorted_steps = sorted(
        unique_steps,
        key=lambda x: (
            PHASE_ORDER[x.phase],
            OPERATION_ORDER[x.operation],
            x.system_id,
            x.resource_id,
        ),
    )

    return [s.model_copy(update={"step_no": i + 1}) for i, s in enumerate(sorted_steps)]
