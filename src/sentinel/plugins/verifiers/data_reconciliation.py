"""Verifier that re-runs a reconciliation target's snapshot comparison.

Reuses the detector's ``DataSource``/comparison logic rather than duplicating
it: given an incident produced by ``DataReconciliationDetector``, look up its
target by the ``target_name`` stored in ``incident.context`` and confirm no
mismatch remains between the source and target snapshots.
"""

from __future__ import annotations

from sentinel.core.incident import Incident
from sentinel.plugins.detectors.data_reconciliation import (
    ReconciliationTarget,
    _mismatches,
)


class DataReconciliationVerifier:
    """Confirm a data-reconciliation incident has no remaining mismatches."""

    def __init__(self, targets: list[ReconciliationTarget]) -> None:
        self._targets = {t.name: t for t in targets}

    def verify(self, incident: Incident) -> bool:
        """Return True iff the incident's target now matches source-to-target.

        Fail closed: if the incident's ``target_name`` is unknown to this
        verifier (so we cannot re-check), return False rather than guessing the
        incident is resolved.
        """
        name = incident.context.get("target_name")
        if not isinstance(name, str) or name not in self._targets:
            return False
        target = self._targets[name]
        return not _mismatches(target.source, target.target)
