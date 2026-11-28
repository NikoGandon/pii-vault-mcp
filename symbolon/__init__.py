"""Symbolon (symbolon-pii) : pseudonymisation réversible RGPD (Art. 4(5)) 100 % locale pour le français."""

from __future__ import annotations

from symbolon.detectors import DetectedSpan, NerBackend, detect_deterministic
from symbolon.scrubber import (
    PiiLeakError,
    ScrubResult,
    Scrubber,
    assert_no_leak,
    rehydrate,
)
from symbolon.vault import EntityKind, PiiVault, VaultSnapshot

__all__ = [
    "DetectedSpan",
    "EntityKind",
    "NerBackend",
    "PiiLeakError",
    "PiiVault",
    "ScrubResult",
    "Scrubber",
    "VaultSnapshot",
    "assert_no_leak",
    "detect_deterministic",
    "rehydrate",
]

__version__ = "0.1.0"
