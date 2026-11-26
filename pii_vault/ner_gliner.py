"""Adaptateur NER local optionnel basé sur GLiNER (import paresseux, fail-closed)."""

from __future__ import annotations

from collections.abc import Sequence

from pii_vault.detectors import DetectedSpan
from pii_vault.vault import EntityKind

DEFAULT_GLINER_MODEL = "urchade/gliner_multi_pii-v1"

_LABEL_TO_KIND: dict[str, EntityKind] = {
    "person": EntityKind.PERSON,
    "email": EntityKind.EMAIL,
    "phone number": EntityKind.PHONE,
    "iban": EntityKind.IBAN,
}


class GlinerUnavailableError(RuntimeError):
    """Levée lorsque l'extra optionnel `[ner]` (gliner) n'est pas installé."""


class GlinerNerBackend:
    """Backend NER 100 % local pour détecter les personnes hors civilités explicites."""

    def __init__(
        self,
        model_name: str = DEFAULT_GLINER_MODEL,
        threshold: float = 0.45,
        local_files_only: bool = True,
    ) -> None:
        try:
            from gliner import GLiNER  # type: ignore[import-not-found]
        except ImportError as exc:
            raise GlinerUnavailableError(
                "GLiNER n'est pas installé. Installez l'extra optionnel : pip install 'pii-vault-mcp[ner]'."
            ) from exc
        self._threshold = threshold
        self._labels = list(_LABEL_TO_KIND.keys())
        self._model = GLiNER.from_pretrained(model_name, local_files_only=local_files_only)

    def predict(self, text: str) -> Sequence[DetectedSpan]:
        raw_entities = self._model.predict_entities(text, self._labels, threshold=self._threshold)
        spans: list[DetectedSpan] = []
        for ent in raw_entities:
            label = str(ent.get("label", "")).lower()
            kind = _LABEL_TO_KIND.get(label)
            if kind is None:
                continue
            start = int(ent["start"])
            end = int(ent["end"])
            if 0 <= start < end <= len(text):
                spans.append(
                    DetectedSpan(
                        start=start,
                        end=end,
                        text=text[start:end],
                        kind=kind,
                        source="gliner",
                    )
                )
        return spans
