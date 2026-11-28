"""Moteur de pseudonymisation réversible, réhydratation et garde-fou anti-fuite."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from pydantic import BaseModel, ConfigDict

from symbolon.detectors import (
    DetectedSpan,
    NerBackend,
    detect_deterministic,
    detect_known_persons,
    resolve_overlaps,
)
from symbolon.normalization import fold_with_map, is_safe_word
from symbolon.vault import AMBIGUOUS_SURNAME, EntityKind, PiiVault

_TOKEN_PATTERN = re.compile(r"\[(?:PERSONNE|IBAN|NIR|SIREN|SIRET|EMAIL|TEL)_\d{2,}\]")
_BORNE_AVANT = r"(?<![a-z])"
_BORNE_APRES = r"(?![a-z])"


class PiiLeakError(RuntimeError):
    """Levée par `assert_no_leak` si une donnée connue du coffre subsiste en clair."""


class ScrubResult(BaseModel):
    """Résultat structuré d'une pseudonymisation (sans exposer les valeurs brutes dans stats)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pseudonymized_text: str
    replacements_count: int
    tokens_by_kind: dict[str, int]
    spans: tuple[DetectedSpan, ...]


class Scrubber:
    """Orchestrateur de pseudonymisation en 2 passes (détection -> chaînage patronymique).

    La double passe rend le chaînage patronymique indépendant de l'ordre d'apparition dans
    le document : si 'LOYER SCI DUPONT' apparaît avant 'M. Pierre Dupont', les deux
    reçoivent le même jeton [PERSONNE_01]. Si un homonyme 'Mme Marie Dupont' existe aussi,
    'dupont' est marqué ambigu et n'est pas rattaché à tort.
    """

    def __init__(
        self,
        vault: PiiVault | None = None,
        ner: NerBackend | None = None,
        known_persons: Iterable[str] = (),
    ) -> None:
        self.vault = vault if vault is not None else PiiVault()
        self.ner = ner
        self._extra_persons = tuple(known_persons)

    def scrub(self, text: str) -> ScrubResult:
        if not text:
            return ScrubResult(
                pseudonymized_text="",
                replacements_count=0,
                tokens_by_kind={},
                spans=(),
            )

        # Passe 1 : détecteurs déterministes + NER optionnel + personnes déjà connues du coffre
        pass1_raw: list[DetectedSpan] = detect_deterministic(text)
        if self.ner is not None:
            pass1_raw.extend(self.ner.predict(text))
        pass1_raw.extend(detect_known_persons(text, self.vault, self._extra_persons))
        pass1_spans = resolve_overlaps(text, pass1_raw)

        # Enregistre les personnes complètes d'abord pour détecter immédiatement les homonymes
        person_spans = [s for s in pass1_spans if s.kind is EntityKind.PERSON]
        person_spans.sort(key=lambda s: -len(s.text.split()))
        for s in person_spans:
            self.vault.get_or_create_token(s.text, EntityKind.PERSON, civility_gender=s.civility_gender)

        # Passe 2 : raccroche les occurrences isolées des patronymes non ambigus découverts en passe 1
        pass2_links = detect_known_persons(text, self.vault, self._extra_persons)
        final_spans = resolve_overlaps(text, [*pass1_spans, *pass2_links])

        # Remplacement exact en préservant les offsets
        parts: list[str] = []
        cursor = 0
        counts: dict[str, int] = {}
        for span in final_spans:
            parts.append(text[cursor : span.start])
            token = self.vault.get_or_create_token(
                span.text, span.kind, civility_gender=span.civility_gender
            )
            parts.append(token)
            counts[span.kind.value] = counts.get(span.kind.value, 0) + 1
            cursor = span.end
        parts.append(text[cursor:])

        return ScrubResult(
            pseudonymized_text="".join(parts),
            replacements_count=len(final_spans),
            tokens_by_kind=counts,
            spans=tuple(final_spans),
        )


def rehydrate(text: str, vault: PiiVault) -> str:
    """Restaure localement les jetons connus du coffre ; laisse les jetons inconnus visibles."""
    if not text or not vault.token_to_entity:
        return text

    def _replace(match: re.Match[str]) -> str:
        tok = match.group(0)
        return vault.token_to_entity.get(tok, tok)

    return _TOKEN_PATTERN.sub(_replace, text)


_COMPACT_SEP = re.compile(r"[\s.\-]+")
_STRUCTURED_KINDS = frozenset(
    {
        EntityKind.IBAN.value,
        EntityKind.NIR.value,
        EntityKind.SIREN.value,
        EntityKind.SIRET.value,
        EntityKind.EMAIL.value,
        EntityKind.PHONE.value,
    }
)


def find_leaks(texts: Sequence[str], vault: PiiVault) -> list[str]:
    """Vérifie qu'aucune entité enregistrée dans le coffre ne subsiste en clair dans `texts`.

    - Identifiants structurés (IBAN, NIR, SIREN, SIRET, EMAIL, TEL) : comparaison par sous-chaîne
      sur forme compacte sans séparateurs ni frontières de mot (bloque les contournements par
      lettres collées type `XFR76...X`).
    - Personnes : comparaison par mot entier (évite les faux positifs « Marchand » dans
      « marchandises »). Pour un patronyme isolé, la majuscule initiale est exigée (évite
      « petit matériel » quand « Mme Claire Petit » est dans le coffre).
    """
    structured_compact: set[str] = set()
    person_full_names: set[str] = set()
    person_single_words: set[str] = set()

    for k in vault.entity_to_token:
        kind_str, raw_key = k.split(":", 1)
        if kind_str in _STRUCTURED_KINDS:
            compact = _COMPACT_SEP.sub("", raw_key).lower()
            if len(compact) >= 5:
                structured_compact.add(compact)
        elif kind_str == EntityKind.PERSON.value:
            if len(raw_key) >= 3 and not is_safe_word(raw_key):
                if " " in raw_key:
                    person_full_names.add(raw_key)
                else:
                    person_single_words.add(raw_key)

    for surname, tok in vault.surname_to_token.items():
        if tok != AMBIGUOUS_SURNAME and len(surname) >= 3 and not is_safe_word(surname):
            person_single_words.add(surname)

    leaks: set[str] = set()
    for text in texts:
        folded_doc = fold_with_map(text)
        folded = folded_doc.folded
        compact_text = _COMPACT_SEP.sub("", folded)

        for compact_id in structured_compact:
            if compact_id in compact_text:
                leaks.add(compact_id)

        for full_name in person_full_names:
            if re.search(_BORNE_AVANT + re.escape(full_name) + _BORNE_APRES, folded):
                leaks.add(full_name)

        for single in person_single_words:
            pattern = re.compile(_BORNE_AVANT + re.escape(single) + _BORNE_APRES)
            for m in pattern.finditer(folded):
                orig_start = folded_doc.starts[m.start()]
                if text[orig_start].isupper():
                    leaks.add(single)
                    break
    return sorted(leaks)


def assert_no_leak(texts: Sequence[str], vault: PiiVault) -> None:
    """Garde-fou fail-closed : lève PiiLeakError si une entité du coffre fuit en clair."""
    leaks = find_leaks(texts, vault)
    if leaks:
        raise PiiLeakError(f"{len(leaks)} entité(s) sensible(s) détectée(s) en clair avant envoi externe")
