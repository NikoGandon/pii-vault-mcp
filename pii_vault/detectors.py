"""Détecteurs déterministes d'entités personnelles françaises et protocole NER local."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from pii_vault.normalization import fold_text, fold_with_map, is_safe_word, is_trailing_city
from pii_vault.validators import (
    is_valid_french_phone,
    is_valid_iban,
    is_valid_nir,
    is_valid_siren,
    is_valid_siret,
)
from pii_vault.vault import AMBIGUOUS_SURNAME, CivilityGender, EntityKind, PiiVault

# Priorité lors de la résolution des chevauchements (plus élevé = prioritaire)
_KIND_PRIORITY: dict[EntityKind, int] = {
    EntityKind.IBAN: 100,
    EntityKind.EMAIL: 95,
    EntityKind.NIR: 90,
    EntityKind.SIRET: 85,
    EntityKind.PHONE: 80,
    EntityKind.SIREN: 75,
    EntityKind.PERSON: 70,
}

_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[\s\-]?[A-Z0-9]{4}){3,7}(?:[\s\-]?[A-Z0-9]{1,3})?\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_NIR_RE = re.compile(
    r"(?<!\d)[123478][\s.\-]?\d{2}[\s.\-]?\d{2}[\s.\-]?(?:\d{2}|2[ABab])[\s.\-]?\d{3}[\s.\-]?\d{3}[\s.\-]?\d{2}(?!\d)"
)
# SIRET : 14 chiffres non suivis d'une devise (évite tout télescopage avec un montant)
_SIRET_RE = re.compile(
    r"(?<!\d)\d{3}[\s.\-]?\d{3}[\s.\-]?\d{3}[\s.\-]?\d{5}(?!\d)(?!\s*(?:€|EUR|USD|\$|k€|M€)\b)",
    re.IGNORECASE,
)
# SIREN : contexte explicite obligatoire (SIREN / RCS) — ne jamais capturer un montant nu type "125 000 000 EUR"
_SIREN_CONTEXT_RE = re.compile(
    r"\b(?:siren|rcs(?:\s+[A-Za-zÀ-ÖØ-öø-ÿ\-]+)?)\s*(?:n°|n\.|no|#|:|\-)?\s*(\d{3}[\s.]?\d{3}[\s.]?\d{3})(?![\s.]?\d)",
    re.IGNORECASE,
)
# Téléphones FR : formats compact (0612345678), espacé/ponctué (06 12 34 56 78) et international (+33 / 0033)
_PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:(?:\+33|0033)[\s.\-]?[1-9](?:[\s.\-]?\d{2}){4}|0[1-9](?:[\s.\-]?\d{2}){4})(?![A-Za-z0-9])"
)

# Civilités françaises suivies d'un nom propre sur la même ligne (1 à 3 mots capitalisés, tirets acceptés)
_CIVILITY_PERSON_RE = re.compile(
    r"\b(M\.|Mr\.?|Mme\.?|Mlle\.?|Dr\.?|Me\.?|Monsieur|Madame|Mademoiselle|Docteur|Maître|Maitre)"
    r"[ \t]+([A-ZÀ-ÖØ-Þ][A-ZÀ-ÖØ-Þa-zà-öø-ÿ'\-]+(?:[ \t]+[A-ZÀ-ÖØ-Þ][A-ZÀ-ÖØ-Þa-zà-öø-ÿ'\-]+){0,2})"
)

_MASC_CIVILITIES = frozenset({"m.", "mr", "mr.", "monsieur"})
_FEM_CIVILITIES = frozenset({"mme", "mme.", "mlle", "mlle.", "madame", "mademoiselle"})

# Déjà pseudonymisé : ne jamais re-détecter un jeton [PERSONNE_01], [IBAN_02], etc.
_TOKEN_RE = re.compile(r"\[(?:PERSONNE|IBAN|NIR|SIREN|SIRET|EMAIL|TEL)_\d{2,}\]")

_BORNE_AVANT = r"(?<![a-z])"
_BORNE_APRES = r"(?![a-z])"


class DetectedSpan(BaseModel):
    """Occurrence détectée dans un texte brut (offsets exacts [start, end))."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    start: int
    end: int
    text: str
    kind: EntityKind
    source: str
    civility_gender: CivilityGender | None = None


class NerBackend(Protocol):
    """Protocole de backend NER local optionnel (ex. GLiNER), sans dépendance obligatoire."""

    def predict(self, text: str) -> Sequence[DetectedSpan]: ...


def _trim_person_candidate(raw: str) -> str:
    """Retire en fin de nom propre les mots-outils/libellés, et une ville seulement s'il reste >= 2 mots."""
    matches = list(re.finditer(r"\S+", raw))
    while matches:
        last = matches[-1].group(0)
        if is_safe_word(last):
            matches.pop()
        elif len(matches) >= 3 and is_trailing_city(last):
            matches.pop()
        else:
            break
    if not matches:
        return ""
    return raw[: matches[-1].end()]


def _civility_to_gender(civility: str) -> CivilityGender | None:
    low = civility.lower()
    if low in _MASC_CIVILITIES:
        return "M"
    if low in _FEM_CIVILITIES:
        return "F"
    return None


def detect_deterministic(text: str) -> list[DetectedSpan]:
    """Détecte les entités structurées FR (validées par clé de contrôle) et civilités."""
    spans: list[DetectedSpan] = []

    for m in _IBAN_RE.finditer(text):
        if is_valid_iban(m.group(0)):
            spans.append(DetectedSpan(start=m.start(), end=m.end(), text=m.group(0), kind=EntityKind.IBAN, source="regex+mod97"))

    for m in _EMAIL_RE.finditer(text):
        spans.append(DetectedSpan(start=m.start(), end=m.end(), text=m.group(0), kind=EntityKind.EMAIL, source="regex"))

    for m in _NIR_RE.finditer(text):
        if is_valid_nir(m.group(0)):
            spans.append(DetectedSpan(start=m.start(), end=m.end(), text=m.group(0), kind=EntityKind.NIR, source="regex+nir97"))

    for m in _SIRET_RE.finditer(text):
        if is_valid_siret(m.group(0)):
            spans.append(DetectedSpan(start=m.start(), end=m.end(), text=m.group(0), kind=EntityKind.SIRET, source="regex+luhn"))

    for m in _PHONE_RE.finditer(text):
        if is_valid_french_phone(m.group(0)):
            spans.append(DetectedSpan(start=m.start(), end=m.end(), text=m.group(0), kind=EntityKind.PHONE, source="regex+fr"))

    for m in _SIREN_CONTEXT_RE.finditer(text):
        val = m.group(1)
        if is_valid_siren(val):
            spans.append(DetectedSpan(start=m.start(1), end=m.end(1), text=val, kind=EntityKind.SIREN, source="context+luhn"))

    for m in _CIVILITY_PERSON_RE.finditer(text):
        candidate = _trim_person_candidate(m.group(2))
        if len(candidate) >= 3 and not all(is_safe_word(w) for w in candidate.split()):
            start = m.start(2)
            end = start + len(candidate)
            spans.append(
                DetectedSpan(
                    start=start,
                    end=end,
                    text=text[start:end],
                    kind=EntityKind.PERSON,
                    source="civility",
                    civility_gender=_civility_to_gender(m.group(1)),
                )
            )

    return spans


def detect_known_persons(
    text: str,
    vault: PiiVault,
    extra_persons: Iterable[str] = (),
) -> list[DetectedSpan]:
    """Détecte les personnes déjà connues du coffre (noms complets + patronymes non ambigus)."""
    keys: set[str] = set()
    person_prefix = f"{EntityKind.PERSON.value}:"
    for entity_key in vault.entity_to_token:
        if entity_key.startswith(person_prefix):
            name = entity_key.removeprefix(person_prefix)
            if len(name) >= 3 and not is_safe_word(name):
                # Ne pas auto-chaîner un patronyme isolé déjà marqué ambigu (ex. SCI DUPONT)
                if " " not in name and vault.surname_to_token.get(name) == AMBIGUOUS_SURNAME:
                    continue
                keys.add(name)

    for surname, tok in vault.surname_to_token.items():
        if tok != AMBIGUOUS_SURNAME and len(surname) >= 3 and not is_safe_word(surname):
            keys.add(surname)

    for extra in extra_persons:
        folded = fold_text(extra)
        if len(folded) >= 3 and not is_safe_word(folded):
            keys.add(folded)

    if not keys:
        return []

    folded_doc = fold_with_map(text)
    if not folded_doc.folded:
        return []

    spans: list[DetectedSpan] = []
    for key in sorted(keys, key=len, reverse=True):
        is_single_word = " " not in key
        pattern = re.compile(_BORNE_AVANT + re.escape(key) + _BORNE_APRES)
        for m in pattern.finditer(folded_doc.folded):
            orig_start = folded_doc.starts[m.start()]
            orig_end = folded_doc.ends[m.end() - 1]
            orig_slice = text[orig_start:orig_end]
            # Un patronyme isolé (ex. Petit, Blanc, Roux, Marchand) n'est rattaché que s'il porte
            # une majuscule initiale ou est en capitales : évite de masquer « petit matériel ».
            if is_single_word and not orig_slice[0].isupper():
                continue
            spans.append(
                DetectedSpan(
                    start=orig_start,
                    end=orig_end,
                    text=orig_slice,
                    kind=EntityKind.PERSON,
                    source="vault_link",
                )
            )
    return spans


def resolve_overlaps(text: str, spans: Sequence[DetectedSpan]) -> list[DetectedSpan]:
    """Résout les chevauchements de façon déterministe et ignore les jetons déjà présents."""
    token_ranges = [(m.start(), m.end()) for m in _TOKEN_RE.finditer(text)]

    def _inside_token(s: DetectedSpan) -> bool:
        return any(s.start < t_end and s.end > t_start for t_start, t_end in token_ranges)

    candidates = [s for s in spans if 0 <= s.start < s.end <= len(text) and not _inside_token(s)]
    # Priorité : type structuré fort > longueur décroissante > source civilité > position croissante
    candidates.sort(
        key=lambda s: (-_KIND_PRIORITY[s.kind], -(s.end - s.start), 0 if s.source == "civility" else 1, s.start)
    )

    selected: list[DetectedSpan] = []
    for cand in candidates:
        if any(cand.start < kept.end and cand.end > kept.start for kept in selected):
            continue
        selected.append(cand)

    selected.sort(key=lambda s: s.start)
    return selected
