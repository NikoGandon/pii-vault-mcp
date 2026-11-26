"""Coffre réversible de pseudonymisation RGPD (Art. 4(5)) à persistance atomique.

Remarque juridique : une pseudonymisation réversible reste une donnée à caractère personnel
au sens du RGPD (Article 4(5)). Le coffre doit rester strictement local ; seul le texte
pseudonymisé quitte la machine vers un LLM tiers.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from pii_vault.normalization import fold_text, is_safe_word

AMBIGUOUS_SURNAME = "__AMBIGUOUS__"
_TOKEN_INDEX_RE = re.compile(r"^\[([A-Z]+)_(\d+)\]$")
_WORD_SPLIT_RE = re.compile(r"[\s_]+")

CivilityGender = Literal["M", "F"]


class EntityKind(StrEnum):
    PERSON = "PERSONNE"
    IBAN = "IBAN"
    NIR = "NIR"
    SIREN = "SIREN"
    SIRET = "SIRET"
    EMAIL = "EMAIL"
    PHONE = "TEL"


class VaultSnapshot(BaseModel):
    """Instantané immuable et strictement validé d'un PiiVault (sérialisation JSON)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = 1
    token_to_entity: dict[str, str] = Field(default_factory=dict)
    entity_to_token: dict[str, str] = Field(default_factory=dict)
    surname_to_token: dict[str, str] = Field(default_factory=dict)
    token_gender: dict[str, CivilityGender] = Field(default_factory=dict)
    counters: dict[str, int] = Field(default_factory=dict)


def _significant_person_words(folded_name: str) -> list[str]:
    return [w for w in _WORD_SPLIT_RE.split(folded_name) if len(w) >= 3 and not is_safe_word(w)]


class PiiVault:
    """Coffre réversible stockant les associations entité <-> jeton avec chaînage patronymique.

    Invariants garantis :
    - Aucun jeton déjà attribué n'est jamais écrasé par une nouvelle entité, y compris après
      export JSON -> rechargement -> enrichissement.
    - Si 'Pierre Dupont' est enregistré comme [PERSONNE_01], une occurrence isolée 'Dupont'
      (ex. 'SCI DUPONT') reçoit le même jeton [PERSONNE_01], sauf contradiction de civilité
      (ex. 'M. Dupont' vs 'Mme Marie Dupont').
    - Dès qu'un homonyme est détecté, le patronyme passe à __AMBIGUOUS__ : une occurrence
      isolée ultérieure reçoit un jeton distinct plutôt que d'être rattachée à tort.
    """

    def __init__(self) -> None:
        self.token_to_entity: dict[str, str] = {}
        self.entity_to_token: dict[str, str] = {}
        self.surname_to_token: dict[str, str] = {}
        self.token_gender: dict[str, CivilityGender] = {}
        self.counters: dict[EntityKind, int] = {kind: 0 for kind in EntityKind}

    def get_or_create_token(
        self,
        entity: str,
        kind: EntityKind,
        civility_gender: CivilityGender | None = None,
    ) -> str:
        clean = entity.strip()
        key = fold_text(clean)
        if not key:
            return clean

        lookup_key = f"{kind.value}:{key}"
        if lookup_key in self.entity_to_token:
            existing_tok = self.entity_to_token[lookup_key]
            if kind is EntityKind.PERSON:
                words = _significant_person_words(key)
                # Patronyme isolé devenu ambigu : ne jamais le rattacher silencieusement à un seul porteur
                if len(words) == 1 and self.surname_to_token.get(words[0]) == AMBIGUOUS_SURNAME:
                    if not (
                        civility_gender is not None
                        and self.token_gender.get(existing_tok) == civility_gender
                    ):
                        return self._allocate_distinct_person(clean, key, civility_gender)
                if (
                    civility_gender is not None
                    and existing_tok in self.token_gender
                    and self.token_gender[existing_tok] != civility_gender
                ):
                    return self._allocate_distinct_person(clean, key, civility_gender)
                if civility_gender is not None and existing_tok not in self.token_gender:
                    self.token_gender[existing_tok] = civility_gender
            return existing_tok

        if kind is EntityKind.PERSON:
            token = self._resolve_or_allocate_person(clean, key, civility_gender)
            self.entity_to_token.setdefault(lookup_key, token)
            return token

        self.counters[kind] += 1
        token = f"[{kind.value}_{self.counters[kind]:02d}]"
        self.token_to_entity[token] = clean
        self.entity_to_token[lookup_key] = token
        return token

    def _gender_conflicts(self, token: str, civility_gender: CivilityGender | None) -> bool:
        if civility_gender is None:
            return False
        existing_gender = self.token_gender.get(token)
        return existing_gender is not None and existing_gender != civility_gender

    def _allocate_distinct_person(
        self,
        clean: str,
        key: str,
        civility_gender: CivilityGender | None,
    ) -> str:
        words = _significant_person_words(key)
        self.counters[EntityKind.PERSON] += 1
        token = f"[{EntityKind.PERSON.value}_{self.counters[EntityKind.PERSON]:02d}]"
        self.token_to_entity[token] = clean
        if civility_gender is not None:
            self.token_gender[token] = civility_gender
        if words:
            surname = words[-1]
            prev = self.surname_to_token.get(surname)
            if prev is not None and prev != token:
                self.surname_to_token[surname] = AMBIGUOUS_SURNAME
            else:
                self.surname_to_token[surname] = token
        return token

    def _resolve_or_allocate_person(
        self,
        clean: str,
        key: str,
        civility_gender: CivilityGender | None,
    ) -> str:
        words = _significant_person_words(key)
        # 1) Patronyme isolé : rattacher uniquement si porteur unique ET pas de conflit de civilité
        if len(words) == 1:
            surname = words[0]
            existing = self.surname_to_token.get(surname)
            if existing is not None and existing != AMBIGUOUS_SURNAME:
                if not self._gender_conflicts(existing, civility_gender):
                    if civility_gender is not None and existing not in self.token_gender:
                        self.token_gender[existing] = civility_gender
                    return existing

        # 2) Nom complet : rattacher uniquement si le patronyme existait seul sans conflit de civilité
        elif len(words) >= 2:
            surname = words[-1]
            isolated_key = f"{EntityKind.PERSON.value}:{surname}"
            if isolated_key in self.entity_to_token:
                tok = self.entity_to_token[isolated_key]
                existing_display = self.token_to_entity.get(tok, "").strip()
                if (
                    " " not in existing_display
                    and self.surname_to_token.get(surname) != AMBIGUOUS_SURNAME
                    and not self._gender_conflicts(tok, civility_gender)
                ):
                    self.token_to_entity[tok] = clean
                    if civility_gender is not None:
                        self.token_gender[tok] = civility_gender
                    self.surname_to_token[surname] = tok
                    return tok

        return self._allocate_distinct_person(clean, key, civility_gender)

    def stats(self) -> dict[str, object]:
        """Métadonnées non sensibles du coffre (zéro PII brute exposée)."""
        ambiguous_count = sum(1 for v in self.surname_to_token.values() if v == AMBIGUOUS_SURNAME)
        return {
            "total_tokens": len(self.token_to_entity),
            "counters": {k.value: v for k, v in self.counters.items() if v > 0},
            "ambiguous_surnames_count": ambiguous_count,
        }

    def snapshot(self) -> VaultSnapshot:
        return VaultSnapshot(
            version=1,
            token_to_entity=dict(self.token_to_entity),
            entity_to_token=dict(self.entity_to_token),
            surname_to_token=dict(self.surname_to_token),
            token_gender=dict(self.token_gender),
            counters={k.value: v for k, v in self.counters.items()},
        )

    def to_dict(self) -> dict[str, object]:
        return self.snapshot().model_dump(mode="json")

    @classmethod
    def from_snapshot(cls, snap: VaultSnapshot) -> PiiVault:
        vault = cls()
        vault.token_to_entity = dict(snap.token_to_entity)
        vault.entity_to_token = dict(snap.entity_to_token)
        vault.surname_to_token = dict(snap.surname_to_token)
        vault.token_gender = dict(snap.token_gender)

        max_by_prefix: dict[str, int] = {}
        for tok in vault.token_to_entity:
            m = _TOKEN_INDEX_RE.match(tok)
            if m:
                prefix, num = m.group(1), int(m.group(2))
                if num > max_by_prefix.get(prefix, 0):
                    max_by_prefix[prefix] = num

        for kind in EntityKind:
            saved = int(snap.counters.get(kind.value, 0))
            observed = max_by_prefix.get(kind.value, 0)
            vault.counters[kind] = max(saved, observed)

        if not vault.surname_to_token:
            person_prefix = f"{EntityKind.PERSON.value}:"
            for k, tok in vault.entity_to_token.items():
                if not k.startswith(person_prefix):
                    continue
                words = _significant_person_words(k.removeprefix(person_prefix))
                if not words:
                    continue
                surname = words[-1]
                prev = vault.surname_to_token.get(surname)
                if prev is not None and prev != tok:
                    vault.surname_to_token[surname] = AMBIGUOUS_SURNAME
                else:
                    vault.surname_to_token[surname] = tok
        return vault

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> PiiVault:
        return cls.from_snapshot(VaultSnapshot.model_validate(data))

    def save(self, path: Path) -> None:
        """Écriture atomique sur disque (fichier temporaire + os.replace, permissions 0600)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp_name, path)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise

    @classmethod
    def load(cls, path: Path) -> PiiVault:
        data: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)
