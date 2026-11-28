"""Tests property-based (hypothesis) des invariants du PiiVault (export -> reload -> enrich -> restore)."""

from __future__ import annotations

import json
from pathlib import Path

from hypothesis import given, settings, strategies as st

from symbolon.scrubber import rehydrate
from symbolon.vault import AMBIGUOUS_SURNAME, EntityKind, PiiVault

_FIRST_NAMES = st.sampled_from(["Pierre", "Marie", "Jean", "Claire", "Lucas", "Sophie", "Henri"])
_LAST_NAMES = st.sampled_from(["Dupont", "Martin", "Bernard", "Moreau", "Laurent", "Garnier"])

_EVENT_STRATEGY = st.one_of(
    st.tuples(st.just(EntityKind.PERSON), st.builds(lambda f, l: f"{f} {l}", _FIRST_NAMES, _LAST_NAMES)),
    st.tuples(st.just(EntityKind.PERSON), _LAST_NAMES),
    st.tuples(st.just(EntityKind.IBAN), st.from_regex(r"FR763000600001[0-9]{11}89", fullmatch=True)),
    st.tuples(st.just(EntityKind.EMAIL), st.from_regex(r"[a-z]{3,8}@exemple\.fr", fullmatch=True)),
    st.tuples(st.just(EntityKind.PHONE), st.from_regex(r"06 [0-9]{2} [0-9]{2} [0-9]{2} [0-9]{2}", fullmatch=True)),
    st.tuples(st.just(EntityKind.SIREN), st.from_regex(r"[1-9][0-9]{8}", fullmatch=True)),
    st.tuples(st.just(EntityKind.SIRET), st.from_regex(r"[1-9][0-9]{13}", fullmatch=True)),
    st.tuples(st.just(EntityKind.NIR), st.from_regex(r"1850575112[0-9]{5}", fullmatch=True)),
)


@settings(max_examples=80, deadline=None)
@given(
    before=st.lists(_EVENT_STRATEGY, min_size=1, max_size=20),
    after=st.lists(_EVENT_STRATEGY, min_size=1, max_size=20),
)
def test_property_export_reload_enrich_sans_collision_ni_perte(
    before: list[tuple[EntityKind, str]],
    after: list[tuple[EntityKind, str]],
) -> None:
    """Invariant fondamental : aucun jeton ne peut être écrasé après rechargement du coffre."""
    vault = PiiVault()
    non_person_mapping: dict[str, str] = {}

    for kind, entity in before:
        tok = vault.get_or_create_token(entity, kind)
        if kind is not EntityKind.PERSON:
            if tok in non_person_mapping:
                assert non_person_mapping[tok] == entity
            else:
                non_person_mapping[tok] = entity

    ambiguous_before = {k for k, v in vault.surname_to_token.items() if v == AMBIGUOUS_SURNAME}
    counters_before = dict(vault.counters)

    # Roundtrip JSON complet
    raw_json = json.dumps(vault.to_dict())
    reloaded = PiiVault.from_dict(json.loads(raw_json))

    assert reloaded.counters == counters_before
    ambiguous_after = {k for k, v in reloaded.surname_to_token.items() if v == AMBIGUOUS_SURNAME}
    assert ambiguous_after == ambiguous_before

    # Enrichissement après rechargement : jamais d'écrasement ni régression d'ambiguïté
    for kind, entity in after:
        tok = reloaded.get_or_create_token(entity, kind)
        if kind is not EntityKind.PERSON:
            if tok in non_person_mapping:
                assert non_person_mapping[tok] == entity
            else:
                non_person_mapping[tok] = entity
        assert rehydrate(f"val={tok}", reloaded) == f"val={reloaded.token_to_entity[tok]}"

    # Tous les jetons d'avant rechargement restent intacts et réhydratables
    for tok, entity in non_person_mapping.items():
        assert reloaded.token_to_entity[tok] == entity
        assert rehydrate(tok, reloaded) == entity


def test_persistance_atomique_et_permissions_disque(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    v = PiiVault()
    t1 = v.get_or_create_token("Pierre Dupont", EntityKind.PERSON)
    t2 = v.get_or_create_token("Marie Dupont", EntityKind.PERSON)
    t_iban = v.get_or_create_token("FR7630006000011234567890189", EntityKind.IBAN)
    v.save(path)

    assert path.exists()
    assert (path.stat().st_mode & 0o777) == 0o600

    v2 = PiiVault.load(path)
    assert v2.surname_to_token["dupont"] == AMBIGUOUS_SURNAME
    t_dupont = v2.get_or_create_token("Dupont", EntityKind.PERSON)
    assert t_dupont not in (t1, t2)
    assert v2.get_or_create_token("FR7610011000201234567890188", EntityKind.IBAN) == "[IBAN_02]"
    assert v2.token_to_entity[t_iban] == "FR7630006000011234567890189"
