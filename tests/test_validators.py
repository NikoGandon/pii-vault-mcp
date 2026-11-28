"""Tests unitaires et property-based (hypothesis) des validateurs mathématiques FR/EU."""

from __future__ import annotations

from hypothesis import given, strategies as st

from symbolon.validators import (
    is_valid_french_phone,
    is_valid_iban,
    is_valid_luhn,
    is_valid_nir,
    is_valid_siren,
    is_valid_siret,
)


def _make_valid_fr_iban(bban_digits: str) -> str:
    """Construit un IBAN FR27 valide (clé mod-97 exacte) à partir de 23 chiffres BBAN."""
    rearranged = bban_digits + "FR00"
    rem = 0
    for ch in rearranged:
        if ch.isdigit():
            rem = (rem * 10 + int(ch)) % 97
        else:
            rem = (rem * 100 + (ord(ch) - ord("A") + 10)) % 97
    check = 98 - rem
    return f"FR{check:02d}{bban_digits}"


def _make_valid_luhn(prefix: str) -> str:
    """Calcule la clé de Luhn finale pour obtenir un numéro valide."""
    for d in range(10):
        cand = prefix + str(d)
        if is_valid_luhn(cand):
            return cand
    raise AssertionError("impossible")


def _make_valid_nir(sex: str, year: int, month: int, dept: str, commune: int, ordre: int) -> str:
    dept_num = "19" if dept == "2A" else "18" if dept == "2B" else dept
    base_int = int(f"{sex}{year:02d}{month:02d}{dept_num}{commune:03d}{ordre:03d}")
    key = 97 - (base_int % 97)
    return f"{sex}{year:02d}{month:02d}{dept}{commune:03d}{ordre:03d}{key:02d}"


def test_exemples_reels_valides_et_invalides() -> None:
    assert is_valid_iban("FR76 3000 6000 0112 3456 7890 189")
    assert not is_valid_iban("FR76 3000 6000 0112 3456 7890 188")  # mauvaise clé
    assert not is_valid_iban("FR76 3000 6000")  # trop court

    assert is_valid_siren("732 829 320")
    assert not is_valid_siren("732 829 321")
    assert not is_valid_siren("000000000")

    assert is_valid_siret("732 829 320 00074")
    assert not is_valid_siret("732 829 320 00075")
    # Exception La Poste (SIREN 356000000)
    assert is_valid_siret("35600000000048")

    # NIR métropole + Corse 2A/2B
    assert is_valid_nir(_make_valid_nir("1", 85, 5, "75", 112, 345))
    assert is_valid_nir(_make_valid_nir("2", 91, 11, "2A", 4, 12))
    assert is_valid_nir(_make_valid_nir("1", 78, 3, "2B", 33, 99))
    assert not is_valid_nir("1 85 05 75 112 345 00")  # clé 00 invalide

    assert is_valid_french_phone("06 12 34 56 78")
    assert is_valid_french_phone("+33 6 12 34 56 78")
    assert is_valid_french_phone("0033-1-42-68-55-00")
    assert not is_valid_french_phone("00 12 34 56 78")
    assert not is_valid_french_phone("06 12 34 56")


@given(st.from_regex(r"[0-9]{23}", fullmatch=True))
def test_property_iban_valide_et_mutation_rejetee(bban: str) -> None:
    iban = _make_valid_fr_iban(bban)
    assert is_valid_iban(iban)
    # Changer un seul chiffre dans le BBAN casse forcément mod-97
    mutated_digit = str((int(iban[-1]) + 1) % 10)
    assert not is_valid_iban(iban[:-1] + mutated_digit)


@given(st.from_regex(r"[1-9][0-9]{7}", fullmatch=True))
def test_property_siren_valide_et_mutation_rejetee(prefix8: str) -> None:
    siren = _make_valid_luhn(prefix8)
    assert is_valid_siren(siren)
    mutated = siren[:-1] + str((int(siren[-1]) + 1) % 10)
    assert not is_valid_siren(mutated)


@given(
    sex=st.sampled_from(["1", "2"]),
    year=st.integers(min_value=0, max_value=99),
    month=st.integers(min_value=1, max_value=12),
    dept=st.sampled_from(["01", "37", "75", "92", "2A", "2B"]),
    commune=st.integers(min_value=1, max_value=990),
    ordre=st.integers(min_value=1, max_value=999),
)
def test_property_nir_valide_et_cle_fausse_rejetee(
    sex: str, year: int, month: int, dept: str, commune: int, ordre: int
) -> None:
    nir = _make_valid_nir(sex, year, month, dept, commune, ordre)
    assert is_valid_nir(nir)
    bad_key = (int(nir[-2:]) % 97) + 1
    if bad_key == int(nir[-2:]):
        bad_key = (bad_key % 97) + 1
    assert not is_valid_nir(nir[:-2] + f"{bad_key:02d}")
