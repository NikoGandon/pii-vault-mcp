"""Validateurs mathématiques déterministes pour identifiants français et européens.

Évite les faux positifs sur des suites de chiffres aléatoires (numéros de facture,
références internes, montants) en exigeant la validité de la clé de contrôle.
"""

from __future__ import annotations

import re

_NON_ALNUM = re.compile(r"[\s.\-]+")

# Longueurs IBAN officielles ISO 13616 (principaux pays européens + FR/MC/DOM-TOM)
_IBAN_LENGTHS: dict[str, int] = {
    "AT": 20, "BE": 16, "CH": 21, "DE": 22, "ES": 24, "FR": 27,
    "GB": 22, "IE": 22, "IT": 27, "LU": 20, "MC": 27, "NL": 18,
    "PT": 25,
}


def compact_id(value: str) -> str:
    """Retire espaces, points et tirets et passe en majuscules."""
    return _NON_ALNUM.sub("", value).upper()


def is_valid_iban(value: str) -> bool:
    """Valide un IBAN selon ISO 13616 (longueur par pays si connue + contrôle mod-97 == 1)."""
    code = compact_id(value)
    if len(code) < 15 or len(code) > 34 or not code.isalnum():
        return False
    country = code[:2]
    if not country.isalpha() or not code[2:4].isdigit():
        return False
    expected_len = _IBAN_LENGTHS.get(country)
    if expected_len is not None and len(code) != expected_len:
        return False
    rearranged = code[4:] + code[:4]
    remainder = 0
    for ch in rearranged:
        if ch.isdigit():
            remainder = (remainder * 10 + int(ch)) % 97
        else:
            num = ord(ch) - ord("A") + 10
            remainder = (remainder * 100 + num) % 97
    return remainder == 1


def is_valid_luhn(digits: str) -> bool:
    """Algorithme de Luhn standard sur une chaîne composée uniquement de chiffres."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for idx, ch in enumerate(digits):
        d = int(ch)
        if idx % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def is_valid_siren(value: str) -> bool:
    """Valide un numéro SIREN français (9 chiffres + clé de Luhn, non nul)."""
    digits = compact_id(value)
    if len(digits) != 9 or not digits.isdigit() or digits == "000000000":
        return False
    return is_valid_luhn(digits)


def is_valid_siret(value: str) -> bool:
    """Valide un numéro SIRET français (14 chiffres : SIREN valide + Luhn complet ou règle La Poste)."""
    digits = compact_id(value)
    if len(digits) != 14 or not digits.isdigit():
        return False
    if not is_valid_siren(digits[:9]):
        return False
    if is_valid_luhn(digits):
        return True
    # Exception historique La Poste (SIREN 356000000) : somme simple des chiffres multiple de 5
    if digits[:9] == "356000000":
        return sum(int(d) for d in digits) % 5 == 0
    return False


def is_valid_nir(value: str) -> bool:
    """Valide un NIR (numéro de Sécurité sociale français, 15 caractères, Corse 2A/2B incluse).

    Structure : sexe (1/2/3/4/7/8) + année (2) + mois (01-12, 20, 30-42, 50-99)
    + département (01-95, 2A, 2B, 96-99) + commune (3) + ordre (3) + clé (2 = 97 - n % 97).
    """
    code = compact_id(value)
    if len(code) != 15:
        return False
    if code[0] not in ("1", "2", "3", "4", "7", "8"):
        return False
    if not (code[1:5].isdigit() and code[7:15].isdigit()):
        return False
    month = int(code[3:5])
    if not (1 <= month <= 12 or month == 20 or 30 <= month <= 42 or 50 <= month <= 99):
        return False
    dept = code[5:7]
    if dept == "2A":
        base_str = code[:5] + "19" + code[7:13]
    elif dept == "2B":
        base_str = code[:5] + "18" + code[7:13]
    elif dept.isdigit() and dept != "00":
        base_str = code[:13]
    else:
        return False
    key = int(code[13:15])
    if not (1 <= key <= 97):
        return False
    expected_key = 97 - (int(base_str) % 97)
    return key == expected_key


def is_valid_french_phone(value: str) -> bool:
    """Valide un numéro de téléphone français (format national 0[1-9] ou international +33/0033)."""
    cleaned = _NON_ALNUM.sub("", value)
    if cleaned.startswith("+33"):
        rest = cleaned[3:]
    elif cleaned.startswith("0033"):
        rest = cleaned[4:]
    elif cleaned.startswith("0"):
        rest = cleaned[1:]
    else:
        return False
    return len(rest) == 9 and rest.isdigit() and rest[0] in "123456789"
