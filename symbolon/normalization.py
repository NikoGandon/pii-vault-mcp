"""Normalisation Unicode et table d'offsets pour les remplacements exacts."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_ESPACES = re.compile(r"\s+")

# Mots grammaticaux, civilités et termes génériques français qui ne sont jamais des noms propres.
SAFE_WORDS: frozenset[str] = frozenset(
    {
        "a", "au", "aux", "avec", "chez", "dans", "de", "des", "du", "d", "en", "et", "l", "la",
        "le", "les", "non", "ou", "par", "pas", "plus", "pour", "sans", "sous", "sur", "un", "une",
        "m", "mr", "mme", "mlle", "dr", "me", "monsieur", "madame", "mademoiselle", "docteur",
        "maitre", "famille", "client", "clients", "fournisseur", "fournisseurs", "salarie",
        "salaries", "associe", "associes", "gerant", "directeur", "direction", "service",
        "services", "facture", "factures", "contrat", "contrats", "dossier", "dossiers", "compte",
        "virement", "prelevement", "loyer", "loyers", "salaire", "salaires", "honoraires",
        "mission", "audit", "conseil", "banque", "assurance", "assurances", "hotel", "restaurant",
        "bistrot", "brasserie", "cafe", "garage", "cabinet", "atelier", "bureau", "ecole",
        "institut", "clinique", "laboratoire", "societe", "entreprise", "groupe", "holding",
        "sarl", "sas", "sasu", "eurl", "sci", "snc", "selarl", "scp", "sa", "ets", "ste",
        "janvier", "fevrier", "mars", "avril", "mai", "juin", "juillet", "aout", "septembre",
        "octobre", "novembre", "decembre", "lundi", "mardi", "mercredi", "jeudi", "vendredi",
        "samedi", "dimanche",
        # Libellés de champs documentaires susceptibles de suivre un nom avec une majuscule
        "tel", "telephone", "fax", "mobile", "portable", "email", "mail", "courriel",
        "iban", "bic", "rib", "siren", "siret", "nir", "prix", "montant", "total",
        "objet", "date", "adresse", "contact", "reference", "ref", "cession", "cedant",
        "cessionnaire", "acquereur", "vendeur", "acheteur", "signataire", "siege",
    }
)

# Villes françaises / pays retirés uniquement en 3e position (prénom + nom déjà présents)
# afin de préserver les patronymes homonymes (ex. « M. Gaston Paris », « Mme Claire Lyon »).
TRAILING_CITY_WORDS: frozenset[str] = frozenset(
    {
        "paris", "lyon", "marseille", "toulouse", "nice", "nantes", "montpellier",
        "strasbourg", "bordeaux", "lille", "rennes", "reims", "tours", "grenoble",
        "dijon", "angers", "nimes", "toulon", "rouen", "nancy", "metz", "orleans",
        "caen", "brest", "avignon", "amiens", "limoges", "besancon", "france", "europe",
    }
)


def strip_accents(text: str) -> str:
    """Supprime les diacritiques Unicode (NFD) pour les comparaisons insensibles aux accents."""
    return "".join(
        ch for ch in unicodedata.normalize("NFD", text) if unicodedata.category(ch) != "Mn"
    )


def fold_text(text: str) -> str:
    """Clé canonique : sans accents, minuscules, espaces compactés."""
    return _ESPACES.sub(" ", strip_accents(text).lower()).strip()


def is_safe_word(word: str) -> bool:
    """Vrai si le mot est un mot-outil ou terme générique ne pouvant être un patronyme."""
    folded = fold_text(word)
    return folded in SAFE_WORDS or (folded.endswith("s") and folded[:-1] in SAFE_WORDS)


def is_trailing_city(word: str) -> bool:
    """Vrai si le mot est une ville française/pays susceptible de suivre un nom complet."""
    return fold_text(word) in TRAILING_CITY_WORDS


@dataclass(frozen=True)
class FoldedText:
    """Texte plié (minuscules sans diacritiques) avec correspondance vers les indices d'origine."""

    folded: str
    starts: tuple[int, ...]
    ends: tuple[int, ...]


def fold_with_map(text: str) -> FoldedText:
    """Plie `text` en conservant la borne [debut, fin) d'origine de chaque caractère plié."""
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    i = 0
    n = len(text)
    while i < n:
        j = i + 1
        while j < n and unicodedata.category(text[j]) == "Mn":
            j += 1
        for d in unicodedata.normalize("NFD", text[i:j]):
            if unicodedata.category(d) == "Mn":
                continue
            for low in d.lower():
                out.append(low)
                starts.append(i)
                ends.append(j)
        i = j
    return FoldedText("".join(out), tuple(starts), tuple(ends))
