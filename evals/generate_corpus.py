"""Générateur déterministe du corpus synthétique de non-régression (evals/corpus_fr.jsonl).

Ce corpus synthétique vérifie les invariants et la non-régression des détecteurs FR
(clés de contrôle valides/invalides, téléphones compacts, montants financiers Luhn,
homonymes, noms composés accentués et frontière déterministe vs NER).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from pii_vault.validators import (  # noqa: E402
    is_valid_iban,
    is_valid_luhn,
    is_valid_nir,
    is_valid_siren,
    is_valid_siret,
)


def make_iban(bban: str) -> str:
    rearr = bban + "FR00"
    rem = 0
    for ch in rearr:
        rem = (rem * 10 + int(ch)) % 97 if ch.isdigit() else (rem * 100 + (ord(ch) - ord("A") + 10)) % 97
    raw = f"FR{98 - rem:02d}{bban}"
    assert is_valid_iban(raw)
    return " ".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def make_luhn(prefix: str) -> str:
    for d in range(10):
        cand = prefix + str(d)
        if is_valid_luhn(cand):
            return cand
    raise AssertionError("impossible")


def make_siren(prefix8: str) -> str:
    raw = make_luhn(prefix8)
    assert is_valid_siren(raw)
    return f"{raw[:3]} {raw[3:6]} {raw[6:]}"


def make_siret(siren_digits: str, nic4: str) -> str:
    raw = make_luhn(siren_digits + nic4)
    assert is_valid_siret(raw)
    return f"{raw[:3]} {raw[3:6]} {raw[6:9]} {raw[9:]}"


def make_nir(sex: str, year: int, month: int, dept: str, commune: int, ordre: int) -> str:
    dnum = "19" if dept == "2A" else "18" if dept == "2B" else dept
    base = int(f"{sex}{year:02d}{month:02d}{dnum}{commune:03d}{ordre:03d}")
    key = 97 - (base % 97)
    fmt = f"{sex} {year:02d} {month:02d} {dept} {commune:03d} {ordre:03d} {key:02d}"
    assert is_valid_nir(fmt)
    return fmt


def generate_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    cid = 0

    def add(
        cat: str,
        text: str,
        entities: list[tuple[str, str]],
        is_trap: bool = False,
        known_persons: list[str] | None = None,
    ) -> None:
        nonlocal cid
        cid += 1
        row: dict[str, object] = {
            "id": f"fr_{cid:03d}",
            "category": cat,
            "is_trap": is_trap,
            "text": text,
            "entities": [{"kind": k, "text": v} for k, v in entities],
        }
        if known_persons:
            row["known_persons"] = known_persons
        cases.append(row)

    ibans = [make_iban(f"30006000011234567890{i:03d}") for i in range(100, 110)]
    names_civ = [
        ("M.", "Pierre Dupont"), ("Mme", "Claire Martin"), ("M.", "Jean-Luc Moreau"),
        ("Mme", "Éléonore Lefèvre"), ("Dr", "Antoine Bernard"), ("Me", "Sophie Garnier"),
        ("Monsieur", "Henri Laurent"), ("Madame", "Camille Girard"), ("M.", "Thomas Mercier"),
        ("Mme", "Nathalie Petit"),
    ]

    # 1. Dossiers bancaires / IBAN + personnes + contacts (10 cas, mix formats tél)
    for i in range(10):
        civ, full = names_civ[i]
        surname = full.split()[-1].upper()
        mail = f"contact{i+1}@cabinet-test.fr"
        tel = f"061{i}2{i}3{i}4{i}" if i % 2 == 0 else f"+33 6 1{i} 2{i} 3{i} 4{i}"
        add(
            "banque_ma",
            f"Virement LOYER SCI {surname} autorisé par {civ} {full} ({mail}, {tel}) vers {ibans[i]}.",
            [("PERSONNE", surname), ("PERSONNE", full), ("EMAIL", mail), ("TEL", tel), ("IBAN", ibans[i])],
        )

    # 2. Dossiers RH / NIR (métropole + Corse 2A/2B) + téléphone national (10 cas)
    nirs = [
        make_nir("1", 85, 5, "75", 112, 345),
        make_nir("2", 91, 11, "2A", 4, 12),
        make_nir("1", 78, 3, "2B", 33, 99),
        make_nir("2", 94, 8, "37", 261, 108),
        make_nir("1", 82, 12, "69", 123, 456),
        make_nir("2", 89, 1, "33", 63, 210),
        make_nir("1", 75, 7, "13", 55, 777),
        make_nir("2", 97, 4, "44", 109, 25),
        make_nir("1", 88, 9, "59", 350, 612),
        make_nir("2", 90, 2, "31", 555, 801),
    ]
    for i in range(10):
        civ, full = names_civ[i]
        tel = f"01426855{i:02d}" if i % 3 == 0 else f"06 {10+i} {20+i} {30+i} {40+i}"
        add(
            "rh_paie",
            f"Fiche salarié : {civ} {full}, NIR {nirs[i]}, joignable au {tel}.",
            [("PERSONNE", full), ("NIR", nirs[i]), ("TEL", tel)],
        )

    # 3. Contrats & factures B2B : SIREN / SIRET valides + emails (10 cas)
    for i in range(10):
        siren_fmt = make_siren(f"7328293{i}")
        siren_raw = siren_fmt.replace(" ", "")
        siret_fmt = make_siret(siren_raw, f"000{i}")
        mail = f"facturation{i}@fournisseur-b2b.fr"
        add(
            "contrat_b2b",
            f"Contrat prestataire SIREN {siren_fmt} (établissement SIRET {siret_fmt}), contact : {mail}.",
            [("SIREN", siren_fmt), ("SIRET", siret_fmt), ("EMAIL", mail)],
        )

    # 4. Homonymes, civilités contradictoires et chaînage multi-mentions (6 cas)
    add(
        "homonymes",
        "Litige entre M. Pierre Dupont et Mme Marie Dupont ; courrier signé M. Dupont.",
        [("PERSONNE", "Pierre Dupont"), ("PERSONNE", "Marie Dupont"), ("PERSONNE", "Dupont")],
    )
    add(
        "homonymes",
        "M. Dupont et Mme Marie Dupont ont paraphé l'avenant de cession.",
        [("PERSONNE", "Dupont"), ("PERSONNE", "Marie Dupont")],
    )
    add(
        "homonymes",
        "Cession entre Mme Alice Martin et M. Paul Martin ; virement Martin reçu.",
        [("PERSONNE", "Alice Martin"), ("PERSONNE", "Paul Martin"), ("PERSONNE", "Martin")],
        known_persons=["Martin"],
    )
    add(
        "chainage_inverse",
        "Note de frais NDF_GARNIER réglée après accord de Me Sophie Garnier.",
        [("PERSONNE", "GARNIER"), ("PERSONNE", "Sophie Garnier")],
    )
    add(
        "chainage_unicode",
        "Relance LEFEVRE-DUMONT suite au rendez-vous avec Mme Éléonore Lefèvre-Dumont.",
        [("PERSONNE", "LEFEVRE-DUMONT"), ("PERSONNE", "Éléonore Lefèvre-Dumont")],
    )
    add(
        "multi_identifiants",
        f"Audit de M. Lucas Chevalier, tel 0755443322, mail l.chevalier@banque.fr, IBAN {ibans[0]}, NIR {nirs[0]}.",
        [
            ("PERSONNE", "Lucas Chevalier"),
            ("TEL", "0755443322"),
            ("EMAIL", "l.chevalier@banque.fr"),
            ("IBAN", ibans[0]),
            ("NIR", nirs[0]),
        ],
    )

    add(
        "homonymes_mots_courants",
        "M. Paul Marchand contrôle le stock de marchandises avant livraison.",
        [("PERSONNE", "Paul Marchand")],
    )
    add(
        "homonymes_mots_courants",
        "Mme Claire Petit valide l'achat de petit matériel ; relance PETIT envoyée.",
        [("PERSONNE", "Claire Petit"), ("PERSONNE", "PETIT")],
    )
    add(
        "homonymes_mots_courants",
        "M. Jean Martin organise la mission en Martinique sans incident.",
        [("PERSONNE", "Jean Martin")],
    )
    add(
        "retour_ligne_et_ville",
        (
            "Cession SCI DUPONT\n"
            "Cédant : M. Pierre Dupont\n"
            "Tél : 0612345678\n"
            f"IBAN : {ibans[0]}\n"
            "Prix : 125 000 000 EUR"
        ),
        [("PERSONNE", "DUPONT"), ("PERSONNE", "Pierre Dupont"), ("TEL", "0612345678"), ("IBAN", ibans[0])],
    )
    add(
        "retour_ligne_et_ville",
        "Rendez-vous avec Mme Claire Martin Paris pour la signature.",
        [("PERSONNE", "Claire Martin")],
    )

    # 5. Cas limites honnêtes : noms nus SANS civilité (frontière déterministe vs GLiNER) (5 cas)
    add("nom_nu_sans_ner", "Déjeuner de travail avec Julien Delacroix pour préparer la levée de fonds.", [("PERSONNE", "Julien Delacroix")])
    add("nom_nu_sans_ner", "Appeler Camille Rousseau demain matin au 0688776655.", [("PERSONNE", "Camille Rousseau"), ("TEL", "0688776655")])
    add("nom_nu_sans_ner", "Dossier transmis par Marc-Antoine Vasseur (m.vasseur@cabinet.fr).", [("PERSONNE", "Marc-Antoine Vasseur"), ("EMAIL", "m.vasseur@cabinet.fr")])
    add("nom_nu_sans_ner", "Validation orale de Bastien Lefort sur le budget Q4.", [("PERSONNE", "Bastien Lefort")])
    add("nom_nu_sans_ner", "Signature électronique de Pauline Marchand reçue ce jour.", [("PERSONNE", "Pauline Marchand")])

    # 6. Pièges négatifs (25 cas : 0 entité à masquer -> montants Luhn, faux IDs, enseignes)
    traps = [
        "Prix de cession : 125 000 000 EUR payable au closing.",
        "Valorisation retenue : 400 000 000 € hors trésorerie nette.",
        "Chiffre d'affaires consolidé de 732 829 320 EUR en hausse de 12 %.",
        "Budget CAPEX pluriannuel : 100 000 009 EUR validé en comité.",
        "Ligne de crédit syndiquée de 250 000 006 EUR sur 5 ans.",
        "Déjeuner Chez Michel puis dîner Bistrot Paul pour l'équipe commerciale.",
        "Billet SNCF Paris-Tours 84,50 EUR et abonnement EDF mensuel.",
        "Facture Kiloutou matériel de chantier et assurance AXA professionnelle.",
        "Achat montre Rolex et séjour Club Med séminaire annuel.",
        "Dîner Fouquet's Champs-Élysées et frais École Alsacienne.",
        "Faux IBAN à mauvaise clé : FR76 3000 6000 0112 3456 7890 188.",
        "Faux IBAN tronqué : FR76 3000 6000 0112 3456.",
        "Faux SIREN à clé Luhn invalide : SIREN 732 829 321.",
        "Faux SIREN nul : SIREN 000 000 000.",
        "Faux SIRET à clé Luhn invalide : 732 829 320 00075.",
        "Faux NIR à clé 97 invalide : 1 85 05 75 112 345 00.",
        "Faux NIR mois 15 inexistant : 1 85 15 75 112 345 12.",
        "Faux téléphone préfixe 00 : 0012345678 et 00 12 34 56 78.",
        "Numéro de commande interne CMD-2026-481920384 sans donnée personnelle.",
        "Facture Microsoft Azure Cloud et licences GitHub Enterprise.",
        "Location véhicule Hertz aéroport Orly et péage Vinci Autoroutes.",
        "Commande fournitures Amazon Business et café Starbucks.",
        "Montant total 125 480,00 EUR HT, TVA 20 %, référence 984 120 331.",
        "Virement interne compte 512000 vers compte 455000 exercice 2026.",
        "Note de frais hôtel Mercure et taxi G7 déplacement Lyon.",
    ]
    for t in traps:
        add("piege_negatif", t, [], is_trap=True)

    return cases


def main() -> int:
    cases = generate_cases()
    out_path = Path(__file__).parent / "corpus_fr.jsonl"
    out_path.write_text("\n".join(json.dumps(c, ensure_ascii=False) for c in cases) + "\n", encoding="utf-8")
    print(f"Généré {len(cases)} cas dans {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
