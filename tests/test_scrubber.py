"""Tests du Scrubber FR : chaînage patronymique, homonymes, civilités, téléphones compacts, montants et anti-fuite."""

from __future__ import annotations

import pytest

from pii_vault.scrubber import PiiLeakError, Scrubber, assert_no_leak, rehydrate
from pii_vault.vault import PiiVault


def test_chainage_patronymique_independant_de_l_ordre() -> None:
    text = (
        "Virement LOYER SCI DUPONT de 2 400 EUR.\n"
        "Associé signataire : M. Pierre Dupont (contact : p.dupont@societe.fr, +33 6 12 34 56 78).\n"
        "IBAN : FR76 3000 6000 0112 3456 7890 189."
    )
    scrubber = Scrubber()
    res = scrubber.scrub(text)

    assert "Dupont" not in res.pseudonymized_text
    assert "DUPONT" not in res.pseudonymized_text
    assert "p.dupont@societe.fr" not in res.pseudonymized_text
    assert "FR76 3000 6000 0112 3456 7890 189" not in res.pseudonymized_text
    assert "LOYER SCI [PERSONNE_01]" in res.pseudonymized_text
    assert "M. [PERSONNE_01]" in res.pseudonymized_text
    assert "[EMAIL_01]" in res.pseudonymized_text
    assert "[TEL_01]" in res.pseudonymized_text
    assert "[IBAN_01]" in res.pseudonymized_text

    assert_no_leak([res.pseudonymized_text], scrubber.vault)


def test_telephone_compact_sans_espaces_detecte() -> None:
    text = "Contacter M. Pierre Dupont au 0612345678 ou fixe 0142685500."
    scrubber = Scrubber()
    res = scrubber.scrub(text)

    assert "0612345678" not in res.pseudonymized_text
    assert "0142685500" not in res.pseudonymized_text
    assert res.pseudonymized_text == "Contacter M. [PERSONNE_01] au [TEL_01] ou fixe [TEL_02]."


def test_montants_financiers_luhn_jamais_masques_en_siren() -> None:
    text = (
        "Prix de cession : 125 000 000 EUR. "
        "Valorisation retenue : 400 000 000 € (dette 100 000 009 EUR). "
        "Société immatriculée SIREN 732 829 320."
    )
    scrubber = Scrubber()
    res = scrubber.scrub(text)

    assert "125 000 000 EUR" in res.pseudonymized_text
    assert "400 000 000 €" in res.pseudonymized_text
    assert "100 000 009 EUR" in res.pseudonymized_text
    assert "SIREN [SIREN_01]." in res.pseudonymized_text
    assert res.replacements_count == 1


def test_homonymes_et_civilites_contradictoires_jamais_fusionnes() -> None:
    # 1) Deux prénoms distincts + occurrence isolée
    scrubber1 = Scrubber()
    r1 = scrubber1.scrub("Réunion entre M. Pierre Dupont et Mme Marie Dupont.\nNote signée M. Dupont.")
    assert "M. [PERSONNE_01] et Mme [PERSONNE_02]" in r1.pseudonymized_text
    assert "Note signée M. [PERSONNE_03]." in r1.pseudonymized_text

    # 2) Patronyme seul avec civilité masculine vs nom complet avec civilité féminine
    scrubber2 = Scrubber()
    r2 = scrubber2.scrub("M. Dupont et Mme Marie Dupont ont signé le pacte.")
    assert r2.pseudonymized_text == "M. [PERSONNE_02] et Mme [PERSONNE_01] ont signé le pacte."

    # 3) Quand le patronyme est ambigu, SCI DUPONT n'est pas rattaché à tort à M. Dupont
    scrubber3 = Scrubber()
    r3 = scrubber3.scrub("M. Dupont et Mme Marie Dupont ont signé le bail SCI DUPONT.")
    assert "M. [PERSONNE_02] et Mme [PERSONNE_01]" in r3.pseudonymized_text
    assert "SCI [PERSONNE_02]" not in r3.pseudonymized_text
    assert "SCI [PERSONNE_01]" not in r3.pseudonymized_text


def test_assert_no_leak_bloque_lettres_collees_sur_iban_et_epargne_mots_courants() -> None:
    vault = PiiVault()
    scrubber = Scrubber(vault=vault)
    scrubber.scrub("M. Pierre Dupont, IBAN FR76 3000 6000 0112 3456 7890 189.")

    with pytest.raises(PiiLeakError):
        assert_no_leak(["XFR76 3000 6000 0112 3456 7890 189X"], vault)


def test_patronymes_communs_ne_masquent_ni_ne_bloquent_mots_courants() -> None:
    # 1) "Marchand" ne doit pas faire échouer assert_no_leak sur "marchandises"
    s1 = Scrubber()
    r1 = s1.scrub("M. Paul Marchand valide le stock de marchandises et le voyage en Martinique.")
    assert r1.pseudonymized_text == "M. [PERSONNE_01] valide le stock de marchandises et le voyage en Martinique."
    assert_no_leak([r1.pseudonymized_text], s1.vault)

    # 2) "Petit" en minuscule ("petit matériel") reste en clair, mais "PETIT" / "Petit" en majuscule est chaîné
    s2 = Scrubber()
    r2 = s2.scrub("Mme Claire Petit valide le petit matériel ; relance PETIT transmise.")
    assert r2.pseudonymized_text == "Mme [PERSONNE_01] valide le petit matériel ; relance [PERSONNE_01] transmise."
    assert_no_leak([r2.pseudonymized_text], s2.vault)


def test_enseignes_commerciales_et_faux_identifiants_preserves() -> None:
    text = (
        "Déjeuner Chez Michel puis dîner Bistrot Paul, billet SNCF 145 EUR, "
        "facture EDF et location Kiloutou. Référence interne 732 829 321 (SIREN invalide), "
        "faux SIRET 732 829 320 00075 et faux IBAN FR76 3000 6000 0112 3456 7890 188."
    )
    scrubber = Scrubber()
    res = scrubber.scrub(text)

    assert res.pseudonymized_text == text
    assert res.replacements_count == 0


def test_accents_unicode_et_noms_composes() -> None:
    text = "Dossier de Mme Éléonore Lefèvre-Dumont ; relance envoyée à LEFEVRE-DUMONT."
    scrubber = Scrubber()
    res = scrubber.scrub(text)

    assert "Éléonore" not in res.pseudonymized_text
    assert "LEFEVRE-DUMONT" not in res.pseudonymized_text
    assert res.pseudonymized_text == "Dossier de Mme [PERSONNE_01] ; relance envoyée à [PERSONNE_01]."
    assert rehydrate(res.pseudonymized_text, scrubber.vault) == (
        "Dossier de Mme Éléonore Lefèvre-Dumont ; relance envoyée à Éléonore Lefèvre-Dumont."
    )


def test_assert_no_leak_detecte_une_fuite_residuelle() -> None:
    vault = PiiVault()
    scrubber = Scrubber(vault=vault)
    scrubber.scrub("Dossier de M. Henri Garnier, tel 06 11 22 33 44.")

    with pytest.raises(PiiLeakError):
        assert_no_leak(["Compte-rendu mentionnant GARNIER en clair"], vault)


def test_rehydrate_laisse_jetons_inconnus_intacts() -> None:
    vault = PiiVault()
    assert rehydrate("Voir [PERSONNE_99] et [IBAN_42]", vault) == "Voir [PERSONNE_99] et [IBAN_42]"


def test_civilite_ne_traverse_pas_les_sauts_de_ligne_et_epargne_les_villes() -> None:
    # 1) Retour à la ligne suivi d'un libellé capitalisé (« Tél ») : ne doit pas être avalé
    text = (
        "Cession SCI DUPONT\n"
        "Cédant : M. Pierre Dupont\n"
        "Tél : 0612345678\n"
        "IBAN : FR76 3000 6000 0112 3456 7890 189\n"
        "Prix : 125 000 000 EUR"
    )
    s1 = Scrubber()
    r1 = s1.scrub(text)
    assert r1.pseudonymized_text == (
        "Cession SCI [PERSONNE_01]\n"
        "Cédant : M. [PERSONNE_01]\n"
        "Tél : [TEL_01]\n"
        "IBAN : [IBAN_01]\n"
        "Prix : 125 000 000 EUR"
    )
    assert_no_leak([r1.pseudonymized_text], s1.vault)

    # 2) Ville française en 3e position après prénom + nom : reste en clair
    s2 = Scrubber()
    r2 = s2.scrub("Dossier de Mme Claire Martin Paris et M. Henri Laurent Lyon.")
    assert r2.pseudonymized_text == "Dossier de Mme [PERSONNE_01] Paris et M. [PERSONNE_02] Lyon."
    assert_no_leak([r2.pseudonymized_text], s2.vault)

    # 3) Patronyme homonyme d'une ville (2 mots seulement) : entièrement masqué
    s3 = Scrubber()
    r3 = s3.scrub("M. Gaston Paris a signé avec Mme Claire Lyon.")
    assert r3.pseudonymized_text == "M. [PERSONNE_01] a signé avec Mme [PERSONNE_02]."
    assert "Paris" not in r3.pseudonymized_text
    assert "Lyon" not in r3.pseudonymized_text
    assert_no_leak([r3.pseudonymized_text], s3.vault)
