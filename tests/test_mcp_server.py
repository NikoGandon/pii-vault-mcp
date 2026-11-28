"""Tests du serveur MCP à séparation entrée/sortie (anti-exfiltration, anti-écrasement, fail-closed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from symbolon.mcp_server import (
    ENV_INPUT_DIR,
    ENV_OUTPUT_DIR,
    ENV_VAULT_DIR,
    inspect_vault,
    pseudonymize_file,
    rehydrate_to_file,
    verify_no_leak,
)


def _setup_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    in_dir = tmp_path / "input"
    out_dir = tmp_path / "output"
    vault_dir = tmp_path / "vaults"
    in_dir.mkdir()
    out_dir.mkdir()
    monkeypatch.setenv(ENV_INPUT_DIR, str(in_dir))
    monkeypatch.setenv(ENV_OUTPUT_DIR, str(out_dir))
    monkeypatch.setenv(ENV_VAULT_DIR, str(vault_dir))
    return in_dir, out_dir, vault_dir


def test_mcp_separation_entree_sortie_multi_appels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    in_dir, out_dir, _ = _setup_dirs(tmp_path, monkeypatch)

    (in_dir / "doc1.txt").write_text(
        "Client M. Pierre Dupont, tel 0612345678, IBAN FR76 3000 6000 0112 3456 7890 189, mail p.dupont@test.fr.",
        encoding="utf-8",
    )
    (in_dir / "doc2.txt").write_text(
        "Bail SCI DUPONT, prix 125 000 000 EUR, second IBAN FR76 1001 1000 2012 3456 7890 188.",
        encoding="utf-8",
    )

    r1 = pseudonymize_file("doc1.txt", vault_id="dossier-42")
    out1 = str(r1["pseudonymized_text"])
    assert "Dupont" not in out1 and "0612345678" not in out1 and "FR76" not in out1
    assert "[PERSONNE_01]" in out1 and "[TEL_01]" in out1 and "[IBAN_01]" in out1 and "[EMAIL_01]" in out1

    r2 = pseudonymize_file("doc2.txt", vault_id="dossier-42")
    out2 = str(r2["pseudonymized_text"])
    assert "Bail SCI [PERSONNE_01]" in out2
    assert "125 000 000 EUR" in out2
    assert "[IBAN_02]" in out2

    # inspect_vault ne révèle jamais de valeur brute
    stats = inspect_vault(vault_id="dossier-42")
    assert stats["exists"] is True
    assert "Dupont" not in str(stats) and "FR76" not in str(stats) and "0612345678" not in str(stats)

    # verify_no_leak bloque les identifiants structurés collés et les noms en clair
    assert verify_no_leak(out2, vault_id="dossier-42")["clean"] is True
    assert verify_no_leak("XFR76 3000 6000 0112 3456 7890 189X", vault_id="dossier-42")["clean"] is False
    assert verify_no_leak("Compte-rendu sur Pierre Dupont", vault_id="dossier-42")["clean"] is False

    # rehydrate_to_file écrit uniquement dans SYMBOLON_OUTPUT_DIR (0600) sans renvoyer de PII
    rehyd_meta = rehydrate_to_file(
        "Analyse de [PERSONNE_01] (IBAN [IBAN_01], inconnu [PERSONNE_99]).",
        output_path="rapports/final.txt",
        vault_id="dossier-42",
    )
    assert "Dupont" not in str(rehyd_meta) and "FR76" not in str(rehyd_meta)
    assert rehyd_meta["tokens_restored"] == 2
    assert rehyd_meta["tokens_unknown"] == 1
    out_file = out_dir / "rapports" / "final.txt"
    assert (out_file.stat().st_mode & 0o777) == 0o600
    assert out_file.read_text(encoding="utf-8") == (
        "Analyse de Pierre Dupont (IBAN FR76 3000 6000 0112 3456 7890 189, inconnu [PERSONNE_99])."
    )


def test_mcp_bloque_exfiltration_par_enchainement_et_ecrasement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Régression red-team : impossible de réhydrater X[IBAN_01]X puis de le relire, ni d'écraser."""
    in_dir, out_dir, _ = _setup_dirs(tmp_path, monkeypatch)
    (in_dir / "source.txt").write_text(
        "M. Pierre Dupont, IBAN FR76 3000 6000 0112 3456 7890 189.", encoding="utf-8"
    )
    pseudonymize_file("source.txt", vault_id="redteam")

    # 1) Un agent piégé tente de réhydrater X[IBAN_01]X et Z[PERSONNE_01] dans output/exfil.txt
    rehydrate_to_file("X[IBAN_01]X Z[PERSONNE_01]", output_path="exfil.txt", vault_id="redteam")
    assert (out_dir / "exfil.txt").exists()

    # 2) Tenter de relire ce fichier depuis pseudonymize_file échoue (SYMBOLON_OUTPUT_DIR non lisible)
    with pytest.raises(FileNotFoundError):
        pseudonymize_file("exfil.txt", vault_id="redteam")
    with pytest.raises(PermissionError) as exc_info:
        pseudonymize_file("../output/exfil.txt", vault_id="redteam")
    # Le message d'erreur ne divulgue jamais le chemin absolu de la machine hôte
    assert str(tmp_path) not in str(exc_info.value)

    # 3) Tenter d'écraser exfil.txt est refusé
    with pytest.raises(FileExistsError, match="écrasement refusé"):
        rehydrate_to_file("vide", output_path="exfil.txt", vault_id="redteam")

    # 4) Le fichier source dans SYMBOLON_INPUT_DIR n'a pas été touché
    assert "Pierre Dupont" in (in_dir / "source.txt").read_text(encoding="utf-8")


def test_mcp_refuse_dossiers_confondus_ou_imbriques(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    same = tmp_path / "same"
    same.mkdir()
    monkeypatch.setenv(ENV_INPUT_DIR, str(same))
    monkeypatch.setenv(ENV_OUTPUT_DIR, str(same))
    monkeypatch.setenv(ENV_VAULT_DIR, str(tmp_path / "vaults"))

    with pytest.raises(RuntimeError, match="strictement disjoints"):
        pseudonymize_file("doc.txt")

    nested_out = same / "sub_out"
    nested_out.mkdir()
    monkeypatch.setenv(ENV_OUTPUT_DIR, str(nested_out))
    with pytest.raises(RuntimeError, match="strictement disjoints"):
        pseudonymize_file("doc.txt")


def test_mcp_verify_no_leak_fail_closed_si_coffre_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_dirs(tmp_path, monkeypatch)
    with pytest.raises(FileNotFoundError, match="coffre introuvable"):
        verify_no_leak("texte quelconque", vault_id="inexistant")


def test_mcp_rejette_chemins_absolus_symlinks_et_vault_id_invalide(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    in_dir, _, _ = _setup_dirs(tmp_path, monkeypatch)
    outside = tmp_path / "secret.txt"
    outside.write_text("M. Pierre Dupont", encoding="utf-8")
    (in_dir / "lien.txt").symlink_to(outside)

    with pytest.raises(PermissionError) as exc1:
        pseudonymize_file(str(outside))
    assert str(tmp_path) not in str(exc1.value)

    with pytest.raises(PermissionError) as exc2:
        pseudonymize_file("lien.txt")
    assert str(tmp_path) not in str(exc2.value)

    with pytest.raises(ValueError, match="vault_id invalide"):
        pseudonymize_file("doc.txt", vault_id="../etc/passwd")

    monkeypatch.delenv(ENV_INPUT_DIR)
    with pytest.raises(RuntimeError, match=ENV_INPUT_DIR):
        pseudonymize_file("doc.txt")
