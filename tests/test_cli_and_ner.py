"""Tests de la CLI et du protocole NerBackend optionnel (0 réseau, 0 USD)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from symbolon.cli import main as cli_main
from symbolon.detectors import DetectedSpan
from symbolon.scrubber import Scrubber, rehydrate
from symbolon.vault import EntityKind


class _FakeLocalNer:
    """Stub de NerBackend simulant GLiNER sur des noms nus sans civilité."""

    def predict(self, text: str) -> Sequence[DetectedSpan]:
        target = "Julien Delacroix"
        idx = text.find(target)
        if idx == -1:
            return ()
        return (
            DetectedSpan(
                start=idx,
                end=idx + len(target),
                text=target,
                kind=EntityKind.PERSON,
                source="fake_ner",
            ),
        )


def test_scrubber_avec_backend_ner_et_chainage_patronymique() -> None:
    text = "Déjeuner avec Julien Delacroix puis virement SCI DELACROIX."
    scrubber = Scrubber(ner=_FakeLocalNer())
    res = scrubber.scrub(text)
    assert res.pseudonymized_text == "Déjeuner avec [PERSONNE_01] puis virement SCI [PERSONNE_01]."
    assert rehydrate(res.pseudonymized_text, scrubber.vault) == (
        "Déjeuner avec Julien Delacroix puis virement SCI Julien Delacroix."
    )


def test_cli_scrub_et_rehydrate_roundtrip(tmp_path: Path, capsys: object) -> None:
    vault_file = tmp_path / "dossier.json"
    in_file = tmp_path / "doc.txt"
    in_file.write_text(
        "Client M. Pierre Dupont, IBAN FR76 3000 6000 0112 3456 7890 189.",
        encoding="utf-8",
    )

    rc = cli_main(["scrub", "--vault", str(vault_file), "--input", str(in_file)])
    assert rc == 0
    assert vault_file.exists()

    # Capture via fichier de sortie intermédiaire pour tester rehydrate
    from pytest import CaptureFixture

    assert isinstance(capsys, CaptureFixture)
    scrubbed = capsys.readouterr().out
    assert "[PERSONNE_01]" in scrubbed and "[IBAN_01]" in scrubbed
    assert "Dupont" not in scrubbed

    scrubbed_file = tmp_path / "scrubbed.txt"
    scrubbed_file.write_text(scrubbed, encoding="utf-8")
    rc2 = cli_main(["rehydrate", "--vault", str(vault_file), "--input", str(scrubbed_file)])
    assert rc2 == 0
    restored = capsys.readouterr().out
    assert restored == "Client M. Pierre Dupont, IBAN FR76 3000 6000 0112 3456 7890 189."
