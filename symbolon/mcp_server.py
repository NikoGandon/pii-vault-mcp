"""Serveur MCP (Model Context Protocol) à séparation stricte entrée/sortie pour la pseudonymisation RGPD.

Modèle de menace :
  En MCP, le LLM cloud rédige les arguments et lit les sorties de chaque outil.
  Pour empêcher à la fois l'exposition directe des PII ET l'exfiltration par enchaînement
  d'outils (ex. réhydrater `X[IBAN_01]X` puis relire le fichier avec `pseudonymize_file`) :

  1. Deux dossiers strictement disjoints sont obligatoires (fail-closed) :
     - `SYMBOLON_INPUT_DIR`  : lecture seule pour `pseudonymize_file`
     - `SYMBOLON_OUTPUT_DIR` : écriture seule pour `rehydrate_to_file` (jamais lisible par les outils)
  2. `rehydrate_to_file` refuse d'écraser un fichier existant (création atomique O_EXCL en mode 0600).
  3. Les messages d'erreur ne divulguent jamais les chemins absolus de la machine hôte.
  4. `verify_no_leak` est fail-closed : lève FileNotFoundError si le coffre n'existe pas.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from symbolon.scrubber import Scrubber, assert_no_leak, find_leaks, rehydrate
from symbolon.vault import PiiVault

_VAULT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_TOKEN_RE = re.compile(r"\[(?:PERSONNE|IBAN|NIR|SIREN|SIRET|EMAIL|TEL)_\d{2,}\]")

ENV_VAULT_DIR = "SYMBOLON_VAULT_DIR"
ENV_INPUT_DIR = "SYMBOLON_INPUT_DIR"
ENV_OUTPUT_DIR = "SYMBOLON_OUTPUT_DIR"

mcp = MCPServer(
    "symbolon-pii",
    instructions=(
        "Serveur local de pseudonymisation réversible RGPD (Art. 4(5)) à séparation stricte "
        "entrée (SYMBOLON_INPUT_DIR, lecture seule) / sortie (SYMBOLON_OUTPUT_DIR, écriture seule sans écrasement). "
        "Utilisez pseudonymize_file pour lire un document d'entrée en mode pseudonymisé, "
        "verify_no_leak pour vérifier un texte avant partage, et rehydrate_to_file pour écrire "
        "un nouveau fichier réhydraté localement sans réexposer les identités au modèle."
    ),
)


def _vault_dir() -> Path:
    raw = os.environ.get(ENV_VAULT_DIR)
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".symbolon-pii" / "vaults").resolve()


def _require_dir(env_name: str) -> Path:
    raw = os.environ.get(env_name)
    if not raw:
        raise RuntimeError(f"{env_name} doit être défini (configuration fail-closed).")
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"dossier configuré pour {env_name} introuvable")
    return root


def _validated_io_dirs() -> tuple[Path, Path]:
    in_dir = _require_dir(ENV_INPUT_DIR)
    out_dir = _require_dir(ENV_OUTPUT_DIR)
    v_dir = _vault_dir()
    if in_dir.is_relative_to(out_dir) or out_dir.is_relative_to(in_dir):
        raise RuntimeError(f"{ENV_INPUT_DIR} et {ENV_OUTPUT_DIR} doivent être strictement disjoints.")
    if in_dir.is_relative_to(v_dir) or v_dir.is_relative_to(in_dir):
        raise RuntimeError(f"{ENV_INPUT_DIR} et {ENV_VAULT_DIR} doivent être strictement disjoints.")
    if out_dir.is_relative_to(v_dir) or v_dir.is_relative_to(out_dir):
        raise RuntimeError(f"{ENV_OUTPUT_DIR} et {ENV_VAULT_DIR} doivent être strictement disjoints.")
    return in_dir, out_dir


def _resolve_under(root: Path, relative_path: str) -> Path:
    raw_path = Path(relative_path)
    if raw_path.is_absolute():
        raise PermissionError("chemin absolu refusé : fournir un chemin relatif au dossier autorisé")
    candidate = (root / raw_path).resolve()
    if not candidate.is_relative_to(root):
        raise PermissionError("accès refusé hors du dossier autorisé")
    return candidate


def _vault_path(vault_id: str) -> Path:
    if not _VAULT_ID_RE.fullmatch(vault_id):
        raise ValueError(
            f"vault_id invalide : {vault_id!r} (attendu alphanumérique, tirets ou underscores, 1-64 caractères)"
        )
    return _vault_dir() / f"{vault_id}.json"


def _write_new_text_0600(path: Path, content: str) -> None:
    """Crée un nouveau fichier (0600) et échoue si le fichier existe déjà (jamais d'écrasement)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise FileExistsError("le fichier de sortie existe déjà (écrasement refusé)") from exc
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
    except Exception:
        if path.exists():
            path.unlink()
        raise


@mcp.tool()
def pseudonymize_file(
    input_path: str,
    vault_id: str = "default",
    known_persons: list[str] | None = None,
) -> dict[str, object]:
    """Lit un fichier local dans SYMBOLON_INPUT_DIR, le pseudonymise et persiste le coffre."""
    in_dir, _ = _validated_io_dirs()
    v_path = _vault_path(vault_id)
    src = _resolve_under(in_dir, input_path)
    if not src.is_file():
        raise FileNotFoundError(f"fichier introuvable : {input_path!r}")

    raw_text = src.read_text(encoding="utf-8")
    vault = PiiVault.load(v_path) if v_path.exists() else PiiVault()
    scrubber = Scrubber(vault=vault, known_persons=known_persons or ())
    result = scrubber.scrub(raw_text)
    assert_no_leak([result.pseudonymized_text], vault)
    vault.save(v_path)
    return {
        "vault_id": vault_id,
        "pseudonymized_text": result.pseudonymized_text,
        "replacements_count": result.replacements_count,
        "tokens_by_kind": result.tokens_by_kind,
        "vault_stats": vault.stats(),
    }


@mcp.tool()
def rehydrate_to_file(
    text: str,
    output_path: str,
    vault_id: str = "default",
) -> dict[str, object]:
    """Réhydrate localement `text` dans un NOUVEAU fichier de SYMBOLON_OUTPUT_DIR (0600, sans écrasement)."""
    _, out_dir = _validated_io_dirs()
    v_path = _vault_path(vault_id)
    dst = _resolve_under(out_dir, output_path)
    if not v_path.exists():
        raise FileNotFoundError(f"coffre introuvable : {vault_id!r}")

    vault = PiiVault.load(v_path)
    tokens_found = [m.group(0) for m in _TOKEN_RE.finditer(text)]
    restored_count = sum(1 for t in tokens_found if t in vault.token_to_entity)
    unknown_count = len(tokens_found) - restored_count

    restored_text = rehydrate(text, vault)
    _write_new_text_0600(dst, restored_text)
    return {
        "vault_id": vault_id,
        "output_path": str(dst.relative_to(out_dir)),
        "tokens_restored": restored_count,
        "tokens_unknown": unknown_count,
    }


@mcp.tool()
def inspect_vault(vault_id: str = "default") -> dict[str, object]:
    """Retourne uniquement les compteurs et l'état du coffre (jamais les données personnelles brutes)."""
    path = _vault_path(vault_id)
    if not path.exists():
        return {"vault_id": vault_id, "exists": False, "total_tokens": 0, "counters": {}}
    vault = PiiVault.load(path)
    return {"vault_id": vault_id, "exists": True, **vault.stats()}


@mcp.tool()
def verify_no_leak(text: str, vault_id: str = "default") -> dict[str, object]:
    """Contrôle fail-closed qu'aucune entité enregistrée dans le coffre ne figure en clair dans `text`.

    Lève FileNotFoundError si le coffre n'existe pas (jamais de validation implicite en l'absence de coffre).
    """
    path = _vault_path(vault_id)
    if not path.exists():
        raise FileNotFoundError(f"coffre introuvable : {vault_id!r}")
    vault = PiiVault.load(path)
    leaks = find_leaks([text], vault)
    return {
        "vault_id": vault_id,
        "clean": len(leaks) == 0,
        "leaks_count": len(leaks),
    }


def run_server() -> None:
    mcp.run()
