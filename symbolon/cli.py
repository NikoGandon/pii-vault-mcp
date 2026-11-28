"""Interface en ligne de commande pour Symbolon (symbolon-pii)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from symbolon.scrubber import Scrubber, rehydrate
from symbolon.vault import PiiVault


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="symbolon",
        description="Symbolon — Pseudonymisation réversible RGPD (Art. 4(5)) 100 % locale pour le français.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scrub = sub.add_parser("scrub", help="Pseudonymise un texte (stdin ou --input) et persiste le coffre.")
    p_scrub.add_argument("--vault", type=Path, required=True, help="Chemin du fichier coffre JSON local.")
    p_scrub.add_argument("--input", type=Path, help="Fichier texte d'entrée (défaut : stdin).")
    p_scrub.add_argument("--person", action="append", default=[], help="Personne connue à chaîner (répétable).")

    p_rehyd = sub.add_parser("rehydrate", help="Réhydrate localement un texte depuis le coffre.")
    p_rehyd.add_argument("--vault", type=Path, required=True, help="Chemin du fichier coffre JSON local.")
    p_rehyd.add_argument("--input", type=Path, help="Fichier texte d'entrée (défaut : stdin).")

    sub.add_parser("mcp", help="Lance le serveur MCP (transport stdio).")

    args = parser.parse_args(argv)

    if args.command == "mcp":
        from symbolon.mcp_server import run_server

        run_server()
        return 0

    raw_text = args.input.read_text(encoding="utf-8") if args.input else sys.stdin.read()

    if args.command == "scrub":
        vault = PiiVault.load(args.vault) if args.vault.exists() else PiiVault()
        res = Scrubber(vault=vault, known_persons=args.person).scrub(raw_text)
        vault.save(args.vault)
        sys.stdout.write(res.pseudonymized_text)
        return 0

    if args.command == "rehydrate":
        if not args.vault.exists():
            sys.stderr.write(f"Erreur : coffre introuvable ({args.vault})\n")
            return 1
        vault = PiiVault.load(args.vault)
        sys.stdout.write(rehydrate(raw_text, vault))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
