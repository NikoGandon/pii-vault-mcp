"""Évaluation de non-régression reproductible (0 USD) sur le corpus synthétique français.

Distingue explicitement deux métriques anti-fuite :
  - known_vault_leaks              : entités enregistrées dans le coffre restées en clair (invariant interne, attendu 0)
  - ground_truth_unmasked_entities : entités de vérité terrain non détectées (FN réels, ex. noms nus sans NER)

Avec --check (utilisé en CI), quitte avec le code 1 en cas de régression.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from symbolon.scrubber import Scrubber, find_leaks  # noqa: E402
from symbolon.vault import PiiVault  # noqa: E402

CORPUS_PATH = Path(__file__).parent / "corpus_fr.jsonl"
STRUCTURED_KINDS = ("EMAIL", "IBAN", "NIR", "SIREN", "SIRET", "TEL")


def run_benchmark(corpus_path: Path = CORPUS_PATH) -> dict[str, object]:
    cases = [json.loads(line) for line in corpus_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)

    trap_cases = 0
    trap_false_positives = 0
    known_vault_leaks = 0
    ground_truth_unmasked_docs = 0
    total_cases = len(cases)

    for case in cases:
        text: str = case["text"]
        expected: list[dict[str, str]] = case["entities"]
        known_persons: list[str] = case.get("known_persons", [])
        is_trap: bool = bool(case.get("is_trap", False))

        vault = PiiVault()
        scrubber = Scrubber(vault=vault, known_persons=known_persons)
        res = scrubber.scrub(text)

        if find_leaks([res.pseudonymized_text], vault):
            known_vault_leaks += 1

        if is_trap:
            trap_cases += 1
            if res.replacements_count > 0:
                trap_false_positives += 1

        expected_pairs = {(e["kind"], e["text"]) for e in expected}
        predicted_pairs = {(s.kind.value, s.text) for s in res.spans}

        doc_missed = 0
        for kind, val in predicted_pairs:
            if (kind, val) in expected_pairs:
                tp[kind] += 1
            else:
                fp[kind] += 1
        for kind, val in expected_pairs:
            if (kind, val) not in predicted_pairs:
                fn[kind] += 1
                doc_missed += 1
        if doc_missed > 0:
            ground_truth_unmasked_docs += 1

    kinds = sorted(set(tp) | set(fp) | set(fn))
    by_kind: dict[str, dict[str, float | int]] = {}
    tot_tp = tot_fp = tot_fn = 0
    for k in kinds:
        k_tp, k_fp, k_fn = tp[k], fp[k], fn[k]
        tot_tp += k_tp
        tot_fp += k_fp
        tot_fn += k_fn
        prec = k_tp / (k_tp + k_fp) if (k_tp + k_fp) else 1.0
        rec = k_tp / (k_tp + k_fn) if (k_tp + k_fn) else 1.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        by_kind[k] = {
            "tp": k_tp,
            "fp": k_fp,
            "fn": k_fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        }

    g_prec = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else 1.0
    g_rec = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else 1.0
    g_f1 = (2 * g_prec * g_rec / (g_prec + g_rec)) if (g_prec + g_rec) else 0.0

    return {
        "total_cases": total_cases,
        "trap_cases": trap_cases,
        "trap_false_positives": trap_false_positives,
        "known_vault_leaks": known_vault_leaks,
        "ground_truth_unmasked_entities": tot_fn,
        "ground_truth_unmasked_docs": ground_truth_unmasked_docs,
        "global": {
            "tp": tot_tp,
            "fp": tot_fp,
            "fn": tot_fn,
            "precision": round(g_prec, 4),
            "recall": round(g_rec, 4),
            "f1": round(g_f1, 4),
        },
        "by_kind": by_kind,
    }


def check_thresholds(report: dict[str, object]) -> list[str]:
    failures: list[str] = []
    if report["trap_false_positives"] != 0:
        failures.append(f"faux positifs sur pièges : {report['trap_false_positives']} (attendu 0)")
    if report["known_vault_leaks"] != 0:
        failures.append(f"fuites sur entités connues du coffre : {report['known_vault_leaks']} (attendu 0)")
    by_kind = report["by_kind"]
    assert isinstance(by_kind, dict)
    for kind in STRUCTURED_KINDS:
        stats = by_kind.get(kind)
        if not isinstance(stats, dict) or stats["precision"] < 1.0 or stats["recall"] < 1.0:
            failures.append(f"régression sur identifiant structuré {kind} : {stats}")
    g = report["global"]
    assert isinstance(g, dict)
    if g["precision"] < 1.0:
        failures.append(f"précision globale < 100 % : {g['precision']}")
    if g["recall"] < 0.95:
        failures.append(f"rappel global < 95 % : {g['recall']}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Évaluation de non-régression sur le corpus synthétique FR.")
    parser.add_argument("--check", action="store_true", help="Échoue (code 1) en cas de régression sur les seuils.")
    args = parser.parse_args(argv)

    report = run_benchmark()
    print(f"Corpus synthétique de non-régression FR : {report['total_cases']} documents (dont {report['trap_cases']} pièges)")
    print(f"Faux positifs sur pièges : {report['trap_false_positives']}/{report['trap_cases']}")
    print(f"Fuites sur entités enregistrées dans le coffre (invariant interne) : {report['known_vault_leaks']}/{report['total_cases']}")
    print(
        f"Entités de vérité terrain restées en clair (FN réels, mode déterministe seul) : "
        f"{report['ground_truth_unmasked_entities']} entité(s) dans {report['ground_truth_unmasked_docs']} document(s)"
    )
    print("\nPar type d'entité :")
    by_kind = report["by_kind"]
    assert isinstance(by_kind, dict)
    for k, stats in by_kind.items():
        print(
            f"  {k:<10} P={stats['precision']*100:5.1f}%  R={stats['recall']*100:5.1f}%  "
            f"F1={stats['f1']*100:5.1f}%  (TP={stats['tp']}, FP={stats['fp']}, FN={stats['fn']})"
        )
    g = report["global"]
    assert isinstance(g, dict)
    print(
        f"\nGLOBAL     P={g['precision']*100:5.1f}%  R={g['recall']*100:5.1f}%  "
        f"F1={g['f1']*100:5.1f}%  (TP={g['tp']}, FP={g['fp']}, FN={g['fn']})"
    )

    if args.check:
        failures = check_thresholds(report)
        if failures:
            print("\nÉCHEC NON-RÉGRESSION :", file=sys.stderr)
            for msg in failures:
                print(f"  - {msg}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
