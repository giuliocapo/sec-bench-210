#!/usr/bin/env python3
"""
File: eval_harness/scorer.py
Ruolo: Valuta le risposte normalizzando trattini Unicode, riconoscendo famiglie
       CWE correlate e calcolando la qualità di detection e patch.
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

# Mapping delle famiglie e sinonimi CWE più comuni nell'AppSec
CWE_FAMILIES = {
    # Path Traversal & Input Validation
    "CWE-20": {"CWE-20", "CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "CWE-22": {"CWE-22", "CWE-23", "CWE-20", "CWE-36"},
    "CWE-23": {"CWE-22", "CWE-23", "CWE-20"},
    # Crittografia & IV
    "CWE-329": {"CWE-329", "CWE-330", "CWE-327", "CWE-326", "CWE-323"},
    "CWE-327": {"CWE-327", "CWE-326", "CWE-328", "CWE-329", "CWE-330"},
    "CWE-330": {"CWE-330", "CWE-329", "CWE-327"},
    # Mass Assignment & State Injection
    "CWE-915": {"CWE-915", "CWE-642", "CWE-20", "CWE-471"},
    "CWE-642": {"CWE-642", "CWE-915", "CWE-20"},
    # Broken Object Level Auth (IDOR / BOLA)
    "CWE-639": {"CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863"},
    # Memory safety
    "CWE-119": {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-787"},
    "CWE-787": {"CWE-787", "CWE-120", "CWE-121", "CWE-122", "CWE-119"},
    "CWE-120": {"CWE-120", "CWE-787", "CWE-119"},
}

VULN_SIGNALS = [
    r"vulnerabil[e|ità]", r"difetto", r"falla", r"flaw", r"vulnerabilit[y|ies]",
    r"insicur[o|a]", r"insecure", r"cwe[\-‑\–\—]\d+", r"exploitable", r"attacco", r"criticit[àa]"
]

def normalize_text(text: str) -> str:
    """Sostituisce qualsiasi trattino Unicode (non-breaking, en-dash, em-dash) con il trattino standard ASCII."""
    if not text:
        return ""
    return re.sub(r"[\u2010\u2011\u2012\u2013\u2014\u2212]", "-", text)

def score_case(record: dict) -> dict:
    resp = normalize_text(record.get("response", "").strip())
    cwe_truth = normalize_text(record.get("cwe_truth", "")).upper()

    if not resp or record.get("error"):
        return {"detection": 0, "cwe_match": 0, "patch_present": 0, "total": 0, "passed": False}

    # 1. Detection Score (30 punti)
    detected = any(re.search(pat, resp, re.IGNORECASE) for pat in VULN_SIGNALS)
    detection_score = 30 if detected else 0

    # 2. CWE Accuracy Score (40 punti)
    cwes_found = [c.upper() for c in re.findall(r"CWE-\d+", resp, re.IGNORECASE)]
    cwe_match_score = 0

    if cwe_truth in cwes_found:
        cwe_match_score = 40  # Match esatto
    else:
        # Match di famiglia semantica
        allowed_family = CWE_FAMILIES.get(cwe_truth, {cwe_truth})
        if any(c in allowed_family for c in cwes_found):
            cwe_match_score = 35  # Famiglia equivalente
        elif len(cwes_found) > 0:
            cwe_match_score = 15  # Ha identificato un CWE formale ma differente

    # 3. Patch Presence & Quality Score (30 punti)
    code_blocks = re.findall(r"```[a-zA-Z#+-]*\n(.*?)```", resp, re.DOTALL)
    patch_score = 0
    if len(code_blocks) >= 1:
        patch_len = len(code_blocks[0].strip())
        if patch_len > 60:
            patch_score = 30
        else:
            patch_score = 15

    total = detection_score + cwe_match_score + patch_score
    return {
        "detection": detection_score,
        "cwe_match": cwe_match_score,
        "patch_present": patch_score,
        "total": total,
        "passed": total >= 70
    }

def main():
    parser = argparse.ArgumentParser(description="SEC-BENCH Automated Scorer")
    parser.add_argument("--results", required=True, help="File JSONL dei risultati da run_eval.py")
    args = parser.parse_args()

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"Errore: file '{args.results}' non trovato.")
        return

    records = []
    with open(results_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    if not records:
        print("Nessun record presente nel file.")
        return

    total_score = 0
    passed_count = 0
    by_lang = defaultdict(list)
    by_diff = defaultdict(list)

    for r in records:
        s = score_case(r)
        total_score += s["total"]
        if s["passed"]:
            passed_count += 1

        by_lang[r.get("language", "Unknown")].append(s["total"])
        by_diff[r.get("difficulty", "Unknown")].append(s["total"])

    n = len(records)
    avg_score = total_score / n
    pass_rate = (passed_count / n) * 100

    print("=" * 65)
    print(f"REPORT VALUTAZIONE BENCHMARK: {results_path.name}")
    print("=" * 65)
    print(f"Casi esaminati:           {n}")
    print(f"Punteggio Medio:          {avg_score:.1f} / 100")
    print(f"Pass Rate (Score >= 70):   {pass_rate:.1f}% ({passed_count}/{n})")
    print("-" * 65)
    print("Accuratezza per Livello:")
    for diff in ["junior", "mid", "senior"]:
        if diff in by_diff:
            scores = by_diff[diff]
            avg = sum(scores) / len(scores)
            print(f"  - {diff.capitalize():8} : {avg:.1f}/100 ({len(scores)} casi)")
    print("-" * 65)
    print("Accuratezza per Linguaggio:")
    for lang, scores in sorted(by_lang.items(), key=lambda x: sum(x[1])/len(x[1]), reverse=True):
        avg = sum(scores) / len(scores)
        print(f"  - {lang:22} : {avg:.1f}/100 ({len(scores)} casi)")
    print("=" * 65)

if __name__ == "__main__":
    main()