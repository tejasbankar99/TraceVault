#!/usr/bin/env python3
"""
TraceVault — Accuracy & Performance Evaluation Benchmark
Evaluates the Tri-Layer Threat Engine across standard benchmark emails.
"""
import asyncio
import glob
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.services.email_parser import EmailParserService
from app.services.header_forensics import HeaderForensicsService
from app.services.auth_validator import AuthValidatorService
from app.services.ioc_extractor import IOCExtractorService
from app.services.ai_threat_engine import AIThreatEngine


async def run_benchmark(seed_dir: str = None):
    if not seed_dir:
        candidate_dirs = [
            "/app/seed_data",
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "seed_data")),
            os.path.abspath("seed_data"),
        ]
        for c in candidate_dirs:
            if os.path.isdir(c):
                seed_dir = c
                break

    if not seed_dir or not os.path.isdir(seed_dir):
        print("Error: Could not locate seed_data directory.")
        return

    parser = EmailParserService()
    forensics = HeaderForensicsService()
    auth = AuthValidatorService()
    iocs_svc = IOCExtractorService()
    engine = AIThreatEngine()

    files = sorted(glob.glob(os.path.join(seed_dir, "*.eml")))
    print(f"\n{'='*70}")
    print(f"  TraceVault Cyber Forensics Benchmark Evaluation ({len(files)} cases)")
    print(f"{'='*70}\n")

    tp = tn = fp = fn = 0

    for f in files:
        with open(f, "rb") as fp_in:
            content = fp_in.read()
        fname = os.path.basename(f)
        parsed = await parser.parse_eml_bytes(content)
        h_res = forensics.analyze_headers(parsed)
        sender_ip = h_res.first_public_hop.ip_address if h_res.first_public_hop else None
        a_res = await auth.validate_all(parsed, sender_ip, content)
        i_res = iocs_svc.extract_all_iocs(parsed, h_res.relay_chain)
        t_res = await engine.analyze(parsed, h_res, a_res, i_res)

        is_actual_benign = "benign" in fname.lower()
        is_pred_benign = t_res.threat_score < 40

        if not is_actual_benign and not is_pred_benign:
            tp += 1
            status = "PASS (TP)"
        elif is_actual_benign and is_pred_benign:
            tn += 1
            status = "PASS (TN)"
        elif is_actual_benign and not is_pred_benign:
            fp += 1
            status = "FAIL (FP)"
        else:
            fn += 1
            status = "FAIL (FN)"

        print(f"[{status}] {fname}")
        print(f"   Score:     {t_res.threat_score}/100 | Severity: {t_res.severity}")
        print(f"   Breakdown: Rule={t_res.rule_score} | ML={t_res.ml_score} | Gemini={t_res.gemini_score}")
        print(f"   Verdict:   {a_res.overall_verdict} (Risk: {a_res.spoofing_risk})")
        print("-" * 70)

    total = len(files)
    acc = ((tp + tn) / total) * 100 if total else 0
    prec = (tp / (tp + fp)) * 100 if (tp + fp) else 0
    rec = (tp / (tp + fn)) * 100 if (tp + fn) else 0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) else 0

    print(f"\n{'='*70}")
    print(f"  FINAL EVALUATION METRICS")
    print(f"{'='*70}")
    print(f"Total Evaluated: {total}")
    print(f"True Positives:  {tp}  | True Negatives:  {tn}")
    print(f"False Positives: {fp}  | False Negatives: {fn}")
    print(f"Accuracy:        {acc:.1f}%")
    print(f"Precision:       {prec:.1f}%")
    print(f"Recall:          {rec:.1f}%")
    print(f"F1-Score:        {f1:.1f}%")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(run_benchmark())
