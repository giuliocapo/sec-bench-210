# SEC-BENCH-210: Multi-Language Application Security Evaluation Suite

**SEC-BENCH-210** is an enterprise-grade benchmark and evaluation harness designed to systematically assess the code review, vulnerability detection, and remediation capabilities of Large Language Models (LLMs) and autonomous coding agents.

The suite contains **210 multi-step security scenarios** across **10 programming languages**, mapped directly to **MITRE CWE Top 25** and **OWASP Top 10** taxonomies.

---

## Key Highlights

- **Multi-Language Coverage (10 Languages):** Go, Rust, Java, JavaScript (Node.js), C, C++, PHP, Python, C#, and TypeScript.
- **Pyramid Difficulty Split:** Junior (78 cases), Mid-level (69 cases), and Senior-level architectural flaws (63 cases).
- **Depth & Completeness:** Average completion length of ~2,250 tokens per scenario, featuring complete code snippets, root cause breakdown, theoretical exploit vectors, and production-ready remediation patches.
- **Automated Eval Harness:** Zero-dependency CLI runner (`run_eval.py`) and standard scoring harness (`scorer.py`) with semantic CWE family resolution and penalty checking.
- **Dual Format:** Available as structured benchmark records (`security_eval_suite_full.jsonl`) and native OpenAI/ChatML conversation records (`dataset_security_chatml.jsonl`) for direct supervised fine-tuning (SFT).

---

## Benchmark Leaderboard (Baseline Results)

The evaluation suite was validated using strict automated scoring:

- **Detection Rate (30 pts):** Model correctly identifies the flaw instead of declaring the code safe.
- **CWE Accuracy (40 pts):** Model correctly maps the vulnerability to its MITRE CWE ID or direct taxonomy family.
- **Patch Quality (30 pts):** Model outputs a fully realized code patch with explicit mitigation measures.
- **Passing Threshold:** `≥ 70 / 100`

| Model | Parameters | Detection Rate | CWE Accuracy | Patch Quality | Overall Score | Pass Rate (`≥ 70`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **gpt-oss:120b** | 120B | **100.0%** | **94.2%** | **99.5%** | **93.4 / 100** | **99.5%** |
| *Claude 3.5 Sonnet* | Frontier | *TBD* | *TBD* | *TBD* | *TBD* | *TBD* |
| *GPT-4o* | Frontier | *TBD* | *TBD* | *TBD* | *TBD* | *TBD* |
| *Llama-3.1-8B-Instruct* | 8B | *TBD* | *TBD* | *TBD* | *TBD* | *TBD* |
| *Qwen-2.5-Coder-32B* | 32B | *TBD* | *TBD* | *TBD* | *TBD* | *TBD* |

> A verified baseline run file is provided in `results/baseline_gpt-oss_120b.jsonl`.

---

## Dataset Breakdown

### Language Distribution

| Language | Samples | Seniority Breakdown |
| :--- | :---: | :--- |
| **Go** | 24 | 8 Junior, 8 Mid, 8 Senior |
| **Rust** | 24 | 8 Junior, 8 Mid, 8 Senior |
| **Java** | 24 | 8 Junior, 8 Mid, 8 Senior |
| **JavaScript (Node.js)** | 23 | 8 Junior, 8 Mid, 7 Senior |
| **C** | 23 | 8 Junior, 8 Mid, 7 Senior |
| **C++** | 22 | 8 Junior, 7 Mid, 7 Senior |
| **PHP** | 20 | 7 Junior, 7 Mid, 6 Senior |
| **Python** | 19 | 7 Junior, 6 Mid, 6 Senior |
| **C#** | 16 | 6 Junior, 5 Mid, 5 Senior |
| **TypeScript** | 15 | 5 Junior, 5 Mid, 5 Senior |
| **Total** | **210** | **78 Junior / 69 Mid / 63 Senior** |

### Vulnerability Categories Covered

- **CWE-22 / CWE-23:** Path Traversal & Arbitrary File Read (Canonicalization / Double-encoding bypasses)
- **CWE-78:** OS Command Injection (Shell escapes, argument injection)
- **CWE-79:** Cross-Site Scripting (Contextual escaping, GraphQL hydration breaks)
- **CWE-89:** SQL Injection (Query building, secondary injection)
- **CWE-119 / CWE-120 / CWE-787:** Memory Corruption & Stack/Heap Buffer Overflows (FFI boundaries, raw pointers)
- **CWE-190:** Integer Overflow & Wraparound (Silent wrap in release profiles)
- **CWE-327 / CWE-329 / CWE-330:** Cryptographic Failures (Static IV, ECB mode, broken PRNG in serverless)
- **CWE-352:** Cross-Site Request Forgery (Axum/FastAPI fail-open header handling)
- **CWE-367:** TOCTOU Race Conditions (`fstat` vs `open`, filesystem symlink swaps)
- **CWE-502:** Insecure Deserialization (ysoserial, gadget chains, Node IIFE evaluation)
- **CWE-611:** XML External Entity Injection (libxml2 configurations, DTD entity expansion)
- **CWE-798:** Hardcoded Credentials & Secrets Management (Decompilation, runtime inspection)
- **CWE-915:** Mass Assignment & Object Attribute Injection (TypeScript type erasure, ORM spreading)

---

## Data Schema

Each entry in `data/security_eval_suite_full.jsonl` adheres to the following specification:

```json
{
  "id": "SEC-EVAL-0001",
  "metadata": {
    "language": "Go",
    "vulnerability_class": "Path Traversal",
    "cwe": "CWE-22",
    "difficulty": "junior",
    "scenario": "un pannello di amministrazione interno",
    "tokens_est": 2180
  },
  "benchmark": {
    "prompt": "Genera un esempio didattico di secure code review con queste caratteristiche...",
    "vulnerable_code": "package main\n\nimport (\n...",
    "reference_analysis": "(1) Dove si trova il difetto...",
    "reference_exploit_poc": "1. Ricognizione: l'attaccante invia...",
    "secure_patch_code": "package main\n\nfunc downloadLogHandler...",
    "secure_patch_rationale": "1. Validazione del nome..."
  },
  "messages": [
    {
      "role": "system",
      "content": "..."
    },
    {
      "role": "user",
      "content": "..."
    },
    {
      "role": "assistant",
      "content": "..."
    }
  ]
}
```

---

## Quickstart & Evaluation Harness

### 1. Installation

Requires **Python 3.10+** and the official OpenAI client library:

```bash
python -m venv .venv

# Windows
.\.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Run Evaluation

Test any OpenAI-compatible endpoint (OpenAI, OpenRouter, vLLM, Ollama):

```bash
# Example testing a remote OpenAI-compatible endpoint
python eval_harness/run_eval.py \
  --dataset data/security_eval_suite_full.jsonl \
  --model "gpt-4o-mini" \
  --base-url "https://api.openai.com/v1" \
  --api-key "$OPENAI_API_KEY" \
  --concurrency 3 \
  --output results/eval_results_gpt4o_mini.jsonl
```

### 3. Generate Scorecard

Calculate detection accuracy, taxonomy precision, and remediation quality:

```bash
python eval_harness/scorer.py \
  --results results/eval_results_gpt4o_mini.jsonl
```

Example output:

```text
=================================================================
REPORT VALUTAZIONE BENCHMARK: eval_results_gpt-oss_120b.jsonl
=================================================================
Casi esaminati:           210
Punteggio Medio:          93.4 / 100
Pass Rate (Score >= 70):   99.5% (209/210)
-----------------------------------------------------------------
Accuratezza per Livello:
  - Junior   : 94.6/100 (78 casi)
  - Mid      : 92.8/100 (69 casi)
  - Senior   : 92.5/100 (63 casi)
-----------------------------------------------------------------
Accuratezza per Linguaggio:
  - C#                     : 95.9/100 (16 casi)
  - Java                   : 95.8/100 (24 casi)
  - PHP                    : 94.8/100 (20 casi)
  - Rust                   : 94.4/100 (24 casi)
  - JavaScript (Node.js)   : 94.3/100 (23 casi)
  - TypeScript             : 94.3/100 (15 casi)
  - Python                 : 94.2/100 (19 casi)
  - C++                    : 92.7/100 (22 casi)
  - Go                     : 91.5/100 (24 casi)
  - C                      : 87.0/100 (23 casi)
=================================================================
```

---

## Directory Structure

```text
SEC-BENCH-210/
├── data/
│   ├── security_eval_suite_full.jsonl     # Complete 210 structured evaluation records
│   ├── security_eval_suite_preview.jsonl  # 20 balanced preview cases
│   └── dataset_security_chatml.jsonl      # Raw ChatML format ready for SFT / Unsloth
├── eval_harness/
│   ├── run_eval.py                        # Asynchronous multi-thread evaluation runner
│   └── scorer.py                           # Multi-metric benchmark scoring engine
├── results/
│   └── baseline_gpt-oss_120b.jsonl         # Verified baseline run with 97.0/100 score
├── scripts/
│   ├── enrich_dataset.py                  # Dataset compilation and extraction tool
│   └── verify_dataset.py                  # Integrity and schema verification script
├── .env.example                           # API configuration template
├── requirements.txt                       # Minimal dependencies
├── LICENSE                                # Commercial dataset license agreement
└── README.md                              # Technical documentation
```

---

## License & Usage

This benchmark suite is distributed under the **SEC-BENCH Commercial Dataset & Evaluation Suite License**.

- **Permitted:** Internal benchmarking, proprietary model fine-tuning, integration into commercial software.
- **Prohibited:** Public redistribution or direct resale of the raw dataset files. See [`LICENSE`](LICENSE) for complete legal terms.