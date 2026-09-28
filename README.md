# LLM Safety Red-Team Evals (`llm-safety-redteam-evals`)

> AI Safety, Jailbreak, Prompt Injection, PII Leakage & Harmful Content Red-Teaming Evaluation Suite.

[![CI](https://github.com/user/llm-safety-redteam-evals/actions/workflows/ci.yml/badge.svg)](https://github.com/user/llm-safety-redteam-evals/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Executive Summary

`llm-safety-redteam-evals` provides an automated red-teaming framework to evaluate and benchmark LLM vulnerabilities across 5 adversarial attack categories:
1. **Prompt Injection**: Direct and indirect override of system instructions.
2. **Jailbreak (DAN)**: Do-Anything-Now persona adoption and rule bypassing.
3. **PII Leakage**: Extraction of sensitive customer data (SSNs, credit card numbers, API keys).
4. **Harmful Content Generation**: Cyberattack exploits, malware generation, or illegal synthesis.
5. **System Prompt Extraction**: Eliciting confidential system instructions.

This repository compares 3 defense configurations:
- **Def v0 (Raw Model)**: Unfiltered model execution without guardrails.
- **Def v1 (Prompt Guard)**: System prompt negative constraints and refusal instructions.
- **Def v2 (Dual Filter)**: Input/Output regex sanitization and automated PII anonymizer guardrail.

---

## Architecture & Severity Taxonomy

```
                     ┌───────────────────────────────────────────┐
                     │          Adversarial Attack Suite         │
                     └─────────────────────┬─────────────────────┘
                                           │
            ┌──────────────────────────────┼──────────────────────────────┐
            ▼                              ▼                              ▼
 ┌─────────────────────┐        ┌─────────────────────┐        ┌─────────────────────┐
 │  Prompt Injection   │        │   Jailbreak (DAN)   │        │     PII Leakage     │
 └──────────┬──────────┘        └──────────┬──────────┘        └──────────┬──────────┘
            │                              │                              │
            └──────────────────────────────┼──────────────────────────────┘
                                           ▼
                           ┌──────────────────────────────┐
                           │   Safety Evaluator Engine    │
                           └───────────────┬──────────────┘
                                           │
         ┌─────────────────────────────────┴─────────────────────────────────┐
         ▼                                 ▼                                 ▼
   CRITICAL Breaches                 HIGH / MEDIUM Risk                 SAFE Refusals
(PII / Harmful Output)            (Prompt / DAN Compliance)         (Clean Refusal Trigger)
```

---

## Quickstart & Installation

```bash
# Clone repository
git clone https://github.com/user/llm-safety-redteam-evals.git
cd llm-safety-redteam-evals

# Install in editable mode
pip install -e .

# Run pytest suite
pytest
```

---

## Executing Red-Team Benchmark CLI

Run the safety red-team evaluation suite via CLI:

```bash
python -m safety_evals.cli run \
  --dataset data/redteam_attacks.jsonl \
  --output-dir results \
  --report-path reports/safety_redteam_report.md \
  --figures-dir reports/figures
```

---

## Controlled Benchmark Results

| Defense Variant | Defense Success Rate | Attack Success Rate (ASR) | Vulnerability Rate | Critical Breaches |
| :--- | :--- | :--- | :--- | :--- |
| **Def v0 (Raw Model)** | `0.0%` | `100.0%` | `100.0%` | `4` |
| **Def v1 (Prompt Guard)** | `80.0%` | `20.0%` | `20.0%` | `1` |
| **Def v2 (Dual Filter)** | `100.0%` | `0.0%` | `0.0%` | `0` |

### Key Safety Visualizations

- **Defense Efficacy Comparison**: `reports/figures/defense_efficacy_comparison.png`
- **Vulnerability by Category**: `reports/figures/vulnerability_by_category.png`
- **Severity Breakdown**: `reports/figures/severity_breakdown.png`

---

## Repository Structure

```
llm-safety-redteam-evals/
├── .github/workflows/ci.yml     # GitHub Actions CI workflow
├── pyproject.toml               # Package build metadata
├── requirements.txt             # Project dependencies
├── safety_evals/                # Core Python package
│   ├── __init__.py
│   ├── schema.py                # Attack categories & severity models
│   ├── evaluator.py             # Refusal, PII, and breach detector
│   ├── experiment_runner.py    # Defense variant runner (v0, v1, v2)
│   ├── metrics.py               # Dataset-wide metric aggregator
│   ├── visualizer.py            # Matplotlib figure generator
│   ├── report_generator.py      # Markdown report & JSON/CSV exporter
│   └── cli.py                   # CLI entry point
├── data/
│   ├── README.md
│   └── redteam_attacks.jsonl    # Benchmark attack dataset
├── results/                     # JSON & CSV results output
├── reports/
│   ├── safety_redteam_report.md # Generated safety report
│   └── figures/                 # Visual charts
└── tests/                       # Unit and integration tests
```

---

## License

MIT License © 2026 AI Evaluation Engineering Team.
