# Reducing False Positives in Python Static Security Analyzers Using LLM Semantic Slicing

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An empirical research replication package investigating false-positive mitigation in Python Static Application Security Testing (SAST) tools (**Bandit**, **Semgrep**, **CodeQL**) using Large Language Model (LLM) backward program slicing.

---

## 📌 Research Overview

Static application security analyzers often suffer from high false-positive rates (ranging from **40% to 80%**) in dynamic languages like Python due to path insensitivity and missing sanitizer context. This project implements a two-stage hybrid framework:

1. **Static Candidate Detection**: Fast identification of potentially dangerous sinks (SQL injections, shell calls, unsafe deserialization) using Bandit and Semgrep.
2. **AST Program Slicing**: Automatic extraction of backward dataflow and control dependency code slices (**Variant A**, **Variant B**, and **Variant C**).
3. **LLM Semantic Verification**: LLM evaluation of whether runtime sanitizers (e.g., `shlex.quote`, `int()` type coercion, framework validators) neutralize the warning.

---

## 📁 Repository Structure
```text
├── src/                    # Core Python analysis engines & scripts
│   ├── scanners/           # Bandit and Semgrep runner harnesses
│   ├── slicing/            # AST backward program slicer (Variants A, B, C)
│   ├── dataset_curation/   # 100-repository selection & filtering pipeline
│   └── evaluation/         # Benchmark execution & metric computation
├── data/                   # Experimental datasets & alert manifests
│   ├── raw/                # Immutable raw scanner JSON findings
│   └── processed/          # Curated repository manifests and sliced prompts
├── results/                # Generated research figures, LaTeX tables, and reports
├── papers/                 # Literature matrix and peer review dossiers
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

---

## 🚀 Quickstart & Setup

### 1. Installation
Clone the repository and install required packages:
```bash
git clone [https://github.com/](https://github.com/)<YOUR_USERNAME>/python-sast-fp-reduction.git
cd python-sast-fp-reduction
pip install -r requirements.txt
```

### 2. Running the Static Security Scanner
Scan any Python target with the Bandit engine:
```bash
python3 src/scanners/bandit_engine.py <target_path> output_alerts.json
```

### 3. Extracting Semantic AST Slices
Extract backward slices around any flagged alert line:
```bash
python3 src/slicing/ast_slicer.py <filepath> <line_number>
```

### 📊 Experimental Slicing Variants
* **Variant A (Isolated Diff)**: Isolated alert line ± 3 lines.
* **Variant B (Intra-Procedural Slice)**: Enclosing function backward slice tracing dataflow and local guards.
* **Variant C (Inter-Procedural Taint Slice)**: Multi-level call-graph slice tracing parameters, decorators, and callers up to 3 layers deep.

### 📄 License
Distributed under the MIT License.
