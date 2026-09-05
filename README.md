Replication Package: Reducing False Positives in Python Static Security Analyzers Using LLM Semantic Slicing
This repository constitutes the official open-science artifact and replication package for the research paper:

"Reducing False Positives in Python Static Security Analyzers Using Large Language Model Semantic Slicing" (Target Venue: IEEE Software Engineering Track).

Adheres strictly to Rule 36 (Reproducibility Rule) and the ACM/IEEE Artifact Evaluation Guidelines.

________________________________________
1. Directory Structure
.

├── README.md                          <- Step-by-step reproduction instructions

├── requirements.txt                   <- Python package dependencies

├── reproduce_pilot_results.py         <- 1-click script to regenerate all pilot metrics and plots

├── code/

│   ├── scanners/                      <- Bandit & Semgrep static analysis runners

│   ├── slicing/                       <- AST backward & inter-procedural slicer (Variants A, B, C)

│   └── evaluation/                    <- Metric calculators & statistical test engines

├── data/

│   ├── raw/                           <- Immutable raw scanner findings (Rule 15)

│   └── processed/                     <- Sliced contexts & double-blind ground truth labels

└── results/

    ├── tables/                        <- Generated CSV and LaTeX tables

    └── figures/                       <- High-resolution publication plots (300 DPI)

________________________________________
2. Requirements & Installation
●	Operating System: Linux (Ubuntu 22.04+), macOS, or Windows 10/11
●	Python Version: Python 3.10+ or 3.11+
●	Dependencies:

pip install -r requirements.txt

________________________________________
3. How Reviewers Reproduce the Results (1-Click Execution)
To re-run the static analysis scanner, execute the program slicer across Variants A, B, and C, evaluate precision/recall/FPRR/FNR, and regenerate the publication plot:

python reproduce_pilot_results.py
Expected Output:
1.	results/tables/pilot_metrics_table.csv: Confusion matrix and performance metrics.
2.	results/tables/pilot_results.tex: LaTeX formatted table for paper inclusion.
3.	results/figures/pilot_performance_comparison.png: 300-DPI bar/line plot comparing accuracy and token economics.

