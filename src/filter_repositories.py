from pathlib import Path

import pandas as pd
import json

PROJECT_ROOT = Path(__file__).resolve().parent.parent

GENERATED_DATA_DIR = PROJECT_ROOT / "data" / "generated"

REPOS_OUTPUT_CSV = GENERATED_DATA_DIR / "curated_100_repositories.csv"
PIPELINE_STATS_JSON = GENERATED_DATA_DIR / "repository_filtering_funnel.json"

if __name__ == "__main__":
    GENERATED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    print("Filter repositories script ready.")